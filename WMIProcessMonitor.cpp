#include "WMIProcessMonitor.h"
#include "Logger.h"
#include "utils/SystemUtils.h"
#include <comdef.h>
#include <Wbemidl.h>
#include <TlHelp32.h>
#include <chrono>

#pragma comment(lib, "wbemuuid.lib")

namespace anti_cheat
{

// 内部Sink类：用于解耦WMI异步回调与WMIProcessMonitor的生命周期
// 即使WMIProcessMonitor被销毁，Sink对象仍能通过引用计数存活，直到WMI释放它
class WmiSink : public IWbemObjectSink
{
public:
    WmiSink(WMIProcessMonitor* parent) : m_parent(parent), m_refCount(1) {}

    void Detach() { m_parent = nullptr; }

    // IUnknown
    virtual ULONG STDMETHODCALLTYPE AddRef() override { return ++m_refCount; }
    virtual ULONG STDMETHODCALLTYPE Release() override {
        ULONG res = --m_refCount;
        if (res == 0) delete this;
        return res;
    }
    virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv) override {
        if (riid == IID_IUnknown || riid == IID_IWbemObjectSink) {
            *ppv = static_cast<IWbemObjectSink*>(this);
            AddRef();
            return WBEM_S_NO_ERROR;
        }
        *ppv = NULL;
        return E_NOINTERFACE;
    }

    // IWbemObjectSink
    virtual HRESULT STDMETHODCALLTYPE Indicate(long lObjectCount, IWbemClassObject** apObjArray) override {
        if (m_parent) return m_parent->InternalIndicate(lObjectCount, apObjArray);
        return WBEM_S_NO_ERROR;
    }
    virtual HRESULT STDMETHODCALLTYPE SetStatus(long lFlags, HRESULT hResult, BSTR strParam, IWbemClassObject* pObjParam) override {
        if (m_parent) return m_parent->InternalSetStatus(lFlags, hResult, strParam, pObjParam);
        return WBEM_S_NO_ERROR;
    }

private:
    WMIProcessMonitor* m_parent;
    std::atomic<ULONG> m_refCount;
};

WMIProcessMonitor::WMIProcessMonitor(ProcessCallback callback)
    : m_callback(std::move(callback))
{
}

WMIProcessMonitor::~WMIProcessMonitor()
{
    Shutdown();
}

bool WMIProcessMonitor::Initialize()
{
    std::lock_guard<std::mutex> lock(m_initMutex);
    if (m_initialized) return true;

    bool initialized = false;
    /*
    if (SystemUtils::HasApiCapability(SystemUtils::ApiCapability::WmiAsyncProcessMonitor))
    {
        initialized = InitializeWmiAsync();
    }
    */

    if (!initialized)
    {
        LOG_WARNING(AntiCheatLogger::LogCategory::SYSTEM,
                    "WMIProcessMonitor: WMI初始化失败或能力矩阵禁用，回退到Toolhelp轮询监控。");
        initialized = InitializeToolhelpFallback();
    }

    m_initialized = initialized;
    return initialized;
}

bool WMIProcessMonitor::InitializeWmiAsync()
{
    HRESULT hres;

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (SUCCEEDED(hres))
    {
        m_comInitialized = true;
    }
    else if (hres != RPC_E_CHANGED_MODE)
    {
        LOG_ERROR_F(AntiCheatLogger::LogCategory::SYSTEM,
                    "WMIProcessMonitor: Failed to initialize COM library. Err code = 0x%x", hres);
        return false;
    }

    hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL,
                                 EOAC_NONE, NULL);
    if (FAILED(hres) && hres != RPC_E_TOO_LATE)
    {
        LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM, "WMIProcessMonitor: CoInitializeSecurity warning: 0x%x", hres);
    }

    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID *)&m_pLoc);
    if (FAILED(hres))
    {
        LOG_ERROR_F(AntiCheatLogger::LogCategory::SYSTEM,
                    "WMIProcessMonitor: Failed to create IWbemLocator object. Err code = 0x%x", hres);
        return false;
    }

    hres = m_pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &m_pSvc);
    if (FAILED(hres))
    {
        LOG_ERROR_F(AntiCheatLogger::LogCategory::SYSTEM,
                    "WMIProcessMonitor: Could not connect to ROOT\\CIMV2. Err code = 0x%x", hres);
        m_pLoc->Release();
        m_pLoc = nullptr;
        return false;
    }

    hres = CoSetProxyBlanket(m_pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL,
                             RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    if (FAILED(hres))
    {
        LOG_ERROR_F(AntiCheatLogger::LogCategory::SYSTEM,
                    "WMIProcessMonitor: Could not set proxy blanket. Err code = 0x%x", hres);
        m_pSvc->Release();
        m_pSvc = nullptr;
        m_pLoc->Release();
        m_pLoc = nullptr;
        return false;
    }

    hres = CoCreateInstance(CLSID_UnsecuredApartment, NULL, CLSCTX_LOCAL_SERVER, IID_IUnsecuredApartment,
                            (void **)&m_pUnsecApp);
    if (SUCCEEDED(hres))
    {
        m_pInternalSink = new WmiSink(this); // 创建内部Sink

        IUnknown *pStubUnk = nullptr;
        hres = m_pUnsecApp->CreateObjectStub(m_pInternalSink, &pStubUnk);
        if (SUCCEEDED(hres))
        {
            hres = pStubUnk->QueryInterface(IID_IWbemObjectSink, (void **)&m_pStubSink);
            pStubUnk->Release();
        }
    }

    IWbemObjectSink *pSink = m_pStubSink ? m_pStubSink : m_pInternalSink;
    if (!pSink) return false;

    hres = m_pSvc->ExecNotificationQueryAsync(
            _bstr_t("WQL"), _bstr_t("SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"),
            WBEM_FLAG_SEND_STATUS, NULL, pSink);

    if (FAILED(hres))
    {
        LOG_ERROR_F(AntiCheatLogger::LogCategory::SYSTEM,
                    "WMIProcessMonitor: ExecNotificationQueryAsync failed. Err code = 0x%x", hres);
        return false;
    }

    m_wmiCallInProgress = true;
    m_backendMode = BackendMode::WmiAsync;
    LOG_INFO(AntiCheatLogger::LogCategory::SYSTEM, "WMIProcessMonitor: Using WMI async backend.");
    return true;
}

bool WMIProcessMonitor::InitializeToolhelpFallback()
{
    m_pollingActive = true;
    m_pollingThread = std::thread(&WMIProcessMonitor::PollingLoop, this);
    m_backendMode = BackendMode::ToolhelpPolling;
    LOG_INFO(AntiCheatLogger::LogCategory::SYSTEM, "WMIProcessMonitor: Using Toolhelp polling fallback backend.");
    return true;
}

void WMIProcessMonitor::PollingLoop()
{
    while (m_pollingActive.load())
    {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE)
        {
            std::unordered_set<DWORD> currentPids;
            PROCESSENTRY32W pe = {};
            pe.dwSize = sizeof(pe);

            if (Process32FirstW(hSnapshot, &pe))
            {
                do
                {
                    currentPids.insert(pe.th32ProcessID);
                    if (m_seenPids.count(pe.th32ProcessID) == 0 && m_callback)
                    {
                        m_callback(pe.th32ProcessID, pe.szExeFile);
                    }
                } while (Process32NextW(hSnapshot, &pe));
            }

            m_seenPids.swap(currentPids);
            CloseHandle(hSnapshot);
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
}

void WMIProcessMonitor::Shutdown()
{
    {
        std::lock_guard<std::mutex> lock(m_initMutex);
        if (m_shuttingDown) return;
        m_shuttingDown = true;
    }
    m_pollingActive = false;
    if (m_pollingThread.joinable())
    {
        m_pollingThread.join();
    }

    LOG_DEBUG(AntiCheatLogger::LogCategory::SYSTEM, "WMIProcessMonitor: Shutdown started.");
    if (m_pSvc)
    {
        LOG_DEBUG(AntiCheatLogger::LogCategory::SYSTEM, "WMIProcessMonitor: Canceling async call.");
        m_pSvc->CancelAsyncCall(m_pStubSink ? m_pStubSink : m_pInternalSink);
    }

    {
        std::unique_lock<std::mutex> lk(m_callbackMutex);
        LOG_DEBUG(AntiCheatLogger::LogCategory::SYSTEM, "WMIProcessMonitor: Waiting for pending callbacks/WMI finish.");
        // 等待所有正在进行的回调完成，以及WMI确认异步调用结束
        bool waitSuccess = m_callbackCv.wait_for(lk, std::chrono::seconds(5), [&]() {
            return m_activeIndications.load() == 0 && !m_wmiCallInProgress.load();
        });
        if (!waitSuccess)
        {
            LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM, "WMIProcessMonitor: Shutdown wait timeout. Indications: %u, InProgress: %d",
                        m_activeIndications.load(), m_wmiCallInProgress.load());
        }
    }

    {
        std::lock_guard<std::mutex> lock(m_initMutex);
        if (m_pInternalSink)
        {
            LOG_DEBUG(AntiCheatLogger::LogCategory::SYSTEM, "WMIProcessMonitor: Detaching internal sink.");
            // 关键：解耦并释放我们持有的引用，但WMI持有的引用会让Sink对象在后台继续存活直到WMI完成
            static_cast<WmiSink*>(m_pInternalSink)->Detach();
            m_pInternalSink->Release();
            m_pInternalSink = nullptr;
        }
        if (m_pSvc)
        {
            m_pSvc->Release();
            m_pSvc = nullptr;
        }
        if (m_pLoc)
        {
            m_pLoc->Release();
            m_pLoc = nullptr;
        }
        if (m_pStubSink)
        {
            m_pStubSink->Release();
            m_pStubSink = nullptr;
        }
        if (m_pUnsecApp)
        {
            m_pUnsecApp->Release();
            m_pUnsecApp = nullptr;
        }
        m_seenPids.clear();
        m_initialized = false;
        m_backendMode = BackendMode::None;

        LOG_DEBUG(AntiCheatLogger::LogCategory::SYSTEM, "WMIProcessMonitor: Releasing COM resources.");
        /*
        if (m_comInitialized)
        {
            CoUninitialize();
            m_comInitialized = false;
        }
        */
    }
    LOG_DEBUG(AntiCheatLogger::LogCategory::SYSTEM, "WMIProcessMonitor: Shutdown completed.");
}

HRESULT WMIProcessMonitor::InternalIndicate(long lObjectCount, IWbemClassObject** apObjArray)
{
    struct IndicateScope
    {
        WMIProcessMonitor *self;
        explicit IndicateScope(WMIProcessMonitor *s) : self(s) { self->m_activeIndications.fetch_add(1); }
        ~IndicateScope()
        {
            if (self->m_activeIndications.fetch_sub(1) == 1)
            {
                std::lock_guard<std::mutex> lk(self->m_callbackMutex);
                self->m_callbackCv.notify_all();
            }
        }
    } scope(this);

    if (m_shuttingDown.load())
    {
        return WBEM_S_NO_ERROR;
    }

    for (int i = 0; i < lObjectCount; i++)
    {
        IWbemClassObject* pObj = apObjArray[i];
        VARIANT vtProp;

        // Get TargetInstance
        if (SUCCEEDED(pObj->Get(L"TargetInstance", 0, &vtProp, 0, 0)))
        {
            if (vtProp.vt == VT_UNKNOWN || vtProp.vt == VT_DISPATCH)
            {
                 IUnknown* pUnk = vtProp.punkVal;
                 IWbemClassObject* pTargetFunc = nullptr;
                 if (SUCCEEDED(pUnk->QueryInterface(IID_IWbemClassObject, (void**)&pTargetFunc)))
                 {
                     VARIANT vtPid, vtName;
                     DWORD pid = 0;
                     std::wstring name;

                     // Handle is usually PID in Win32_Process
                     if (SUCCEEDED(pTargetFunc->Get(L"Handle", 0, &vtPid, 0, 0)))
                     {
                         if(vtPid.vt == VT_BSTR)
                             pid = std::wcstoul(vtPid.bstrVal, nullptr, 10);
                         else if(vtPid.vt == VT_I4)
                             pid = vtPid.lVal;
                         VariantClear(&vtPid);
                     }
                     // Fallback to ProcessId property
                     else if (SUCCEEDED(pTargetFunc->Get(L"ProcessId", 0, &vtPid, 0, 0)))
                     {
                          if(vtPid.vt == VT_I4)
                             pid = vtPid.lVal;
                          VariantClear(&vtPid);
                     }

                     if (SUCCEEDED(pTargetFunc->Get(L"Name", 0, &vtName, 0, 0)))
                     {
                         if(vtName.vt == VT_BSTR)
                             name = vtName.bstrVal;
                         VariantClear(&vtName);
                     }

                     if (!m_shuttingDown.load() && m_callback && pid != 0 && !name.empty())
                     {
                         m_callback(pid, name);
                     }

                     pTargetFunc->Release();
                 }
            }
            VariantClear(&vtProp);
        }
    }
    return WBEM_S_NO_ERROR;
}


HRESULT WMIProcessMonitor::InternalSetStatus(long lFlags, HRESULT hResult, BSTR strParam, IWbemClassObject* pObjParam)
{
    if (lFlags == WBEM_STATUS_COMPLETE)
    {
        m_wmiCallInProgress = false;
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        m_callbackCv.notify_all();
    }
    return WBEM_S_NO_ERROR;
}

} // namespace anti_cheat
