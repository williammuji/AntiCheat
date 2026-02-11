#include "WMIProcessMonitor.h"
#include "Logger.h"
#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

namespace anti_cheat
{

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

    HRESULT hres;

    // Initialize COM.
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres) && hres != RPC_E_CHANGED_MODE)
    {
         LOG_ERROR_F(AntiCheatLogger::LogCategory::SYSTEM, "WMIProcessMonitor: Failed to initialize COM library. Err code = 0x%x", hres);
        return false;
    }

    // Initialize Security
    hres = CoInitializeSecurity(
        NULL,
        -1,                          // COM authentication
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication
        RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities
        NULL                         // Reserved
    );

    if (FAILED(hres) && hres != RPC_E_TOO_LATE)
    {
         // Security might vary per app
    }

    // Obtain the initial locator to WMI
    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&m_pLoc);

    if (FAILED(hres))
    {
        LOG_ERROR_F(AntiCheatLogger::LogCategory::SYSTEM, "WMIProcessMonitor: Failed to create IWbemLocator object. Err code = 0x%x", hres);
        return false;
    }

    // Connect to WMI
    hres = m_pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &m_pSvc
    );

    if (FAILED(hres))
    {
        LOG_ERROR_F(AntiCheatLogger::LogCategory::SYSTEM, "WMIProcessMonitor: Could not connect to ROOT\\CIMV2. Err code = 0x%x", hres);
        m_pLoc->Release();
        m_pLoc = nullptr;
        return false;
    }

    // Set security levels on the proxy
    hres = CoSetProxyBlanket(
        m_pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
    );

    if (FAILED(hres))
    {
        LOG_ERROR_F(AntiCheatLogger::LogCategory::SYSTEM, "WMIProcessMonitor: Could not set proxy blanket. Err code = 0x%x", hres);
        m_pSvc->Release();
        m_pSvc = nullptr;
        m_pLoc->Release();
        m_pLoc = nullptr;
        return false;
    }

    // Setup Unsecured Apartment for callbacks
    hres = CoCreateInstance(CLSID_UnsecuredApartment, NULL, CLSCTX_LOCAL_SERVER, IID_IUnsecuredApartment, (void**)&m_pUnsecApp);
    if (SUCCEEDED(hres))
    {
         m_pUnsecApp->CreateObjectStub(this, &m_pStubSink);
    }

    // Use stub sink if available, else use this
    IWbemObjectSink* pSink = m_pStubSink ? m_pStubSink : this;

    // Send the request
    hres = m_pSvc->ExecNotificationQueryAsync(
        _bstr_t("WQL"),
        _bstr_t("SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_Process'"),
        WBEM_FLAG_SEND_STATUS,
        NULL,
        pSink
    );

    if (FAILED(hres))
    {
        LOG_ERROR_F(AntiCheatLogger::LogCategory::SYSTEM, "WMIProcessMonitor: ExecNotificationQueryAsync failed. Err code = 0x%x", hres);
        Shutdown();
        return false;
    }

    m_initialized = true;
    return true;
}

void WMIProcessMonitor::Shutdown()
{
    std::lock_guard<std::mutex> lock(m_initMutex);

    if (m_pSvc)
    {
        m_pSvc->CancelAsyncCall(m_pStubSink ? m_pStubSink : this);
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
    m_initialized = false;
}

ULONG STDMETHODCALLTYPE WMIProcessMonitor::AddRef()
{
    return ++m_refCount;
}

ULONG STDMETHODCALLTYPE WMIProcessMonitor::Release()
{
    ULONG lRef = --m_refCount;
    return lRef;
}

HRESULT STDMETHODCALLTYPE WMIProcessMonitor::QueryInterface(REFIID riid, void** ppv)
{
    if (riid == IID_IUnknown || riid == IID_IWbemObjectSink)
    {
        *ppv = (IWbemObjectSink*)this;
        AddRef();
        return WBEM_S_NO_ERROR;
    }
    *ppv = NULL;
    return E_NOINTERFACE;
}

HRESULT STDMETHODCALLTYPE WMIProcessMonitor::Indicate(long lObjectCount, IWbemClassObject** apObjArray)
{
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

                     if (m_callback && pid != 0 && !name.empty())
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

HRESULT STDMETHODCALLTYPE WMIProcessMonitor::SetStatus(long lFlags, HRESULT hResult, BSTR strParam, IWbemClassObject* pObjParam)
{
    return WBEM_S_NO_ERROR;
}

} // namespace anti_cheat
