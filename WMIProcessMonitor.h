#pragma once

#include <windows.h>
#include <wbemidl.h>
#include <string>
#include <functional>
#include <atomic>
#include <mutex>
#include <thread>
#include <unordered_set>
#include <condition_variable>

namespace anti_cheat
{

class WMIProcessMonitor : public IWbemObjectSink
{
public:
    using ProcessCallback = std::function<void(DWORD pid, const std::wstring& name)>;

    explicit WMIProcessMonitor(ProcessCallback callback);
    virtual ~WMIProcessMonitor();

    bool Initialize();
    void Shutdown();

    // IWbemObjectSink interface
    virtual ULONG STDMETHODCALLTYPE AddRef();
    virtual ULONG STDMETHODCALLTYPE Release();
    virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv);
    virtual HRESULT STDMETHODCALLTYPE Indicate(long lObjectCount, IWbemClassObject** apObjArray);
    virtual HRESULT STDMETHODCALLTYPE SetStatus(long lFlags, HRESULT hResult, BSTR strParam, IWbemClassObject* pObjParam);

private:
    enum class BackendMode
    {
        None,
        WmiAsync,
        ToolhelpPolling
    };

    bool InitializeWmiAsync();
    bool InitializeToolhelpFallback();
    void PollingLoop();

    std::atomic<ULONG> m_refCount{1};
    std::atomic<bool> m_shuttingDown{false};
    std::atomic<uint32_t> m_activeIndications{0};
    std::mutex m_callbackMutex;
    std::condition_variable m_callbackCv;
    ProcessCallback m_callback;
    IWbemServices* m_pSvc = nullptr;
    IWbemLocator* m_pLoc = nullptr;
    IUnsecuredApartment* m_pUnsecApp = nullptr;
    IWbemObjectSink* m_pStubSink = nullptr;
    bool m_initialized = false;
    BackendMode m_backendMode = BackendMode::None;
    std::mutex m_initMutex;
    std::atomic<bool> m_pollingActive{false};
    std::thread m_pollingThread;
    std::unordered_set<DWORD> m_seenPids;
};

} // namespace anti_cheat
