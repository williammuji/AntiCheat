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

class WMIProcessMonitor
{
public:
    using ProcessCallback = std::function<void(DWORD pid, const std::wstring& name)>;

    explicit WMIProcessMonitor(ProcessCallback callback);
    virtual ~WMIProcessMonitor();

    bool Initialize();
    void Shutdown();

    // Internal methods for WmiSink to call
    HRESULT InternalIndicate(long lObjectCount, IWbemClassObject** apObjArray);
    HRESULT InternalSetStatus(long lFlags, HRESULT hResult, BSTR strParam, IWbemClassObject* pObjParam);

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
    IWbemObjectSink* m_pInternalSink = nullptr; // 用于解耦C++对象与COM生命周期的内部Sink
    bool m_initialized = false;
    BackendMode m_backendMode = BackendMode::None;
    std::mutex m_initMutex;
    std::atomic<bool> m_wmiCallInProgress{false};
    bool m_comInitialized = false;
    std::atomic<bool> m_pollingActive{false};
    std::thread m_pollingThread;
    std::unordered_set<DWORD> m_seenPids;
};

} // namespace anti_cheat
