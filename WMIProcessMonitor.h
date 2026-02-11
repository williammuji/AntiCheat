#pragma once

#include <windows.h>
#include <wbemidl.h>
#include <string>
#include <functional>
#include <atomic>
#include <mutex>

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
    std::atomic<ULONG> m_refCount{1};
    ProcessCallback m_callback;
    IWbemServices* m_pSvc = nullptr;
    IWbemLocator* m_pLoc = nullptr;
    IUnsecuredApartment* m_pUnsecApp = nullptr;
    IWbemObjectSink* m_pStubSink = nullptr;
    bool m_initialized = false;
    std::mutex m_initMutex;
};

} // namespace anti_cheat
