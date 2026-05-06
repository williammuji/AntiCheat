#include "CheatMonitor.h"
#include "CheatMonitorEngine.h"
#include "utils/SystemUtils.h"

#include <memory>
#include <mutex>
#include <thread>

struct CheatMonitor::Pimpl : public CheatMonitorEngine
{
};

namespace
{
bool ShouldEnforceControlApiCaller(const CheatMonitor::Pimpl *pimpl)
{
    return pimpl && pimpl->m_processBaselineEstablished.load(std::memory_order_relaxed);
}
}

CheatMonitor &CheatMonitor::GetInstance()
{
    static CheatMonitor instance;
    return instance;
}

CheatMonitor::CheatMonitor() : m_pimpl(nullptr) {}
CheatMonitor::~CheatMonitor() { Shutdown(); }

bool CheatMonitor::Initialize()
{
    if (!m_pimpl)
    {
        m_pimpl = std::make_unique<Pimpl>();
        m_pimpl->m_isSystemActive = true;
        m_pimpl->StartControlThread();
    }
    return true;
}

void CheatMonitor::OnPlayerLogin(uint32_t user_id, const std::string &user_name)
{
    if (m_pimpl)
    {
        if (ShouldEnforceControlApiCaller(m_pimpl.get()) && !m_pimpl->IsAddressInLegitimateModule(_ReturnAddress()))
        {
            m_pimpl->AddEvidence(anti_cheat::RUNTIME_ERROR, "Rejected forged OnPlayerLogin call from illegitimate module");
            m_pimpl->SendServerLog("ERROR", "SYSTEM", "Rejected forged OnPlayerLogin call from illegitimate module");
            return;
        }
        {
            std::lock_guard<std::mutex> lock(m_pimpl->m_sessionMutex);
            m_pimpl->m_currentUserId = user_id;
            m_pimpl->m_currentUserName = user_name;
        }
        m_pimpl->m_isSessionActive = true;
        m_pimpl->m_expectedSessionActive.store(true, std::memory_order_relaxed);
        m_pimpl->UpdateSessionGuard(true);
        m_pimpl->m_hasServerConfig = true;
        m_pimpl->WakeMonitor();
    }
}

void CheatMonitor::OnPlayerLogout()
{
    if (m_pimpl)
    {
        if (ShouldEnforceControlApiCaller(m_pimpl.get()) && !m_pimpl->IsAddressInLegitimateModule(_ReturnAddress()))
        {
            m_pimpl->AddEvidence(anti_cheat::RUNTIME_ERROR, "Rejected forged OnPlayerLogout call from illegitimate module");
            m_pimpl->SendServerLog("ERROR", "SYSTEM", "Rejected forged OnPlayerLogout call from illegitimate module");
            return;
        }
        m_pimpl->m_expectedSessionActive.store(false, std::memory_order_relaxed);
        m_pimpl->m_isSessionActive = false;
        m_pimpl->UpdateSessionGuard(false);
        m_pimpl->ResetSessionState();
    }
}

void CheatMonitor::Shutdown()
{
    if (m_pimpl && m_pimpl->m_isSystemActive.load())
    {
        m_pimpl->m_isSystemActive = false;
        m_pimpl->WakeMonitor();
        m_pimpl->StopControlThread(true);
        m_pimpl->StopScanThread(true);
    }
    m_pimpl.reset();
}

void CheatMonitor::OnServerConfigUpdated()
{
    if (m_pimpl)
    {
        if (ShouldEnforceControlApiCaller(m_pimpl.get()) && !m_pimpl->IsAddressInLegitimateModule(_ReturnAddress()))
        {
            m_pimpl->AddEvidence(anti_cheat::RUNTIME_ERROR,
                                 "Rejected forged OnServerConfigUpdated call from illegitimate module");
            m_pimpl->SendServerLog("ERROR", "SYSTEM", "Rejected forged OnServerConfigUpdated call from illegitimate module");
            return;
        }
        m_pimpl->OnConfigUpdated();
        m_pimpl->m_hasServerConfig = true;
        m_pimpl->WakeMonitor();
    }
}

void CheatMonitor::SetGameWindow(void *hwnd)
{
    if (m_pimpl) m_pimpl->m_gameWindowHandle.store(reinterpret_cast<uintptr_t>(hwnd), std::memory_order_relaxed);
}

void CheatMonitor::SubmitTargetedSensorRequest(const std::string &request_id, const std::string &sensor_name)
{
    if (m_pimpl)
    {
        if (ShouldEnforceControlApiCaller(m_pimpl.get()) && !m_pimpl->IsAddressInLegitimateModule(_ReturnAddress()))
        {
            m_pimpl->AddEvidence(anti_cheat::RUNTIME_ERROR,
                                 "Rejected forged SubmitTargetedSensorRequest call from illegitimate module");
            m_pimpl->SendServerLog("ERROR", "SYSTEM",
                                   "Rejected forged SubmitTargetedSensorRequest call from illegitimate module");
            return;
        }
        m_pimpl->SubmitTargetedScanRequest(request_id, sensor_name);
    }
}

void CheatMonitor::SubmitTargetedSensorRequest(const anti_cheat::TargetedSensorCommand &command)
{
    if (m_pimpl)
    {
        if (ShouldEnforceControlApiCaller(m_pimpl.get()) && !m_pimpl->IsAddressInLegitimateModule(_ReturnAddress()))
        {
            m_pimpl->AddEvidence(anti_cheat::RUNTIME_ERROR,
                                 "Rejected forged SubmitTargetedSensorRequest(proto) call from illegitimate module");
            m_pimpl->SendServerLog("ERROR", "SYSTEM",
                                   "Rejected forged SubmitTargetedSensorRequest(proto) call from illegitimate module");
            return;
        }
        m_pimpl->SubmitTargetedScanRequest(command.request_id(), command.sensor_name());
    }
}

void CheatMonitor::UploadSnapshot()
{
    if (m_pimpl) m_pimpl->UploadSnapshotReport();
}

bool CheatMonitor::IsCallerLegitimate()
{
    if (!m_pimpl) return true;
    return m_pimpl->IsAddressInLegitimateModule(_ReturnAddress());
}

CheatMonitorEngine::CheatMonitorEngine()
{
    m_windowsVersion = SystemUtils::GetWindowsVersion();
    // 动态获取反作弊模块句柄（支持静态编译到EXE或单独作为DLL）
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                       reinterpret_cast<LPCWSTR>(CheatMonitor::GetInstance), &m_hSelfModule);

    // 生成会话 ID (类似 UUID 格式)
    char session[37];
    const char *chars = "abcdef0123456789";
    for (int i = 0; i < 36; ++i)
    {
        if (i == 8 || i == 13 || i == 18 || i == 23)
            session[i] = '-';
        else
            session[i] = chars[m_rng() % 16];
    }
    session[36] = 0;
    m_sessionId = session;
    m_sessionGuardSecret = (static_cast<uint64_t>(m_rng()) << 32) ^ static_cast<uint64_t>(m_rng());
    m_expectedSessionActive.store(false, std::memory_order_relaxed);
    UpdateSessionGuard(false);
}

CheatMonitorEngine::~CheatMonitorEngine()
{
    if (m_wmiMonitor)
    {
        m_wmiMonitor->Shutdown();
        m_wmiMonitor.reset();
    }
    UnregisterDllNotification();
}
