#include "CheatMonitor.h"
#include "CheatMonitorImpl.h"
#include "utils/SystemUtils.h"

#include <memory>
#include <mutex>
#include <thread>

struct CheatMonitor::Pimpl : public CheatMonitorImpl
{
};

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
        m_pimpl->m_monitorThread = std::thread(&CheatMonitorImpl::MonitorLoop, m_pimpl.get());
    }
    return true;
}

void CheatMonitor::OnPlayerLogin(uint32_t user_id, const std::string &user_name)
{
    if (m_pimpl)
    {
        std::lock_guard<std::mutex> lock(m_pimpl->m_sessionMutex);
        m_pimpl->m_currentUserId = user_id;
        m_pimpl->m_currentUserName = user_name;
        m_pimpl->m_isSessionActive = true;
        m_pimpl->m_hasServerConfig = true;
        m_pimpl->WakeMonitor();
    }
}

void CheatMonitor::OnPlayerLogout()
{
    if (m_pimpl)
    {
        m_pimpl->m_isSessionActive = false;
        m_pimpl->ResetSessionState();
    }
}

void CheatMonitor::Shutdown()
{
    if (m_pimpl && m_pimpl->m_isSystemActive.load())
    {
        m_pimpl->m_isSystemActive = false;
        m_pimpl->WakeMonitor();
        if (m_pimpl->m_monitorThread.joinable())
        {
            m_pimpl->m_monitorThread.join();
        }
    }
}

void CheatMonitor::OnServerConfigUpdated()
{
    if (m_pimpl)
    {
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
    if (m_pimpl) m_pimpl->SubmitTargetedScanRequest(request_id, sensor_name);
}

void CheatMonitor::SubmitTargetedSensorRequest(const anti_cheat::TargetedSensorCommand &command)
{
    if (m_pimpl) m_pimpl->SubmitTargetedScanRequest(command.request_id(), command.sensor_name());
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

CheatMonitorImpl::CheatMonitorImpl()
{
    m_windowsVersion = SystemUtils::GetWindowsVersion();
}

CheatMonitorImpl::~CheatMonitorImpl()
{
    if (m_wmiMonitor)
    {
        m_wmiMonitor->Shutdown();
        m_wmiMonitor.reset();
    }
    UnregisterDllNotification();
}
