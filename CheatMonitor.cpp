#include "CheatMonitor.h"
#include "CheatMonitorImpl.h"
#include "ISensor.h"
#include "IatHookSensor.h"
#include "VehHookSensor.h"
#include "InlineHookSensor.h"
#include "ProcessHollowingSensor.h"
#include "ProcessAndWindowMonitorSensor.h"
#include "DriverIntegritySensor.h"
#include "ThreadActivitySensor.h"
#include "ModuleActivitySensor.h"
#include "MemorySecuritySensor.h"
#include "AdvancedAntiDebugSensor.h"
#include "SystemCodeIntegritySensor.h"
#include "ModuleIntegritySensor.h"
#include "ProcessHandleSensor.h"
#include "VTableHookSensor.h"
#include "utils/SystemUtils.h"
#include "utils/Utils.h"
#include "utils/Scanners.h"
#include "Logger.h"
#include "CheatConfigManager.h"
#include <wincrypt.h>
#include <wintrust.h>
#include <winternl.h>
#include <iphlpapi.h>
#include <memory>
#include <mutex>
#include <thread>
#include <atomic>
#include <vector>
#include <chrono>

typedef NTSTATUS (NTAPI *P_LdrRegisterDllNotification)(
    ULONG Flags,
    PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
    PVOID Context,
    PVOID *Cookie
);

typedef NTSTATUS (NTAPI *P_LdrUnregisterDllNotification)(
    PVOID Cookie
);

struct CheatMonitor::Pimpl : public CheatMonitorImpl
{
    // Implementation is in CheatMonitorImpl
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
    if (m_pimpl) m_pimpl->m_hGameWindow = (HWND)hwnd;
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
    UnregisterDllNotification();
}

void CheatMonitorImpl::WakeMonitor()
{
    m_cv.notify_one();
}

void CheatMonitorImpl::InitializeSystem()
{
    // Initialize Sensors
    if (m_lightweightSensors.empty())
    {
        // Light Sensors (0-10ms)
        m_lightweightSensors.push_back(std::make_unique<AdvancedAntiDebugSensor>());
        m_lightweightSensors.push_back(std::make_unique<SystemCodeIntegritySensor>());
        m_lightweightSensors.push_back(std::make_unique<IatHookSensor>());
        m_lightweightSensors.push_back(std::make_unique<VehHookSensor>());
        m_lightweightSensors.push_back(std::make_unique<VTableHookSensor>());

        // Heavy Sensors (10-100ms)
        m_heavyweightSensors.push_back(std::make_unique<ThreadActivitySensor>());
        m_heavyweightSensors.push_back(std::make_unique<ModuleActivitySensor>());
        m_heavyweightSensors.push_back(std::make_unique<MemorySecuritySensor>());
        m_heavyweightSensors.push_back(std::make_unique<DriverIntegritySensor>());
        m_heavyweightSensors.push_back(std::make_unique<InlineHookSensor>());
        m_heavyweightSensors.push_back(std::make_unique<ProcessHollowingSensor>());

        // Critical Sensors (~1000ms+) - Treated as Heavy for scheduling
        m_heavyweightSensors.push_back(std::make_unique<ProcessHandleSensor>());
        m_heavyweightSensors.push_back(std::make_unique<ModuleIntegritySensor>());
        m_heavyweightSensors.push_back(std::make_unique<ProcessAndWindowMonitorSensor>());

        // Register for targeted scans
        for (const auto &sensor : m_lightweightSensors)
        {
            m_sensorRegistry[sensor->GetName()] = sensor.get();
        }
        for (const auto &sensor : m_heavyweightSensors)
        {
            m_sensorRegistry[sensor->GetName()] = sensor.get();
        }
    }

    RegisterDllNotification();
    HardenProcessAndThreads();
    CheckParentProcessAtStartup();
    DetectVirtualMachine();
    InitializeProcessBaseline();
    InitializeSelfIntegrityBaseline();
}

void CheatMonitorImpl::InitializeProcessBaseline()
{
    // 1. 获取基础模块信息
    std::vector<HMODULE> hMods(1024);
    DWORD cbNeeded = 0;
    if (EnumProcessModules(GetCurrentProcess(), hMods.data(), hMods.size() * sizeof(HMODULE), &cbNeeded))
    {
        size_t count = cbNeeded / sizeof(HMODULE);
        for (size_t i = 0; i < count; i++)
        {
            HMODULE hModule = hMods[i];
            wchar_t modulePath_w[MAX_PATH];
            if (GetModuleFileNameW(hModule, modulePath_w, MAX_PATH) == 0)
                continue;
            std::wstring modulePath(modulePath_w);

            PVOID codeBase = nullptr;
            DWORD codeSize = 0;
            if (SystemUtils::GetModuleCodeSectionInfo(hModule, codeBase, codeSize))
            {
                m_moduleBaselineHashes[modulePath] =
                        SystemUtils::CalculateFnv1aHash(static_cast<BYTE *>(codeBase), codeSize);
            }
        }
    }

    // 4. 建立IAT Hook检测基线
    m_iatBaselineHashes.clear();
    const HMODULE hSelf = GetModuleHandle(NULL);
    if (hSelf)
    {
        const BYTE *baseAddress = reinterpret_cast<const BYTE *>(hSelf);
        const auto *pDosHeader = reinterpret_cast<const IMAGE_DOS_HEADER *>(baseAddress);
        if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
        {
            const auto *pNtHeaders = reinterpret_cast<const IMAGE_NT_HEADERS *>(baseAddress + pDosHeader->e_lfanew);
            if (pNtHeaders->Signature == IMAGE_NT_SIGNATURE)
            {
                IMAGE_DATA_DIRECTORY importDirectory =
                        pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                if (importDirectory.VirtualAddress != 0)
                {
                    const auto *pImportDesc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR *>(
                            baseAddress + importDirectory.VirtualAddress);
                    const auto *pCurrentDesc = pImportDesc;
                    while (pCurrentDesc->Name)
                    {
                        const char *dllName = (const char *)(baseAddress + pCurrentDesc->Name);
                        std::vector<uint8_t> iat_hashes;
                        const auto *pThunk =
                                reinterpret_cast<const IMAGE_THUNK_DATA *>(baseAddress + pCurrentDesc->FirstThunk);
                        while (pThunk && pThunk->u1.AddressOfData)
                        {
                            uintptr_t func_ptr = pThunk->u1.Function;
                            iat_hashes.insert(iat_hashes.end(), (uint8_t *)&func_ptr,
                                              (uint8_t *)&func_ptr + sizeof(func_ptr));
                            pThunk++;
                        }
                        m_iatBaselineHashes[dllName] =
                                SystemUtils::CalculateFnv1aHash(iat_hashes.data(), iat_hashes.size());
                        pCurrentDesc++;
                    }
                }
            }
        }
    }

    if (!m_hwCollector)
        m_hwCollector = std::make_unique<anti_cheat::HardwareInfoCollector>();
    m_hwCollector->EnsureCollected();

    AddEvidence(anti_cheat::SYSTEM_INITIALIZED, "Process baseline established.");
    m_processBaselineEstablished = true;
}

void CheatMonitorImpl::MonitorLoop()
{
    InitializeSystem();

    // 初始化扫描时间
    auto next_light_scan = std::chrono::steady_clock::now();
    auto next_heavy_scan = std::chrono::steady_clock::now();
    auto next_report_upload = std::chrono::steady_clock::now();
    auto next_sensor_stats_upload = std::chrono::steady_clock::now();
    auto next_snapshot_upload = std::chrono::steady_clock::now();

    while (m_isSystemActive.load())
    {
        // 计算下一次应当唤醒的时间点（最早的调度时间），支持快速关停
        const auto now_before_wait = std::chrono::steady_clock::now();
        auto earliest = now_before_wait + std::chrono::seconds(1);  // 默认1秒检查一次状态

        if (m_isSessionActive.load() && m_hasServerConfig.load())
        {
            earliest = std::min({next_light_scan, next_heavy_scan, next_report_upload, next_sensor_stats_upload, next_snapshot_upload});
        }

        {
            std::unique_lock<std::mutex> lk(m_cvMutex);
            m_cv.wait_until(lk, earliest, [&]() { return !m_isSystemActive.load(); });
        }

        if (!m_isSystemActive.load())
            break;

        // 核心逻辑：只有在会话激活并且已收到服务器配置后才执行扫描
        if (!m_isSessionActive.load() || !m_hasServerConfig.load())
        {
            continue;
        }

        ProcessPendingTargetedScans();

        // 在循环开始时定义now变量，确保在整个循环迭代中都有效
        const auto now = std::chrono::steady_clock::now();

        // === 轻量级传感器扫描 (45秒间隔) ===
        if (now >= next_light_scan)
        {
            ExecuteLightweightSensors();
            next_light_scan = now + GetLightScanInterval();
        }

        // === 重量级传感器扫描 (8分钟间隔) ===
        if (now >= next_heavy_scan)
        {
            ExecuteHeavyweightSensors();
            next_heavy_scan = now + GetHeavyScanInterval();
        }

        // === 报告上传调度 ===
        if (now >= next_report_upload)
        {
            UploadEvidenceReport();
            next_report_upload =
                    now + std::chrono::minutes(CheatConfigManager::GetInstance().GetReportUploadIntervalMinutes());
        }

        // === 统一传感器统计上报调度 (配置间隔) ===
        // 包含重量级和轻量级传感器的所有统计信息
        if (now >= next_sensor_stats_upload)
        {
            UploadSensorExecutionStatsReport();
            next_sensor_stats_upload =
                    now + std::chrono::minutes(CheatConfigManager::GetInstance().GetSensorStatsUploadIntervalMinutes());
        }

        // === 快照数据上报调度 (配置间隔) ===
        if (now >= next_snapshot_upload)
        {
            if (CheatConfigManager::GetInstance().IsSnapshotUploadEnabled())
            {
                UploadSnapshotReport();
            }
            next_snapshot_upload =
                    now + std::chrono::minutes(CheatConfigManager::GetInstance().GetSnapshotUploadIntervalMinutes());
        }
    }
}

void CheatMonitorImpl::ResetSessionState()
{
    // 重置会话状态变量（受m_sessionMutex保护）
    {
        std::lock_guard<std::mutex> lock(m_sessionMutex);
        m_currentUserId = 0;
        m_currentUserName.clear();
        m_uniqueEvidence.clear();
        m_evidences.clear();
        m_lastReported.clear();
        m_evidenceOverflowed = false;
    }

    // 重置统一传感器统计（受m_sensorStatsMutex保护）
    {
        std::lock_guard<std::mutex> lock(m_sensorStatsMutex);
        m_sensorExecutionStats.clear();
    }

    // 重置基线数据（受m_baselineMutex保护）
    {
        std::lock_guard<std::mutex> lock(m_baselineMutex);
        m_knownThreadIds.clear();
        m_knownModules.clear();
    }

    {
        std::lock_guard<std::mutex> lock(m_targetedScanMutex);
        m_targetedScanQueue.clear();
        m_consumedTargetedScanIds.clear();
    }

    LOG_INFO(AntiCheatLogger::LogCategory::SYSTEM, "Session state reset completed");
}

void CheatMonitorImpl::OnConfigUpdated()
{
    // 获取配置信息
    std::string osVersionName = CheatConfigManager::GetInstance().GetMinOsVersionName();
    anti_cheat::OsVersion requiredOsVersion = CheatConfigManager::GetInstance().GetMinOsVersion();

    // 使用统一的IsCurrentOsSupported()方法检查版本兼容性
    const bool osVersionSupported = IsCurrentOsSupported();

    LOG_INFO_F(AntiCheatLogger::LogCategory::SYSTEM, "OS版本门控结果: 当前OS=%d, 配置要求min_os=%d, 版本兼容=%s",
               (int)m_windowsVersion, (int)requiredOsVersion, osVersionSupported ? "是" : "否");
}

bool CheatMonitorImpl::IsCurrentOsSupported() const
{
    anti_cheat::OsVersion requiredOsVersion = CheatConfigManager::GetInstance().GetMinOsVersion();

    switch (requiredOsVersion)
    {
        case anti_cheat::OS_ANY:
            return true;
        case anti_cheat::OS_WIN_XP:
            return m_windowsVersion == SystemUtils::WindowsVersion::Win_XP ||
                   m_windowsVersion == SystemUtils::WindowsVersion::Win_Vista_Win7 ||
                   m_windowsVersion == SystemUtils::WindowsVersion::Win_8_Win81 ||
                   m_windowsVersion == SystemUtils::WindowsVersion::Win_10 ||
                   m_windowsVersion == SystemUtils::WindowsVersion::Win_11;
        case anti_cheat::OS_WIN7_SP1:
            return m_windowsVersion == SystemUtils::WindowsVersion::Win_Vista_Win7 ||
                   m_windowsVersion == SystemUtils::WindowsVersion::Win_8_Win81 ||
                   m_windowsVersion == SystemUtils::WindowsVersion::Win_10 ||
                   m_windowsVersion == SystemUtils::WindowsVersion::Win_11;
        case anti_cheat::OS_WIN10:
            return m_windowsVersion == SystemUtils::WindowsVersion::Win_10 ||
                   m_windowsVersion == SystemUtils::WindowsVersion::Win_11;
        default:
            return false;
    }
}

void CheatMonitorImpl::AddEvidence(anti_cheat::CheatCategory category, const std::string &description)
{
    std::lock_guard<std::mutex> lock(m_sessionMutex);

    if (m_evidenceOverflowed)
        return;

    if (m_evidences.size() >= (size_t)CheatConfigManager::GetInstance().GetMaxEvidencesPerSession())
    {
        m_evidenceOverflowed = true;
        // 添加一条特殊证据，表明证据缓冲区已满
        anti_cheat::Evidence overflow_evidence;
        overflow_evidence.set_client_timestamp_ms(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                          std::chrono::system_clock::now().time_since_epoch())
                                                          .count());
        overflow_evidence.set_category(anti_cheat::RUNTIME_ERROR);
        overflow_evidence.set_description("Evidence buffer overflow. Further events for this session are suppressed.");
        m_evidences.push_back(overflow_evidence);
        return;
    }

    // 使用 m_uniqueEvidence 集合进行去重检查
    if (m_uniqueEvidence.find({category, description}) != m_uniqueEvidence.end())
    {
        return;  // 相同的证据已经存在，直接返回
    }

    // 检查上报冷却时间
    const auto now = std::chrono::steady_clock::now();

    auto it = m_lastReported.find({m_currentUserId, category});
    if (it != m_lastReported.end())
    {
        auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(now - it->second);
        if (elapsed < std::chrono::minutes(CheatConfigManager::GetInstance().GetReportCooldownMinutes()))
        {
            return;  // 未达到冷却时间，不添加新证据
        }
    }

    // 添加新证据
    anti_cheat::Evidence evidence;
    evidence.set_client_timestamp_ms(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                    .count());
    evidence.set_category(category);
    evidence.set_description(description);

    m_evidences.push_back(evidence);
    m_uniqueEvidence.insert({category, description});
    m_lastReported[{m_currentUserId, category}] = now;  // 更新上报时间

    LOG_WARNING_F(AntiCheatLogger::LogCategory::SECURITY, "Evidence added: %s", description.c_str());
}

void CheatMonitorImpl::UploadHardwareReport()
{
    auto sendWithFingerprint = [&](std::unique_ptr<anti_cheat::HardwareFingerprint> fp) {
        if (!fp)
        {
            fp = std::make_unique<anti_cheat::HardwareFingerprint>();
            fp->set_os_version("ERROR:FingerprintNull");
        }

        anti_cheat::Report report;
        report.set_type(anti_cheat::REPORT_HARDWARE);

        auto hardware_report = report.mutable_hardware();
        hardware_report->set_report_id(Utils::GenerateUuid());
        hardware_report->set_report_timestamp_ms(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                         std::chrono::system_clock::now().time_since_epoch())
                                                         .count());
        *hardware_report->mutable_fingerprint() = *fp;

        SendReport(report);
    };

    if (!m_hwCollector)
    {
        auto fp = std::make_unique<anti_cheat::HardwareFingerprint>();
        fp->set_disk_serial("ERROR:CollectorNull");
        fp->add_mac_addresses("ERROR:CollectorNull");
        fp->set_computer_name("ERROR:CollectorNull");
        fp->set_os_version("ERROR:CollectorNull");
        fp->set_cpu_info("ERROR:CollectorNull");
        sendWithFingerprint(std::move(fp));
        return;
    }

    // 修复：如果fingerprint已被消费（多开场景），先重新收集
    if (!m_hwCollector->GetFingerprint())
    {
        bool collected = m_hwCollector->EnsureCollected();
        if (!collected && !m_hwCollector->GetFingerprint())
        {
            auto fp = std::make_unique<anti_cheat::HardwareFingerprint>();
            fp->set_os_version("ERROR:EnsureCollectedFailed");
            fp->add_mac_addresses("ERROR:EnsureCollectedFailed");
            sendWithFingerprint(std::move(fp));
            return;
        }
    }

    auto fp = m_hwCollector->ConsumeFingerprint();
    if (!fp)
    {
        auto fallback = std::make_unique<anti_cheat::HardwareFingerprint>();
        fallback->set_os_version("ERROR:ConsumeFingerprintNull");
        fallback->add_mac_addresses("ERROR:ConsumeFingerprintNull");
        sendWithFingerprint(std::move(fallback));
        return;
    }

    // 检查硬件信息是否为空（可能是沙箱环境）
    if (fp->disk_serial().empty() && fp->mac_addresses().empty() && fp->computer_name().empty() &&
        fp->cpu_info().empty())
    {
        fp->set_os_version("ERROR:FingerprintEmpty");
        fp->add_mac_addresses("ERROR:FingerprintEmpty");
    }

    sendWithFingerprint(std::move(fp));
}

void CheatMonitorImpl::UploadTargetedSensorReport(const std::string &requestId, const std::string &sensorName,
                                                 SensorExecutionResult result,
                                                 anti_cheat::SensorFailureReason failureReason, int duration_ms,
                                                 const std::string &notes,
                                                 const std::vector<anti_cheat::Evidence> &evidences)
{
    anti_cheat::Report report;
    report.set_type(anti_cheat::REPORT_TARGETED_SENSOR);

    auto targeted = report.mutable_targeted_sensor();
    targeted->set_request_id(requestId);
    targeted->set_sensor_name(sensorName);
    targeted->set_success(result == SensorExecutionResult::SUCCESS);
    targeted->set_failure_reason(failureReason);
    targeted->set_duration_ms(duration_ms >= 0 ? static_cast<uint64_t>(duration_ms) : 0);
    targeted->set_notes(notes);

    for (const auto &evidence : evidences)
    {
        *targeted->add_evidences() = evidence;
    }

    SendReport(report);
}

void CheatMonitorImpl::UploadEvidenceReport()
{
    // 避免在上传过程中持有 m_sessionMutex，以降低死锁/竞态风险
    std::vector<anti_cheat::Evidence> evidencesToSend;
    {
        std::lock_guard<std::mutex> lock(m_sessionMutex);
        if (m_evidences.empty())
            return;
        evidencesToSend.swap(m_evidences);
        m_uniqueEvidence.clear();  // 清空去重集合
    }

    anti_cheat::Report report;
    report.set_type(anti_cheat::REPORT_EVIDENCE);

    auto evidence_report = report.mutable_evidence();
    evidence_report->set_report_id(Utils::GenerateUuid());
    evidence_report->set_report_timestamp_ms(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                    .count());

    // 移动证据到报告中
    for (auto &evidence : evidencesToSend)
    {
        *evidence_report->add_evidences() = std::move(evidence);
    }

    SendReport(report);
}

void CheatMonitorImpl::UploadTelemetryMetricsReport(const anti_cheat::TelemetryMetrics &metrics)
{
    anti_cheat::Report report;
    report.set_type(anti_cheat::REPORT_TELEMETRY);

    auto telemetry_report = report.mutable_telemetry();
    telemetry_report->set_report_id(Utils::GenerateUuid());
    telemetry_report->set_report_timestamp_ms(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                    .count());
    *telemetry_report->mutable_metrics() = metrics;

    SendReport(report);
}

// 新增：快照数据上报
void CheatMonitorImpl::UploadSnapshotReport()
{
    // 检查是否启用
    if (!CheatConfigManager::GetInstance().IsSnapshotUploadEnabled())
    {
        return;
    }

    LOG_INFO(AntiCheatLogger::LogCategory::SYSTEM, "开始采集快照数据...");

    // 采集数据
    auto threads = CollectThreadSnapshots();
    auto modules = CollectModuleSnapshots();

    LOG_INFO_F(AntiCheatLogger::LogCategory::SYSTEM, "采集完成: %zu个线程, %zu个模块", threads.size(), modules.size());

    // 构建报告
    anti_cheat::Report report;
    report.set_type(anti_cheat::REPORT_SNAPSHOT);

    auto snapshot_report = report.mutable_snapshot();
    snapshot_report->set_report_id(Utils::GenerateUuid());
    snapshot_report->set_report_timestamp_ms(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                    .count());
    snapshot_report->set_user_id(m_currentUserId);
    snapshot_report->set_user_name(m_currentUserName);

    // 填充线程数据
    for (const auto &thread : threads)
    {
        *snapshot_report->add_threads() = thread;
    }

    // 填充模块数据
    for (const auto &module : modules)
    {
        *snapshot_report->add_modules() = module;
    }

    // 统计信息
    snapshot_report->set_total_thread_count(static_cast<uint32_t>(threads.size()));
    snapshot_report->set_total_module_count(static_cast<uint32_t>(modules.size()));

    // 发送报告
    SendReport(report);

    LOG_INFO(AntiCheatLogger::LogCategory::SYSTEM, "快照数据上报完成");
}

void CheatMonitorImpl::UploadSensorExecutionStatsReport()
{
    // 创建TelemetryMetrics并填充统一传感器统计数据
    anti_cheat::TelemetryMetrics metrics;
    {
        std::lock_guard<std::mutex> lock(m_sensorStatsMutex);

        // 填充每个传感器的详细执行统计
        for (const auto &kv : m_sensorExecutionStats)
        {
            const std::string &name = kv.first;
            const auto &stats = kv.second;
            // 跳过全0统计，避免后台出现大量0字段
            bool nonEmpty = false;
            if (stats.success_count() > 0 || stats.failure_count() > 0 || stats.timeout_count() > 0 ||
                stats.total_success_time_ms() > 0 || stats.total_failure_time_ms() > 0 ||
                stats.avg_success_time_ms() > 0 || stats.avg_failure_time_ms() > 0 || stats.max_success_time_ms() > 0 ||
                stats.min_success_time_ms() > 0 || stats.max_failure_time_ms() > 0 || stats.min_failure_time_ms() > 0 ||
                stats.workload_snapshot_size_total() > 0 || stats.workload_attempts_total() > 0 ||
                stats.workload_hits_total() > 0 || stats.workload_last_snapshot_size() > 0 ||
                stats.workload_last_attempts() > 0 || stats.workload_last_hits() > 0)
            {
                nonEmpty = true;
            }
            if (!nonEmpty)
                continue;
            // 添加到metrics中
            (*metrics.mutable_sensor_execution_stats())[name] = stats;
        }

        // 清空统计数据，准备下一轮统计
        m_sensorExecutionStats.clear();
    }

    // 汇总上报不需要设置基础信息字段，只包含传感器统计数据

    UploadTelemetryMetricsReport(metrics);
}
void CheatMonitorImpl::RecordSensorExecutionStats(const char *name, int duration_ms, SensorExecutionResult result,
                                                     anti_cheat::SensorFailureReason failureReason)
{
    std::lock_guard<std::mutex> lock(m_sensorStatsMutex);

    auto &stats = m_sensorExecutionStats[name];

    // 更新执行次数和时间统计（抑制为0的时间字段赋值）
    switch (result)
    {
        case SensorExecutionResult::SUCCESS:
            stats.set_success_count(stats.success_count() + 1);
            if (duration_ms > 0)
            {
                stats.set_total_success_time_ms(stats.total_success_time_ms() + duration_ms);
                if (stats.total_success_time_ms() > 0 && stats.success_count() > 0)
                {
                    stats.set_avg_success_time_ms(stats.total_success_time_ms() / stats.success_count());
                }
                // 更新最大/最小成功执行时间
                if (stats.max_success_time_ms() == 0 || duration_ms > stats.max_success_time_ms())
                {
                    stats.set_max_success_time_ms(duration_ms);
                }
                if (stats.min_success_time_ms() == 0 || duration_ms < stats.min_success_time_ms())
                {
                    stats.set_min_success_time_ms(duration_ms);
                }
            }
            break;
        case SensorExecutionResult::FAILURE:
            stats.set_failure_count(stats.failure_count() + 1);
            if (duration_ms > 0)
            {
                stats.set_total_failure_time_ms(stats.total_failure_time_ms() + duration_ms);
                if (stats.total_failure_time_ms() > 0 && stats.failure_count() > 0)
                {
                    stats.set_avg_failure_time_ms(stats.total_failure_time_ms() / stats.failure_count());
                }
                // 更新最大/最小失败执行时间
                if (stats.max_failure_time_ms() == 0 || duration_ms > stats.max_failure_time_ms())
                {
                    stats.set_max_failure_time_ms(duration_ms);
                }
                if (stats.min_failure_time_ms() == 0 || duration_ms < stats.min_failure_time_ms())
                {
                    stats.set_min_failure_time_ms(duration_ms);
                }
            }
            break;
        case SensorExecutionResult::TIMEOUT:
            stats.set_timeout_count(stats.timeout_count() + 1);
            // 超时统计只记录次数，不记录时间
            break;
    }

    // 记录失败原因（使用enum索引）
    if (result == SensorExecutionResult::FAILURE && failureReason != anti_cheat::UNKNOWN_FAILURE)
    {
        (*stats.mutable_failure_reasons())[static_cast<int32_t>(failureReason)]++;
    }
}
void CheatMonitorImpl::RecordSensorWorkloadCounters(const std::string &name, uint64_t snapshot_size,
                                                       uint64_t attempts, uint64_t hits)
{
    std::lock_guard<std::mutex> lock(m_sensorStatsMutex);
    auto &stats = m_sensorExecutionStats[name];
    // 仅在非零时赋值，避免上报全0字段
    if (snapshot_size)
    {
        stats.set_workload_snapshot_size_total(stats.workload_snapshot_size_total() + snapshot_size);
        stats.set_workload_last_snapshot_size(snapshot_size);
    }
    if (attempts)
    {
        stats.set_workload_attempts_total(stats.workload_attempts_total() + attempts);
        stats.set_workload_last_attempts(attempts);
    }
    if (hits)
    {
        stats.set_workload_hits_total(stats.workload_hits_total() + hits);
        stats.set_workload_last_hits(hits);
    }
}

void CheatMonitorImpl::SendReport(const anti_cheat::Report &report)
{
    std::string serialized_report;
    if (!report.SerializeToString(&serialized_report))
    {
        LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM, "Failed to serialize report");
        return;
    }

    const char *report_type_name = "Unknown";
    size_t content_size = 0;

    switch (report.type())
    {
        case anti_cheat::REPORT_HARDWARE:
            report_type_name = "Hardware";
            if (report.has_hardware())
            {
                content_size = 1;  // 1个硬件指纹
            }
            break;
        case anti_cheat::REPORT_EVIDENCE:
            report_type_name = "Evidence";
            if (report.has_evidence())
            {
                content_size = report.evidence().evidences_size();
            }
            break;
        case anti_cheat::REPORT_TELEMETRY:
            report_type_name = "Telemetry";
            if (report.has_telemetry())
            {
                content_size = 1;  // 1个遥测包
            }
            break;
        case anti_cheat::REPORT_SNAPSHOT:
            report_type_name = "Snapshot";
            if (report.has_snapshot())
            {
                content_size = report.snapshot().threads_size() + report.snapshot().modules_size();
            }
            break;
        case anti_cheat::REPORT_SERVER_LOG:
            report_type_name = "ServerLog";
            if (report.has_server_log())
            {
                content_size = 1;  // 1条日志
            }
            break;
        default:
            break;
    }

    LOG_INFO_F(AntiCheatLogger::LogCategory::SYSTEM, "Uploading %s report... Size: %zu bytes, content items: %zu",
               report_type_name, serialized_report.length(), content_size);

    // TODO: 将 report 序列化并通过网络发送到服务器
    // HttpSend(server_url, serialized_report);
}

void CheatMonitorImpl::SendServerLog(const std::string &log_level, const std::string &log_category,
                                        const std::string &log_message)
{
    anti_cheat::Report report;
    report.set_type(anti_cheat::REPORT_SERVER_LOG);

    // 生成唯一的report_id
    static std::atomic<uint64_t> log_counter{0};
    std::string report_id = "LOG_" + std::to_string(++log_counter);

    // 获取当前时间戳（毫秒）
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

    // 填充ServerLogReport
    anti_cheat::ServerLogReport *server_log = report.mutable_server_log();
    server_log->set_report_id(report_id);
    server_log->set_report_timestamp_ms(ms);
    server_log->set_log_level(log_level);
    server_log->set_log_category(log_category);
    server_log->set_log_message(log_message);

    SendReport(report);
}

void CheatMonitorImpl::HardenProcessAndThreads()
{
    // 1. 检查当前进程权限
    bool isElevated = false;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size))
        {
            isElevated = elevation.TokenIsElevated != 0;
        }
        CloseHandle(hToken);
    }

    if (!isElevated)
    {
        LOG_WARNING(AntiCheatLogger::LogCategory::SYSTEM, "进程未以管理员权限运行，某些安全策略可能无法设置");
    }

    // 2. 启用进程缓解策略 (DEP, 禁止创建子进程等)
    // 动态加载 SetProcessMitigationPolicy
    typedef BOOL(WINAPI * PSetProcessMitigationPolicy)(PROCESS_MITIGATION_POLICY Policy, PVOID lpBuffer,
                                                        SIZE_T dwLength);
    static PSetProcessMitigationPolicy pSetProcessMitigationPolicy = (PSetProcessMitigationPolicy)GetProcAddress(
            GetModuleHandleW(L"kernel32.dll"), "SetProcessMitigationPolicy");

    if (pSetProcessMitigationPolicy)
    {
        int successCount = 0;
        int totalPolicies = 2;

        // 启用DEP - 检查返回值和错误
        PROCESS_MITIGATION_DEP_POLICY depPolicy = {};
        depPolicy.Enable = 1;
        depPolicy.Permanent = false;  // 改为false，减少权限要求
        BOOL depResult = pSetProcessMitigationPolicy(ProcessDEPPolicy, &depPolicy, sizeof(depPolicy));
        if (depResult)
        {
            successCount++;
            LOG_INFO(AntiCheatLogger::LogCategory::SYSTEM, "DEP缓解策略已启用");
        }
        else
        {
            DWORD error = GetLastError();
            // 对于常见的预期错误，使用INFO级别而不是WARNING
            if (error == ERROR_ACCESS_DENIED || error == ERROR_NOT_SUPPORTED || error == ERROR_ALREADY_EXISTS)
            {
                LOG_INFO_F(AntiCheatLogger::LogCategory::SYSTEM, "DEP缓解策略设置跳过，错误代码: %lu (预期情况)",
                           error);
            }
            else
            {
                LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM, "DEP缓解策略设置失败，错误代码: %lu", error);
            }
        }

        // 禁止创建子进程 - 检查返回值和错误
        PROCESS_MITIGATION_CHILD_PROCESS_POLICY childPolicy = {};
        childPolicy.NoChildProcessCreation = 1;
        BOOL childResult = pSetProcessMitigationPolicy(ProcessChildProcessPolicy, &childPolicy, sizeof(childPolicy));
        if (childResult)
        {
            successCount++;
            LOG_INFO(AntiCheatLogger::LogCategory::SYSTEM, "子进程禁止策略已启用");
        }
        else
        {
            DWORD error = GetLastError();
            // 对于常见的预期错误，使用INFO级别而不是WARNING
            if (error == ERROR_ACCESS_DENIED || error == ERROR_NOT_SUPPORTED || error == ERROR_ALREADY_EXISTS)
            {
                LOG_INFO_F(AntiCheatLogger::LogCategory::SYSTEM, "子进程禁止策略设置跳过，错误代码: %lu (预期情况)",
                           error);
            }
            else
            {
                LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM, "子进程禁止策略设置失败，错误代码: %lu", error);
            }
        }

        // 总结策略设置结果
        if (successCount == totalPolicies)
        {
            LOG_INFO(AntiCheatLogger::LogCategory::SYSTEM, "所有进程缓解策略已成功启用");
        }
        else if (successCount > 0)
        {
            LOG_INFO_F(AntiCheatLogger::LogCategory::SYSTEM, "已启用 %d/%d 个进程缓解策略", successCount,
                       totalPolicies);
        }
        else
        {
            LOG_INFO(AntiCheatLogger::LogCategory::SYSTEM, "未能启用进程缓解策略 (这在某些环境下是正常的)");
        }
    }
    else
    {
        // API不可用通常是因为系统版本过低，不视为错误
        LOG_WARNING(AntiCheatLogger::LogCategory::SYSTEM,
                    "SetProcessMitigationPolicy API 不可用，可能是系统版本过低。");
    }

    // 2. 隐藏我们自己的监控线程，增加逆向分析难度
    // 使用SystemUtils命名空间中的g_pNtSetInformationThread
    if (SystemUtils::g_pNtSetInformationThread)
    {
        NTSTATUS status = SystemUtils::g_pNtSetInformationThread(GetCurrentThread(),
                                                                 (THREADINFOCLASS)17,  // ThreadHideFromDebugger
                                                                 nullptr, 0);
        if (!NT_SUCCESS(status))
        {
            // 线程隐藏失败通常不影响功能，只记录日志
            LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM, "线程隐藏设置失败，NTSTATUS: 0x%08X", status);
        }
        else
        {
            LOG_INFO(AntiCheatLogger::LogCategory::SYSTEM, "监控线程已设置为对调试器隐藏");
        }
    }
    else
    {
        LOG_WARNING(AntiCheatLogger::LogCategory::SYSTEM, "NtSetInformationThread API 不可用，无法隐藏监控线程");
    }
}

void CheatMonitorImpl::CheckParentProcessAtStartup()
{
    // 最终版逻辑：考虑到启动器loader.exe启动后立即退出的竞态条件。
    // 1. 如果父进程存在，则必须是 loader.exe，否则立即上报。
    // 2. 如果父进程不存在（孤儿进程），则标记为可疑，交由 SuspiciousLaunchSensor 做后续关联分析。
    DWORD parentPid = 0;
    std::string parentName;
    if (Utils::GetParentProcessInfo(parentPid, parentName))
    {
        // Case 1: Parent process was found.
        std::transform(parentName.begin(), parentName.end(), parentName.begin(), ::tolower);
        if (parentName != "loader.exe")
        {
            AddEvidence(anti_cheat::ENVIRONMENT_INVALID_PARENT_PROCESS,
                        "Invalid parent process: " + parentName + " (PID: " + std::to_string(parentPid) + ")");
        }
        // If parent is loader.exe, this is a valid launch. m_parentWasMissingAtStartup remains false.
    }
    else
    {
        // Case 2: Parent process not found (orphaned).
        // This could indicate an abnormal launch, but we don't treat it as definitive evidence
        // since many legitimate launchers exit after starting the game.
        LOG_INFO(AntiCheatLogger::LogCategory::SYSTEM, "Parent process not found - could be normal launcher behavior");
    }
}

void CheatMonitorImpl::DetectVirtualMachine()
{
    DetectVmByCpuid();
    DetectVmByRegistry();
    DetectVmByMacAddress();
}

void CheatMonitorImpl::DetectVmByCpuid()
{
    std::array<int, 4> cpuid_info;
    __cpuid(cpuid_info.data(), 1);
    if ((cpuid_info[2] >> 31) & 1)
    {
        AddEvidence(anti_cheat::ENVIRONMENT_VIRTUAL_MACHINE, "检测到虚拟机环境 (CPUID hypervisor bit)");
    }

    __cpuid(cpuid_info.data(), 0x40000000);
    std::string vendor_id;
    vendor_id.append(reinterpret_cast<char *>(&cpuid_info[1]), 4);
    vendor_id.append(reinterpret_cast<char *>(&cpuid_info[2]), 4);
    vendor_id.append(reinterpret_cast<char *>(&cpuid_info[3]), 4);

    if (vendor_id.find("VMware") != std::string::npos || vendor_id.find("KVMKVMKVM") != std::string::npos ||
        vendor_id.find("VBoxVBoxVBox") != std::string::npos || vendor_id.find("Microsoft Hv") != std::string::npos)
    {
        AddEvidence(anti_cheat::ENVIRONMENT_VIRTUAL_MACHINE, "检测到虚拟机环境 (CPUID vendor ID: " + vendor_id + ")");
    }
}

void CheatMonitorImpl::DetectVmByRegistry()
{
    const wchar_t *vmKeys[] = {L"HARDWARE\\DESCRIPTION\\System\\BIOS\\SystemManufacturer",
                               L"HARDWARE\\DESCRIPTION\\System\\BIOS\\SystemProductName"};
    const wchar_t *vmValues[] = {L"vmware", L"virtualbox", L"qemu", L"kvm", L"microsoft"};

    for (const auto &key : vmKeys)
    {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
        {
            wchar_t buffer[256];
            DWORD size = sizeof(buffer);
            if (RegQueryValueExW(hKey, L"SystemManufacturer", NULL, NULL, (LPBYTE)buffer, &size) == ERROR_SUCCESS)
            {
                std::wstring manufacturer(buffer);
                std::transform(manufacturer.begin(), manufacturer.end(), manufacturer.begin(), ::towlower);
                for (const auto &vm : vmValues)
                {
                    if (manufacturer.find(vm) != std::wstring::npos)
                    {
                        AddEvidence(anti_cheat::ENVIRONMENT_VIRTUAL_MACHINE,
                                    "检测到虚拟机环境 (Registry: " + Utils::WideToString(manufacturer) + ")");
                        RegCloseKey(hKey);
                        return;
                    }
                }
            }
            RegCloseKey(hKey);
        }
    }
}

void CheatMonitorImpl::DetectVmByMacAddress()
{
    // VMware, VirtualBox, Hyper-V 等常用虚拟机的MAC地址前缀
    const std::vector<std::string> vmMacPrefixes = {"00:05:69", "00:0C:29", "00:1C:14",
                                                    "00:50:56", "08:00:27", "00:15:5D"};

    ULONG bufferSize = sizeof(IP_ADAPTER_INFO);
    std::vector<BYTE> buffer(bufferSize);
    PIP_ADAPTER_INFO pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());

    if (GetAdaptersInfo(pAdapterInfo, &bufferSize) == ERROR_BUFFER_OVERFLOW)
    {
        buffer.resize(bufferSize);
        pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
    }

    if (GetAdaptersInfo(pAdapterInfo, &bufferSize) == NO_ERROR)
    {
        while (pAdapterInfo)
        {
            char macStr[18];
            sprintf_s(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X", pAdapterInfo->Address[0],
                      pAdapterInfo->Address[1], pAdapterInfo->Address[2], pAdapterInfo->Address[3],
                      pAdapterInfo->Address[4], pAdapterInfo->Address[5]);

            for (const auto &prefix : vmMacPrefixes)
            {
                if (std::string(macStr).rfind(prefix, 0) == 0)
                {
                    AddEvidence(anti_cheat::ENVIRONMENT_VIRTUAL_MACHINE,
                                "检测到虚拟机环境 (MAC Address: " + std::string(macStr) + ")");
                    return;
                }
            }
            pAdapterInfo = pAdapterInfo->Next;
        }
    }
}

void CheatMonitorImpl::VerifyModuleSignature(HMODULE hModule)
{
    wchar_t modulePath_w[MAX_PATH];
    if (GetModuleFileNameW(hModule, modulePath_w, MAX_PATH) == 0)
    {
        return;
    }
    // 统一规范化为绝对路径并转小写，避免缓存/节流键不一致
    std::wstring modulePath = modulePath_w;
    std::transform(modulePath.begin(), modulePath.end(), modulePath.begin(), ::towlower);

    const auto now = std::chrono::steady_clock::now();
    // 读取TTL一次，减少锁内工作量
    const auto ttl = std::chrono::minutes(CheatConfigManager::GetInstance().GetSignatureCacheDurationMinutes());
    {
        // 确定性清理：每次调用都清理过期项，确保内存使用稳定
        // 使用迭代器安全删除过期项
        for (auto it = m_moduleSignatureCache.begin(); it != m_moduleSignatureCache.end();)
        {
            if (now >= it->second.second + ttl)
                it = m_moduleSignatureCache.erase(it);
            else
                ++it;
        }
        // 节流：同一路径在短窗口内只验证一次，避免一个扫描周期内的重复开销
        const auto itThr = m_sigThrottleUntil.find(modulePath);
        if (itThr != m_sigThrottleUntil.end() && now < itThr->second)
        {
            return;
        }

        auto it = m_moduleSignatureCache.find(modulePath);
        if (it != m_moduleSignatureCache.end())
        {
            // Check cache expiry (TTL)
            if (now < it->second.second + ttl)
            {
                return;  // Still valid, no need to re-verify
            }
        }
    }

    //  改进签名验证逻辑，更严格地处理验证失败的情况，解决专家提出的"宽松处理"问题。
    // 只有在明确验证为"可信"或"不可信"时才更新缓存。
    // 如果验证过程本身失败（例如，网络问题导致无法检查吊销列表），则不更新缓存，
    // 以便在下一次扫描时重试。
    switch (Utils::VerifyFileSignature(modulePath, m_windowsVersion))
    {
        case Utils::SignatureStatus::TRUSTED: {
            m_moduleSignatureCache[modulePath] = {SignatureVerdict::SIGNED_AND_TRUSTED, now};
            // 设置短节流窗口，避免本周期内重复验证
            m_sigThrottleUntil[modulePath] =
                    now +
                    std::chrono::seconds(CheatConfigManager::GetInstance().GetSignatureVerificationThrottleSeconds());
        }
        break;
        case Utils::SignatureStatus::UNTRUSTED: {
            // 使用统一的模块验证逻辑（包含白名单检查）
            Utils::ModuleValidationResult validation = Utils::ValidateModule(modulePath, m_windowsVersion);

            if (validation.isTrusted)
            {
                // 白名单验证通过，视为可信
                m_moduleSignatureCache[modulePath] = {SignatureVerdict::SIGNED_AND_TRUSTED, now};
                m_sigThrottleUntil[modulePath] =
                        now + std::chrono::seconds(CheatConfigManager::GetInstance().GetSignatureVerificationThrottleSeconds());

                LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR, "模块验证通过: %s (%s)",
                            Utils::WideToString(modulePath).c_str(), validation.reason.c_str());
            }
            else
            {
                // 验证失败，标记为不可信
                m_moduleSignatureCache[modulePath] = {SignatureVerdict::UNSIGNED_OR_UNTRUSTED, now};
                m_sigThrottleUntil[modulePath] =
                        now + std::chrono::seconds(CheatConfigManager::GetInstance().GetSignatureVerificationThrottleSeconds());

                // 在 XP/Vista/Win7 上降噪
                if (m_windowsVersion != SystemUtils::WindowsVersion::Win_XP &&
                    m_windowsVersion != SystemUtils::WindowsVersion::Win_Vista_Win7)
                {
                    AddEvidence(anti_cheat::RUNTIME_MODULE_NEW_UNKNOWN,
                                "加载了不可信模块: " + Utils::WideToString(modulePath) +
                                " (原因: " + validation.reason + ")");
                }
            }
        }
        break;
        case Utils::SignatureStatus::FAILED_TO_VERIFY:
            // 不缓存验证失败的结果，以便下次扫描时可以重试。
            // 但为了避免频繁抖动，设置更短的节流窗口。
            m_sigThrottleUntil[modulePath] =
                    now + std::chrono::milliseconds(
                                  CheatConfigManager::GetInstance().GetSignatureVerificationFailureThrottleMs());
            break;
    }
}

bool CheatMonitorImpl::IsAddressInLegitimateModule(PVOID address, std::wstring &outModulePath)
{
    HMODULE hModule = NULL;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)address, &hModule) &&
        hModule)
    {
        wchar_t modulePath_w[MAX_PATH];
        if (GetModuleFileNameW(hModule, modulePath_w, MAX_PATH) > 0)
        {
            outModulePath = modulePath_w;
            std::wstring originalPath = outModulePath;
            std::transform(outModulePath.begin(), outModulePath.end(), outModulePath.begin(), ::towlower);

            std::lock_guard<std::mutex> lock(m_modulePathsMutex);
            bool isLegitimate = m_legitimateModulePaths.count(outModulePath) > 0;

            // 如果不在已知合法列表，尝试使用通用白名单逻辑检查
            if (!isLegitimate)
            {
                isLegitimate = Utils::IsWhitelistedModule(originalPath);
            }

            // 添加调试日志：记录模块检查结果
            if (!isLegitimate)
            {
                // 使用OutputDebugString记录详细信息
                std::wostringstream debugMsg;
                debugMsg << L"[IsAddressInLegitimateModule] 地址 0x" << std::hex << address
                         << L" 不在合法模块中. 模块路径: " << originalPath << L" (小写: " << outModulePath << L")"
                         << std::endl;
                OutputDebugStringW(debugMsg.str().c_str());

                // 同时记录到日志系统
                LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                            "IsAddressInLegitimateModule: 地址 0x%p 不在合法模块中, 模块路径=%s", address,
                            Utils::WideToString(originalPath).c_str());
            }
            else
            {
                // 记录成功的匹配（可选，用于验证）
                LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                            "IsAddressInLegitimateModule: 地址 0x%p 匹配合法模块, 模块路径=%s", address,
                            Utils::WideToString(originalPath).c_str());
            }

            return isLegitimate;
        }
        else
        {
            // GetModuleFileNameW失败
            LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                        "IsAddressInLegitimateModule: 地址 0x%p 获取模块路径失败, hModule=0x%p", address, hModule);
        }
    }
    else
    {
        // GetModuleHandleExW失败
            LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR, "IsAddressInLegitimateModule: 地址 0x%p 不属于任何模块",
                        address);
    }
    return false;
}

bool CheatMonitorImpl::IsAddressInLegitimateModule(PVOID address)
{
    std::wstring dummyPath;  // 不需要的路径参数
    return IsAddressInLegitimateModule(address, dummyPath);
}

uintptr_t CheatMonitorImpl::FindVehListAddress()
{
    //  采用单一、更可靠的"诱饵处理函数"方法来定位VEH链表。
    // 此方法比依赖脆弱的字节码模式匹配要稳定得多，能更好地适应Windows版本更新。

    // 添加retry机制：AddVectoredExceptionHandler可能因为系统负载等原因失败
    PVOID pDecoyHandler = nullptr;
    int retryCount = 0;
    int maxRetries = 3;

    while (!pDecoyHandler && retryCount < 3)
    {
        pDecoyHandler = AddVectoredExceptionHandler(1, SystemUtils::DecoyVehHandler);
        if (!pDecoyHandler)
        {
            retryCount++;
            DWORD error = GetLastError();
            LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM,
                          "FindVehListAddress: AddVectoredExceptionHandler失败 (尝试 %d/%d)，错误码: 0x%08X",
                          retryCount, maxRetries, error);

            if (retryCount < maxRetries)
            {
                Sleep(300);
            }
        }
    }

    if (!pDecoyHandler)
    {
        LOG_ERROR_F(AntiCheatLogger::LogCategory::SYSTEM,
                    "FindVehListAddress Error: AddVectoredExceptionHandler failed after %d retries.", maxRetries);
        return 0;
    }

    uintptr_t listHeadAddress = 0;
    __try
    {
        const auto *pEntry = reinterpret_cast<const VECTORED_HANDLER_ENTRY *>(pDecoyHandler);
        const LIST_ENTRY *pCurrent = &pEntry->List;

        // 向后遍历链表以查找头节点，设置迭代上限以防意外的循环
        for (int i = 0; i < 100; ++i)
        {
            const LIST_ENTRY *pBlink = pCurrent->Blink;
            if (!SystemUtils::IsValidPointer(pBlink, sizeof(LIST_ENTRY)) ||
                !SystemUtils::IsValidPointer(pBlink->Flink, sizeof(LIST_ENTRY *)))
            {
                break;  // 链表指针无效，终止遍历
            }

            // 链表头的特征：Blink->Flink == 当前节点
            if (pBlink->Flink == pCurrent)
            {
                listHeadAddress = reinterpret_cast<uintptr_t>(pBlink);
                break;
            }
            pCurrent = pBlink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        //  记录异常代码
        LOG_ERROR_F(AntiCheatLogger::LogCategory::SYSTEM, "FindVehListAddress SEH Exception. Code: 0x%08X",
                    GetExceptionCode());
        listHeadAddress = 0;
    }

    if (!RemoveVectoredExceptionHandler(pDecoyHandler))
    {
        LOG_ERROR_F(AntiCheatLogger::LogCategory::SYSTEM,
                    "FindVehListAddress Error: Failed to remove decoy VEH handler. Error: 0x%08X", GetLastError());
    }

    if (listHeadAddress == 0)
    {
        LOG_ERROR(AntiCheatLogger::LogCategory::SYSTEM, "FindVehListAddress Error: Could not find VEH list head.");
        return 0;
    }

    // 根据Windows版本，从链表头地址计算整个VEH列表结构的基地址
    // 这是必要的，因为VEH列表结构在不同Windows版本中不同
    uintptr_t structBaseAddress = 0;
    SystemUtils::WindowsVersion ver = SystemUtils::GetWindowsVersion();
    if (ver == SystemUtils::WindowsVersion::Win_Unknown)
    {
        LOG_WARNING(AntiCheatLogger::LogCategory::SYSTEM,
                    "Unknown Windows version. Assuming Win8+ VEH list structure.");
        // 对于未知或未来的版本，默认使用最新的已知结构是一个合理的降级策略。
    }

    switch (ver)
    {
        case SystemUtils::WindowsVersion::Win_XP:
            // 在XP中，List成员在CRITICAL_SECTION之后
            structBaseAddress = listHeadAddress - offsetof(VECTORED_HANDLER_LIST_XP, List);
            break;
        case SystemUtils::WindowsVersion::Win_Vista_Win7:
            // 在Vista/7中，是ExceptionList成员在CRITICAL_SECTION之后
            structBaseAddress = listHeadAddress - offsetof(VECTORED_HANDLER_LIST_VISTA, ExceptionList);
            break;
        case SystemUtils::WindowsVersion::Win_Unknown:  // 让未知情况的处理更明确
        default:                                        // Win8及更新版本
            structBaseAddress = listHeadAddress - offsetof(VECTORED_HANDLER_LIST_WIN8, ExceptionList);
            break;
    }

    LOG_INFO_F(AntiCheatLogger::LogCategory::SYSTEM, "Dynamically located VEH list structure at: 0x%p",
               (void *)structBaseAddress);
    return structBaseAddress;
}

void CheatMonitorImpl::InitializeSelfIntegrityBaseline()
{
    // 获取 IsAddressInLegitimateModule 函数的地址
    // 注意：成员函数指针转换需要小心处理
    union
    {
        bool (CheatMonitorImpl::*pmf)(PVOID, std::wstring &);
        void *p;
    } u;
    u.pmf = &CheatMonitorImpl::IsAddressInLegitimateModule;

    if (u.p)
    {
        // 读取函数前16个字节作为基线
        // 这足以检测常见的 JMP/RET Patch
        uint8_t buffer[16];
        SIZE_T bytesRead = 0;
        if (ReadProcessMemory(GetCurrentProcess(), u.p, buffer, sizeof(buffer), &bytesRead) && bytesRead == sizeof(buffer))
        {
            m_isAddressInLegitimateModulePrologue.assign(buffer, buffer + sizeof(buffer));
            LOG_INFO_F(AntiCheatLogger::LogCategory::SYSTEM, "自我完整性基线已建立: IsAddressInLegitimateModule @ %p", u.p);
        }
        else
        {
            LOG_ERROR(AntiCheatLogger::LogCategory::SYSTEM, "无法读取 IsAddressInLegitimateModule 函数内存以建立基线");
        }
    }
}

void CheatMonitorImpl::CheckSelfIntegrity()
{
    if (m_isAddressInLegitimateModulePrologue.empty())
        return;

    union
    {
        bool (CheatMonitorImpl::*pmf)(PVOID, std::wstring &);
        void *p;
    } u;
    u.pmf = &CheatMonitorImpl::IsAddressInLegitimateModule;

    if (!u.p)
        return;

    uint8_t currentBytes[16];
    SIZE_T bytesRead = 0;
    if (ReadProcessMemory(GetCurrentProcess(), u.p, currentBytes, sizeof(currentBytes), &bytesRead) &&
        bytesRead == sizeof(currentBytes))
    {
        if (memcmp(currentBytes, m_isAddressInLegitimateModulePrologue.data(), sizeof(currentBytes)) != 0)
        {
            // 检测到篡改
            std::string diff;
            for (size_t i = 0; i < sizeof(currentBytes); ++i)
            {
                if (currentBytes[i] != m_isAddressInLegitimateModulePrologue[i])
                {
                    diff += Utils::FormatString(" [+%zu: %02X->%02X]", i, m_isAddressInLegitimateModulePrologue[i],
                                                currentBytes[i]);
                }
            }

            AddEvidence(anti_cheat::INTEGRITY_SELF_TAMPERING,
                        "关键反作弊函数 (IsAddressInLegitimateModule) 被篡改: " + diff);

            // 尝试恢复（可选，但在反外挂中通常只上报）
            // WriteProcessMemory(GetCurrentProcess(), u.p, m_isAddressInLegitimateModulePrologue.data(), ...);
        }
    }
}

VOID CALLBACK CheatMonitorImpl::DllLoadCallback(ULONG NotificationReason, const LDR_DLL_NOTIFICATION_DATA *NotificationData, PVOID Context)
{
    if (NotificationReason == LDR_DLL_NOTIFICATION_REASON_LOADED)
    {
        auto *pimpl = static_cast<CheatMonitor::Pimpl *>(Context);
        if (pimpl)
        {
            pimpl->OnDllLoaded(NotificationData->Loaded);
        }
    }
}


void CheatMonitorImpl::RegisterDllNotification()
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll)
        return;

    auto pLdrRegisterDllNotification = (P_LdrRegisterDllNotification)GetProcAddress(hNtdll, "LdrRegisterDllNotification");
    if (pLdrRegisterDllNotification && !m_dllNotificationCookie)
    {
        // 0 = standard notification
        pLdrRegisterDllNotification(0, DllLoadCallback, this, &m_dllNotificationCookie);
    }
}

void CheatMonitorImpl::UnregisterDllNotification()
{
    if (m_dllNotificationCookie)
    {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll)
        {
            auto pLdrUnregisterDllNotification = (P_LdrUnregisterDllNotification)GetProcAddress(hNtdll, "LdrUnregisterDllNotification");
            if (pLdrUnregisterDllNotification)
            {
                pLdrUnregisterDllNotification(m_dllNotificationCookie);
            }
        }
        m_dllNotificationCookie = nullptr;
    }
}

void CheatMonitorImpl::OnDllLoaded(const LDR_DLL_LOAD_NOTIFICATION_DATA &data)
{
    if (!data.FullDllName || !data.FullDllName->Buffer)
        return;

    std::wstring modulePath(data.FullDllName->Buffer, data.FullDllName->Length / sizeof(WCHAR));

    // Check whitelist using the unified logic
    if (Utils::IsWhitelistedModule(modulePath))
    {
        return;
    }

    std::string pathStr = Utils::WideToString(modulePath);
    LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "Runtime DLL Loaded: %s", pathStr.c_str());

    AddEvidence(anti_cheat::RUNTIME_MODULE_INJECTION, "Runtime DLL load detected: " + pathStr);
}

void CheatMonitorImpl::OnProcessCreated(DWORD pid, const std::wstring &name)
{
    // Convert name to lowercase/standardize
    std::wstring lowerName = name;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);

    // Check harmful process names
    auto harmfulNames = CheatConfigManager::GetInstance().GetHarmfulProcessNames();
    if (harmfulNames)
    {
        for (const auto &harmful : *harmfulNames)
        {
            if (lowerName.find(harmful) != std::wstring::npos)
            {
                // Found harmful process
                std::string u8Name = Utils::WideToString(name);
                LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "WMI Monitor: Harmful process detected: %s (PID: %lu)",
                              u8Name.c_str(), pid);
                AddEvidence(anti_cheat::RUNTIME_PROCESS_BLACKLIST, "Harmful process started: " + u8Name);
                return;
            }
        }
    }
}


const std::chrono::milliseconds CheatMonitorImpl::GetLightScanInterval() const
{
    // 轻量级传感器：使用配置的扫描间隔 + 随机抖动
    const auto base_interval = std::chrono::seconds(CheatConfigManager::GetInstance().GetBaseScanInterval());
    const auto jitter = std::chrono::milliseconds(m_rng() % 2000);
    return base_interval + jitter;
}

const std::chrono::milliseconds CheatMonitorImpl::GetHeavyScanInterval() const
{
    // 重量级传感器：使用配置的扫描间隔 + 随机抖动
    const auto base_interval = std::chrono::minutes(CheatConfigManager::GetInstance().GetHeavyScanIntervalMinutes());
    const auto jitter = std::chrono::milliseconds(m_rng() % 60000);
    return base_interval + jitter;
}

void CheatMonitorImpl::ExecuteLightweightSensors()
{
    if (m_lightweightSensors.empty())
        return;

    // 创建上下文并刷新缓存 (一次刷新供所有传感器使用)
    ScanContext context(this, false /*isTargetedScan*/);
    context.RefreshModuleCache();

    // 轻量级传感器：执行所有传感器，实现高频全面检测
    for (const auto &sensor : m_lightweightSensors)
    {
        ExecuteAndMonitorSensor(sensor.get(), sensor->GetName(), false /*isHeavyweight*/, context);
    }
    // 移除Round Robin索引更新
}

void CheatMonitorImpl::ExecuteHeavyweightSensors()
{
    if (m_heavyweightSensors.empty())
        return;

    // 创建上下文并刷新缓存 (一次刷新供所有传感器使用)
    ScanContext context(this, false /*isTargetedScan*/);
    context.RefreshModuleCache();
    context.RefreshMemoryCache();

    // 重量级传感器：执行所有传感器
    for (const auto &sensor : m_heavyweightSensors)
    {
        ExecuteAndMonitorSensor(sensor.get(), sensor->GetName(), true /*isHeavyweight*/, context);
    }
// 移除Round Robin索引更新
}
SensorExecutionResult CheatMonitorImpl::ExecuteAndMonitorSensor(ISensor *sensor, const char *name,
                                                                   bool isHeavyweight, ScanContext &context,
                                                                   anti_cheat::SensorFailureReason *outFailure,
                                                                   int *outDurationMs)
{
    const auto startTime = std::chrono::steady_clock::now();
    // ScanContext context(this, isTargetedScan); // Removed local instantiation
    SensorExecutionResult result = SensorExecutionResult::FAILURE;
    anti_cheat::SensorFailureReason failureReason = anti_cheat::UNKNOWN_FAILURE;

    try
    {
        result = sensor->Execute(context);
        const auto end = std::chrono::steady_clock::now();
        const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - startTime).count();

        if (result == SensorExecutionResult::FAILURE)
        {
            failureReason = sensor->GetLastFailureReason();
        }

        // 统一记录传感器执行统计
        RecordSensorExecutionStats(name, (int)elapsed_ms, result, failureReason);

        if (outFailure)
            *outFailure = failureReason;
        if (outDurationMs)
            *outDurationMs = (int)elapsed_ms;
        return result;
    }
    catch (const std::exception &e)
    {
        // 统一异常处理：既记录日志又记录统计
        const auto end = std::chrono::steady_clock::now();
        const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - startTime).count();
        LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR, "传感器异常: %s - %s", name, e.what());

        // 记录异常执行统计 - 使用更明确的C++异常失败原因
        RecordSensorExecutionStats(name, (int)elapsed_ms, SensorExecutionResult::FAILURE,
                                   anti_cheat::CPP_EXCEPTION_FAILURE);
        if (outFailure)
            *outFailure = anti_cheat::CPP_EXCEPTION_FAILURE;
        if (outDurationMs)
            *outDurationMs = (int)elapsed_ms;
        return SensorExecutionResult::FAILURE;
    }
    catch (...)
    {
        // 统一未知异常处理
        const auto end = std::chrono::steady_clock::now();
        const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - startTime).count();
        LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR, "传感器未知异常: %s", name);

        // 记录异常执行统计 - 使用更明确的未知异常失败原因
        RecordSensorExecutionStats(name, (int)elapsed_ms, SensorExecutionResult::FAILURE,
                                   anti_cheat::UNKNOWN_EXCEPTION_FAILURE);
        if (outFailure)
            *outFailure = anti_cheat::UNKNOWN_EXCEPTION_FAILURE;
        if (outDurationMs)
            *outDurationMs = (int)elapsed_ms;
        return SensorExecutionResult::FAILURE;
    }
}

void CheatMonitorImpl::AddRandomJitter()
{
    // 增加随机抖动，避免可预测的扫描周期
    std::uniform_int_distribution<long> jitter_dist(0, CheatConfigManager::GetInstance().GetJitterMilliseconds());
    std::this_thread::sleep_for(std::chrono::milliseconds(jitter_dist(m_rng)));
}

void CheatMonitorImpl::SubmitTargetedScanRequest(const std::string &requestId, const std::string &sensorName)
{
    if (requestId.empty() || sensorName.empty())
        return;

    bool added = false;
    {
        std::lock_guard<std::mutex> lock(m_targetedScanMutex);
        if (m_consumedTargetedScanIds.count(requestId) > 0)
        {
            return;
        }
        bool alreadyQueued =
                std::any_of(m_targetedScanQueue.begin(), m_targetedScanQueue.end(),
                            [&](const TargetedScanRequest &queued) { return queued.requestId == requestId; });
        if (alreadyQueued)
        {
            return;
        }

        m_targetedScanQueue.push_back(TargetedScanRequest{requestId, sensorName});
        added = true;
    }

    if (added)
    {
        WakeMonitor();
    }
}

bool CheatMonitorImpl::TryDequeueTargetedScan(TargetedScanRequest &outRequest)
{
    std::lock_guard<std::mutex> lock(m_targetedScanMutex);
    if (m_targetedScanQueue.empty())
        return false;
    outRequest = m_targetedScanQueue.front();
    m_targetedScanQueue.pop_front();
    return true;
}

void CheatMonitorImpl::ProcessPendingTargetedScans()
{
    if (!m_isSessionActive.load())
        return;
    TargetedScanRequest request;
    while (TryDequeueTargetedScan(request))
    {
        RunTargetedSensorScan(request);
    }
}

void CheatMonitorImpl::RunTargetedSensorScan(const TargetedScanRequest &request)
{
    SensorExecutionResult result = SensorExecutionResult::FAILURE;
    anti_cheat::SensorFailureReason failureReason = anti_cheat::UNKNOWN_FAILURE;
    int durationMs = 0;
    std::string notes;

    ISensor *targetSensor = nullptr;
    auto it = m_sensorRegistry.find(request.sensorName);
    if (it != m_sensorRegistry.end())
    {
        targetSensor = it->second;
    }

    size_t evidence_begin = m_evidences.size();

    if (!targetSensor)
    {
        notes = "Sensor not found";
        UploadTargetedSensorReport(request.requestId, request.sensorName, result, failureReason, durationMs, notes, {});
    }
    else if (!m_isSessionActive.load())
    {
        notes = "Session inactive";
        UploadTargetedSensorReport(request.requestId, request.sensorName, result, failureReason, durationMs, notes, {});
    }
    else
    {
        bool isHeavy = targetSensor->GetWeight() != SensorWeight::LIGHT;
        ScanContext context(this, true /*isTargetedScan*/);
        context.RefreshModuleCache();
        if (isHeavy) context.RefreshMemoryCache();

        result = ExecuteAndMonitorSensor(targetSensor, targetSensor->GetName(), isHeavy, context, &failureReason, &durationMs);

        // Collect evidences added during this targeted scan
        std::vector<anti_cheat::Evidence> evidences;
        {
            std::lock_guard<std::mutex> lock(m_sessionMutex);
            for (size_t i = evidence_begin; i < m_evidences.size(); ++i)
            {
                evidences.push_back(m_evidences[i]);
            }
        }

        UploadTargetedSensorReport(request.requestId, request.sensorName, result, failureReason, durationMs, notes, evidences);
    }
}

// ========== 快照数据采集实现 ==========

std::vector<anti_cheat::ThreadSnapshot> CheatMonitorImpl::CollectThreadSnapshots()
{
    std::vector<anti_cheat::ThreadSnapshot> snapshots;
    DWORD currentPid = GetCurrentProcessId();

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        return snapshots;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(te);

    if (Thread32First(hSnapshot, &te))
    {
        do
        {
            if (te.th32OwnerProcessID != currentPid)
            {
                continue;
            }

            anti_cheat::ThreadSnapshot snapshot;
            snapshot.set_thread_id(te.th32ThreadID);

            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (hThread)
            {
                PVOID startAddress = nullptr;
                if (SystemUtils::g_pNtQueryInformationThread)
                {
                    SystemUtils::g_pNtQueryInformationThread(hThread, (THREADINFOCLASS)9, &startAddress,
                                                             sizeof(startAddress), nullptr);
                }

                if (startAddress)
                {
                    snapshot.set_start_address(reinterpret_cast<uint64_t>(startAddress));

                    FILETIME creationTime, exitTime, kernelTime, userTime;
                    if (GetThreadTimes(hThread, &creationTime, &exitTime, &kernelTime, &userTime))
                    {
                        ULARGE_INTEGER uli;
                        uli.LowPart = creationTime.dwLowDateTime;
                        uli.HighPart = creationTime.dwHighDateTime;
                        snapshot.set_creation_time(uli.QuadPart);
                    }

                    MEMORY_BASIC_INFORMATION mbi = {0};
                    if (VirtualQuery(startAddress, &mbi, sizeof(mbi)))
                    {
                        snapshot.set_memory_base_address(reinterpret_cast<uint64_t>(mbi.BaseAddress));
                        snapshot.set_memory_region_size(mbi.RegionSize);
                        snapshot.set_memory_protect(mbi.Protect);
                        snapshot.set_memory_type(mbi.Type);
                    }

                    HMODULE hModule = nullptr;
                    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                                   GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                           (LPCWSTR)startAddress, &hModule) &&
                        hModule)
                    {
                        wchar_t modulePath[MAX_PATH];
                        if (GetModuleFileNameW(hModule, modulePath, MAX_PATH) > 0)
                        {
                            snapshot.set_associated_module_path(Utils::WideToString(modulePath));
                            snapshot.set_module_base_address(reinterpret_cast<uint64_t>(hModule));
                            snapshot.set_relative_offset(snapshot.start_address() - snapshot.module_base_address());
                        }
                    }
                }

                CloseHandle(hThread);
            }

            snapshots.push_back(snapshot);

        } while (Thread32Next(hSnapshot, &te));
    }

    CloseHandle(hSnapshot);
    return snapshots;
}

// 辅助函数：安全读取PE时间戳（使用SEH保护，不能有C++对象）
static DWORD SafeReadPETimestamp(HMODULE hModule)
{
    DWORD timestamp = 0;
    __try
    {
        const BYTE *baseAddress = reinterpret_cast<const BYTE *>(hModule);
        const auto *pDosHeader = reinterpret_cast<const IMAGE_DOS_HEADER *>(baseAddress);
        if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
        {
            const auto *pNtHeaders =
                    reinterpret_cast<const IMAGE_NT_HEADERS *>(baseAddress + pDosHeader->e_lfanew);
            if (pNtHeaders->Signature == IMAGE_NT_SIGNATURE)
            {
                timestamp = pNtHeaders->FileHeader.TimeDateStamp;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
    return timestamp;
}

std::vector<anti_cheat::ModuleSnapshot> CheatMonitorImpl::CollectModuleSnapshots()
{
    std::vector<anti_cheat::ModuleSnapshot> snapshots;

    std::vector<HMODULE> hMods(1024);
    DWORD cbNeeded = 0;

    if (!EnumProcessModules(GetCurrentProcess(), hMods.data(), hMods.size() * sizeof(HMODULE), &cbNeeded))
    {
        return snapshots;
    }

    size_t moduleCount = cbNeeded / sizeof(HMODULE);

    for (size_t i = 0; i < moduleCount; i++)
    {
        anti_cheat::ModuleSnapshot snapshot;

        wchar_t modulePath[MAX_PATH];
        if (GetModuleFileNameW(hMods[i], modulePath, MAX_PATH) > 0)
        {
            snapshot.set_module_path(Utils::WideToString(modulePath));
            snapshot.set_base_address(reinterpret_cast<uint64_t>(hMods[i]));

            MODULEINFO modInfo;
            if (GetModuleInformation(GetCurrentProcess(), hMods[i], &modInfo, sizeof(modInfo)))
            {
                snapshot.set_module_size(modInfo.SizeOfImage);
            }

            // 读取PE时间戳
            DWORD peTimestamp = SafeReadPETimestamp(hMods[i]);
            if (peTimestamp != 0)
            {
                snapshot.set_timestamp(peTimestamp);
            }

            Utils::SignatureStatus sigStatus = Utils::VerifyFileSignature(modulePath, m_windowsVersion);
            snapshot.set_has_signature(sigStatus == Utils::SignatureStatus::TRUSTED);

            if (snapshot.has_signature())
            {
                std::string thumbprint = GetCertificateThumbprint(modulePath);
                snapshot.set_cert_thumbprint(thumbprint);
            }

            PVOID codeBase = nullptr;
            DWORD codeSize = 0;
            if (SystemUtils::GetModuleCodeSectionInfo(hMods[i], codeBase, codeSize))
            {
                std::string hash = CalculateSHA256String(static_cast<BYTE *>(codeBase), codeSize);
                snapshot.set_code_section_hash(hash);
            }

            snapshots.push_back(snapshot);
        }
    }

    return snapshots;
}

std::string CheatMonitorImpl::GetCertificateThumbprint(const std::wstring &filePath)
{
    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    std::string thumbprint;

    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, filePath.c_str(), CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0, NULL, NULL, NULL, &hStore, &hMsg, NULL))
    {
        return "";
    }

    DWORD dwSignerInfo = 0;
    CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSignerInfo);
    std::vector<BYTE> signerInfo(dwSignerInfo);
    CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, signerInfo.data(), &dwSignerInfo);

    CMSG_SIGNER_INFO *pSignerInfo = (CMSG_SIGNER_INFO *)signerInfo.data();
    CERT_INFO certInfo = {0};
    certInfo.Issuer = pSignerInfo->Issuer;
    certInfo.SerialNumber = pSignerInfo->SerialNumber;

    pCertContext = CertFindCertificateInStore(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0,
                                              CERT_FIND_SUBJECT_CERT, &certInfo, NULL);

    if (pCertContext)
    {
        // 首先尝试获取 SHA-256 指纹
        BYTE hash[32];
        DWORD hashLen = sizeof(hash);
        bool useSHA256 = CertGetCertificateContextProperty(pCertContext, CERT_SHA256_HASH_PROP_ID, hash, &hashLen);

        if (!useSHA256)
        {
            // 如果 SHA-256 不支持，降级使用 SHA-1 指纹（Windows XP 兼容）
            LOG_DEBUG(AntiCheatLogger::LogCategory::SYSTEM,
                     "GetCertificateThumbprint: SHA-256 证书属性不支持，降级使用 SHA-1");

            hashLen = 20;  // SHA-1 哈希长度
            if (!CertGetCertificateContextProperty(pCertContext, CERT_SHA1_HASH_PROP_ID, hash, &hashLen))
            {
                LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM,
                             "GetCertificateThumbprint: 获取 SHA-1 证书指纹也失败，错误码: 0x%08X", GetLastError());
                CertFreeCertificateContext(pCertContext);
                if (hStore) CertCloseStore(hStore, 0);
                if (hMsg) CryptMsgClose(hMsg);
                return "";
            }
        }

        std::ostringstream oss;

        // 添加哈希类型前缀
        if (useSHA256)
        {
            oss << "sha256:";
        }
        else
        {
            oss << "sha1:";
        }

        for (DWORD i = 0; i < hashLen; i++)
        {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        thumbprint = oss.str();
        CertFreeCertificateContext(pCertContext);
    }

    if (hStore)
        CertCloseStore(hStore, 0);
    if (hMsg)
        CryptMsgClose(hMsg);
    return thumbprint;
}

std::string CheatMonitorImpl::CalculateSHA256String(const BYTE *data, size_t size)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    // 首先尝试获取支持 AES 的加密提供程序（Windows Vista+）
    bool useAES = CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);

    // 如果失败，回退到传统的 RSA 提供程序（Windows XP 兼容）
    if (!useAES)
    {
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        {
            LOG_DEBUG(AntiCheatLogger::LogCategory::SYSTEM,
                     "CalculateSHA256String: 无法获取加密上下文，可能不支持加密API");
            return "";
        }
    }

    // 尝试创建 SHA-256 哈希
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        DWORD error = GetLastError();

        // 如果 SHA-256 不支持，尝试使用 SHA-1 作为降级方案
        if (error == NTE_BAD_ALGID || error == ERROR_INVALID_PARAMETER)
        {
            LOG_DEBUG(AntiCheatLogger::LogCategory::SYSTEM,
                     "CalculateSHA256String: SHA-256 不支持，降级使用 SHA-1");

            if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash))
            {
                LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM,
                             "CalculateSHA256String: SHA-1 也不支持，错误码: 0x%08X", GetLastError());
                CryptReleaseContext(hProv, 0);
                return "";
            }
        }
        else
        {
            LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM,
                         "CalculateSHA256String: 创建哈希失败，错误码: 0x%08X", error);
            CryptReleaseContext(hProv, 0);
            return "";
        }
    }

    if (!CryptHashData(hHash, data, size, 0))
    {
        LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM,
                     "CalculateSHA256String: 哈希数据失败，错误码: 0x%08X", GetLastError());
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // 获取哈希值长度
    DWORD hashLen = 0;
    DWORD paramLen = sizeof(hashLen);
    if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&hashLen, &paramLen, 0))
    {
        LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM,
                     "CalculateSHA256String: 获取哈希长度失败，错误码: 0x%08X", GetLastError());
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // 分配适当大小的缓冲区（SHA-256=32字节，SHA-1=20字节）
    std::vector<BYTE> hash(hashLen);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashLen, 0))
    {
        LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM,
                     "CalculateSHA256String: 获取哈希值失败，错误码: 0x%08X", GetLastError());
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // 构建十六进制字符串
    std::ostringstream oss;

    // 如果使用的是 SHA-1，添加前缀标识
    if (hashLen == 20)
    {
        oss << "sha1:";
    }
    else if (hashLen == 32)
    {
        oss << "sha256:";
    }

    for (DWORD i = 0; i < hashLen; i++)
    {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return oss.str();
}
