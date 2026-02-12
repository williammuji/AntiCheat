#include "CheatMonitor.h"
#include "CheatMonitorImpl.h"
#include "CheatConfigManager.h"
#include "Logger.h"
#include "utils/Utils.h"
#include <atomic>

void CheatMonitorImpl::AddEvidence(anti_cheat::CheatCategory category, const std::string &description)
{
    std::lock_guard<std::mutex> lock(m_sessionMutex);

    if (m_evidenceOverflowed) return;
    if (m_evidences.size() >= (size_t)CheatConfigManager::GetInstance().GetMaxEvidencesPerSession())
    {
        m_evidenceOverflowed = true;
        anti_cheat::Evidence overflow_evidence;
        overflow_evidence.set_client_timestamp_ms(
                std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                        .count());
        overflow_evidence.set_category(anti_cheat::RUNTIME_ERROR);
        overflow_evidence.set_description("Evidence buffer overflow. Further events for this session are suppressed.");
        m_evidences.push_back(overflow_evidence);
        return;
    }

    if (m_uniqueEvidence.find({category, description}) != m_uniqueEvidence.end()) return;

    const auto now = std::chrono::steady_clock::now();
    auto it = m_lastReported.find({m_currentUserId, category});
    if (it != m_lastReported.end())
    {
        auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(now - it->second);
        if (elapsed < std::chrono::minutes(CheatConfigManager::GetInstance().GetReportCooldownMinutes())) return;
    }

    anti_cheat::Evidence evidence;
    evidence.set_client_timestamp_ms(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                    .count());
    evidence.set_category(category);
    evidence.set_description(description);

    m_evidences.push_back(evidence);
    m_uniqueEvidence.insert({category, description});
    m_lastReported[{m_currentUserId, category}] = now;
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
        hardware_report->set_report_timestamp_ms(
                std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
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

    if (fp->disk_serial().empty() && fp->mac_addresses().empty() && fp->computer_name().empty() && fp->cpu_info().empty())
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
    std::vector<anti_cheat::Evidence> evidencesToSend;
    {
        std::lock_guard<std::mutex> lock(m_sessionMutex);
        if (m_evidences.empty()) return;
        evidencesToSend.swap(m_evidences);
        m_uniqueEvidence.clear();
    }

    anti_cheat::Report report;
    report.set_type(anti_cheat::REPORT_EVIDENCE);
    auto evidence_report = report.mutable_evidence();
    evidence_report->set_report_id(Utils::GenerateUuid());
    evidence_report->set_report_timestamp_ms(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                    .count());

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

void CheatMonitorImpl::UploadSnapshotReport()
{
    if (!CheatConfigManager::GetInstance().IsSnapshotUploadEnabled()) return;

    LOG_INFO(AntiCheatLogger::LogCategory::SYSTEM, "开始采集快照数据...");
    auto threads = CollectThreadSnapshots();
    auto modules = CollectModuleSnapshots();

    LOG_INFO_F(AntiCheatLogger::LogCategory::SYSTEM, "采集完成: %zu个线程, %zu个模块", threads.size(), modules.size());

    anti_cheat::Report report;
    report.set_type(anti_cheat::REPORT_SNAPSHOT);
    auto snapshot_report = report.mutable_snapshot();
    snapshot_report->set_report_id(Utils::GenerateUuid());
    snapshot_report->set_report_timestamp_ms(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                    .count());
    uint32_t currentUserId = 0;
    std::string currentUserName;
    {
        std::lock_guard<std::mutex> lock(m_sessionMutex);
        currentUserId = m_currentUserId;
        currentUserName = m_currentUserName;
    }
    snapshot_report->set_user_id(currentUserId);
    snapshot_report->set_user_name(currentUserName);
    for (const auto &thread : threads) *snapshot_report->add_threads() = thread;
    for (const auto &module : modules) *snapshot_report->add_modules() = module;
    snapshot_report->set_total_thread_count(static_cast<uint32_t>(threads.size()));
    snapshot_report->set_total_module_count(static_cast<uint32_t>(modules.size()));
    SendReport(report);
    LOG_INFO(AntiCheatLogger::LogCategory::SYSTEM, "快照数据上报完成");
}

void CheatMonitorImpl::UploadSensorExecutionStatsReport()
{
    anti_cheat::TelemetryMetrics metrics;
    {
        std::lock_guard<std::mutex> lock(m_sensorStatsMutex);
        for (const auto &kv : m_sensorExecutionStats)
        {
            const std::string &name = kv.first;
            const auto &stats = kv.second;
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
            if (!nonEmpty) continue;
            (*metrics.mutable_sensor_execution_stats())[name] = stats;
        }
        m_sensorExecutionStats.clear();
    }
    UploadTelemetryMetricsReport(metrics);
}

void CheatMonitorImpl::RecordSensorExecutionStats(const char *name, int duration_ms, SensorExecutionResult result,
                                                  anti_cheat::SensorFailureReason failureReason)
{
    std::lock_guard<std::mutex> lock(m_sensorStatsMutex);
    auto &stats = m_sensorExecutionStats[name];
    switch (result)
    {
        case SensorExecutionResult::SUCCESS:
            stats.set_success_count(stats.success_count() + 1);
            if (duration_ms > 0)
            {
                stats.set_total_success_time_ms(stats.total_success_time_ms() + duration_ms);
                if (stats.total_success_time_ms() > 0 && stats.success_count() > 0)
                    stats.set_avg_success_time_ms(stats.total_success_time_ms() / stats.success_count());
                if (stats.max_success_time_ms() == 0 || duration_ms > stats.max_success_time_ms())
                    stats.set_max_success_time_ms(duration_ms);
                if (stats.min_success_time_ms() == 0 || duration_ms < stats.min_success_time_ms())
                    stats.set_min_success_time_ms(duration_ms);
            }
            break;
        case SensorExecutionResult::FAILURE:
            stats.set_failure_count(stats.failure_count() + 1);
            if (duration_ms > 0)
            {
                stats.set_total_failure_time_ms(stats.total_failure_time_ms() + duration_ms);
                if (stats.total_failure_time_ms() > 0 && stats.failure_count() > 0)
                    stats.set_avg_failure_time_ms(stats.total_failure_time_ms() / stats.failure_count());
                if (stats.max_failure_time_ms() == 0 || duration_ms > stats.max_failure_time_ms())
                    stats.set_max_failure_time_ms(duration_ms);
                if (stats.min_failure_time_ms() == 0 || duration_ms < stats.min_failure_time_ms())
                    stats.set_min_failure_time_ms(duration_ms);
            }
            break;
        case SensorExecutionResult::TIMEOUT:
            stats.set_timeout_count(stats.timeout_count() + 1);
            break;
    }

    if (result == SensorExecutionResult::FAILURE && failureReason != anti_cheat::UNKNOWN_FAILURE)
    {
        (*stats.mutable_failure_reasons())[static_cast<int32_t>(failureReason)]++;
    }
}

void CheatMonitorImpl::RecordSensorWorkloadCounters(const std::string &name, uint64_t snapshot_size, uint64_t attempts,
                                                     uint64_t hits)
{
    std::lock_guard<std::mutex> lock(m_sensorStatsMutex);
    auto &stats = m_sensorExecutionStats[name];
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
            content_size = report.has_hardware() ? 1 : 0;
            break;
        case anti_cheat::REPORT_EVIDENCE:
            report_type_name = "Evidence";
            content_size = report.has_evidence() ? report.evidence().evidences_size() : 0;
            break;
        case anti_cheat::REPORT_TELEMETRY:
            report_type_name = "Telemetry";
            content_size = report.has_telemetry() ? 1 : 0;
            break;
        case anti_cheat::REPORT_SNAPSHOT:
            report_type_name = "Snapshot";
            content_size = report.has_snapshot() ? report.snapshot().threads_size() + report.snapshot().modules_size() : 0;
            break;
        case anti_cheat::REPORT_SERVER_LOG:
            report_type_name = "ServerLog";
            content_size = report.has_server_log() ? 1 : 0;
            break;
        default:
            break;
    }

    LOG_INFO_F(AntiCheatLogger::LogCategory::SYSTEM, "Uploading %s report... Size: %zu bytes, content items: %zu",
               report_type_name, serialized_report.length(), content_size);
    // TODO: HttpSend(server_url, serialized_report);
}

void CheatMonitorImpl::SendServerLog(const std::string &log_level, const std::string &log_category,
                                     const std::string &log_message)
{
    anti_cheat::Report report;
    report.set_type(anti_cheat::REPORT_SERVER_LOG);
    static std::atomic<uint64_t> log_counter{0};
    std::string report_id = "LOG_" + std::to_string(++log_counter);
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

    anti_cheat::ServerLogReport *server_log = report.mutable_server_log();
    server_log->set_report_id(report_id);
    server_log->set_report_timestamp_ms(ms);
    server_log->set_log_level(log_level);
    server_log->set_log_category(log_category);
    server_log->set_log_message(log_message);
    SendReport(report);
}
