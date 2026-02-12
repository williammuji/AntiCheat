#include "CheatMonitor.h"
#include "CheatMonitorEngine.h"
#include "ISensor.h"
#include "CheatConfigManager.h"
#include "Logger.h"

void CheatMonitorEngine::WakeMonitor()
{
    m_cv.notify_one();
}

void CheatMonitorEngine::MonitorLoop()
{
    InitializeSystem();

    auto next_light_scan = std::chrono::steady_clock::now();
    auto next_heavy_scan = std::chrono::steady_clock::now();
    auto next_report_upload = std::chrono::steady_clock::now();
    auto next_sensor_stats_upload = std::chrono::steady_clock::now();
    auto next_snapshot_upload = std::chrono::steady_clock::now();

    while (m_isSystemActive.load())
    {
        const auto now_before_wait = std::chrono::steady_clock::now();
        auto earliest = now_before_wait + std::chrono::seconds(1);

        if (m_isSessionActive.load() && m_hasServerConfig.load())
        {
            earliest = std::min(
                    {next_light_scan, next_heavy_scan, next_report_upload, next_sensor_stats_upload, next_snapshot_upload});
        }

        {
            std::unique_lock<std::mutex> lk(m_cvMutex);
            m_cv.wait_until(lk, earliest, [&]() { return !m_isSystemActive.load(); });
        }

        if (!m_isSystemActive.load()) break;

        if (!m_isSessionActive.load() || !m_hasServerConfig.load()) continue;

        ProcessPendingTargetedScans();
        const auto now = std::chrono::steady_clock::now();

        if (now >= next_light_scan)
        {
            ExecuteLightweightSensors();
            next_light_scan = now + GetLightScanInterval();
        }

        if (now >= next_heavy_scan)
        {
            ExecuteHeavyweightSensors();
            next_heavy_scan = now + GetHeavyScanInterval();
        }

        if (now >= next_report_upload)
        {
            UploadEvidenceReport();
            next_report_upload =
                    now + std::chrono::minutes(CheatConfigManager::GetInstance().GetReportUploadIntervalMinutes());
        }

        if (now >= next_sensor_stats_upload)
        {
            UploadSensorExecutionStatsReport();
            next_sensor_stats_upload =
                    now + std::chrono::minutes(CheatConfigManager::GetInstance().GetSensorStatsUploadIntervalMinutes());
        }

        if (now >= next_snapshot_upload)
        {
            if (CheatConfigManager::GetInstance().IsSnapshotUploadEnabled()) UploadSnapshotReport();
            next_snapshot_upload =
                    now + std::chrono::minutes(CheatConfigManager::GetInstance().GetSnapshotUploadIntervalMinutes());
        }
    }
}

void CheatMonitorEngine::ResetSessionState()
{
    {
        std::lock_guard<std::mutex> lock(m_sessionMutex);
        m_currentUserId = 0;
        m_currentUserName.clear();
        m_uniqueEvidence.clear();
        m_evidences.clear();
        m_lastReported.clear();
        m_evidenceOverflowed = false;
    }
    {
        std::lock_guard<std::mutex> lock(m_sensorStatsMutex);
        m_sensorExecutionStats.clear();
    }
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

const std::chrono::milliseconds CheatMonitorEngine::GetLightScanInterval() const
{
    const auto base_interval = std::chrono::seconds(CheatConfigManager::GetInstance().GetBaseScanInterval());
    const auto jitter = std::chrono::milliseconds(m_rng() % 2000);
    return base_interval + jitter;
}

const std::chrono::milliseconds CheatMonitorEngine::GetHeavyScanInterval() const
{
    const auto base_interval = std::chrono::minutes(CheatConfigManager::GetInstance().GetHeavyScanIntervalMinutes());
    const auto jitter = std::chrono::milliseconds(m_rng() % 60000);
    return base_interval + jitter;
}

void CheatMonitorEngine::ExecuteLightweightSensors()
{
    if (m_lightweightSensors.empty()) return;

    SensorRuntimeContext context(this, false);
    context.RefreshModuleCache();

    for (const auto &sensor : m_lightweightSensors)
    {
        ExecuteAndMonitorSensor(sensor.get(), sensor->GetName(), false, context);
    }
}

void CheatMonitorEngine::ExecuteHeavyweightSensors()
{
    if (m_heavyweightSensors.empty()) return;

    SensorRuntimeContext context(this, false);
    context.RefreshModuleCache();
    context.RefreshMemoryCache();

    long budget_ms = CheatConfigManager::GetInstance().GetHeavyScanBudgetMs();
    auto total_start = std::chrono::steady_clock::now();

    for (const auto &sensor : m_heavyweightSensors)
    {
        auto now = std::chrono::steady_clock::now();
        auto elapsed_total = std::chrono::duration_cast<std::chrono::milliseconds>(now - total_start).count();
        if (budget_ms > 0 && elapsed_total >= budget_ms)
        {
            LOG_WARNING_F(AntiCheatLogger::LogCategory::PERFORMANCE,
                          "Heavy scan budget exceeded (%ld ms > %ld ms). Skipping remaining sensors.", elapsed_total,
                          budget_ms);
            break;
        }
        ExecuteAndMonitorSensor(sensor.get(), sensor->GetName(), true, context);
    }
}

SensorExecutionResult CheatMonitorEngine::ExecuteAndMonitorSensor(ISensor *sensor, const char *name, bool isHeavyweight,
                                                                  SensorRuntimeContext &context,
                                                                anti_cheat::SensorFailureReason *outFailure,
                                                                int *outDurationMs)
{
    (void)isHeavyweight;
    const auto startTime = std::chrono::steady_clock::now();
    SensorExecutionResult result = SensorExecutionResult::FAILURE;
    anti_cheat::SensorFailureReason failureReason = anti_cheat::UNKNOWN_FAILURE;

    try
    {
        result = sensor->Execute(context);
        const auto end = std::chrono::steady_clock::now();
        const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - startTime).count();
        if (result == SensorExecutionResult::FAILURE) failureReason = sensor->GetLastFailureReason();

        RecordSensorExecutionStats(name, (int)elapsed_ms, result, failureReason);
        if (outFailure) *outFailure = failureReason;
        if (outDurationMs) *outDurationMs = (int)elapsed_ms;
        return result;
    }
    catch (const std::exception &e)
    {
        const auto end = std::chrono::steady_clock::now();
        const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - startTime).count();
        LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR, "传感器异常: %s - %s", name, e.what());
        RecordSensorExecutionStats(name, (int)elapsed_ms, SensorExecutionResult::FAILURE,
                                   anti_cheat::CPP_EXCEPTION_FAILURE);
        if (outFailure) *outFailure = anti_cheat::CPP_EXCEPTION_FAILURE;
        if (outDurationMs) *outDurationMs = (int)elapsed_ms;
        return SensorExecutionResult::FAILURE;
    }
    catch (...)
    {
        const auto end = std::chrono::steady_clock::now();
        const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - startTime).count();
        LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR, "传感器未知异常: %s", name);
        RecordSensorExecutionStats(name, (int)elapsed_ms, SensorExecutionResult::FAILURE,
                                   anti_cheat::UNKNOWN_EXCEPTION_FAILURE);
        if (outFailure) *outFailure = anti_cheat::UNKNOWN_EXCEPTION_FAILURE;
        if (outDurationMs) *outDurationMs = (int)elapsed_ms;
        return SensorExecutionResult::FAILURE;
    }
}

void CheatMonitorEngine::AddRandomJitter()
{
    std::uniform_int_distribution<long> jitter_dist(0, CheatConfigManager::GetInstance().GetJitterMilliseconds());
    std::this_thread::sleep_for(std::chrono::milliseconds(jitter_dist(m_rng)));
}

void CheatMonitorEngine::SubmitTargetedScanRequest(const std::string &requestId, const std::string &sensorName)
{
    if (requestId.empty() || sensorName.empty()) return;

    bool added = false;
    {
        std::lock_guard<std::mutex> lock(m_targetedScanMutex);
        if (m_consumedTargetedScanIds.count(requestId) > 0) return;
        bool alreadyQueued = std::any_of(m_targetedScanQueue.begin(), m_targetedScanQueue.end(),
                                         [&](const TargetedScanRequest &queued) { return queued.requestId == requestId; });
        if (alreadyQueued) return;
        m_targetedScanQueue.push_back(TargetedScanRequest{requestId, sensorName});
        added = true;
    }
    if (added) WakeMonitor();
}

bool CheatMonitorEngine::TryDequeueTargetedScan(TargetedScanRequest &outRequest)
{
    std::lock_guard<std::mutex> lock(m_targetedScanMutex);
    if (m_targetedScanQueue.empty()) return false;
    outRequest = m_targetedScanQueue.front();
    m_targetedScanQueue.pop_front();
    return true;
}

void CheatMonitorEngine::ProcessPendingTargetedScans()
{
    if (!m_isSessionActive.load()) return;
    TargetedScanRequest request;
    while (TryDequeueTargetedScan(request))
    {
        RunTargetedSensorScan(request);
    }
}

void CheatMonitorEngine::RunTargetedSensorScan(const TargetedScanRequest &request)
{
    SensorExecutionResult result = SensorExecutionResult::FAILURE;
    anti_cheat::SensorFailureReason failureReason = anti_cheat::UNKNOWN_FAILURE;
    int durationMs = 0;
    std::string notes;

    ISensor *targetSensor = nullptr;
    auto it = m_sensorRegistry.find(request.sensorName);
    if (it != m_sensorRegistry.end()) targetSensor = it->second;

    size_t evidence_begin = 0;
    {
        std::lock_guard<std::mutex> lock(m_sessionMutex);
        evidence_begin = m_evidences.size();
    }

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
        SensorRuntimeContext context(this, true);
        context.RefreshModuleCache();
        if (isHeavy) context.RefreshMemoryCache();

        result = ExecuteAndMonitorSensor(targetSensor, targetSensor->GetName(), isHeavy, context, &failureReason, &durationMs);

        std::vector<anti_cheat::Evidence> evidences;
        {
            std::lock_guard<std::mutex> lock(m_sessionMutex);
            for (size_t i = evidence_begin; i < m_evidences.size(); ++i)
            {
                evidences.push_back(m_evidences[i]);
            }
        }
        UploadTargetedSensorReport(request.requestId, request.sensorName, result, failureReason, durationMs, notes,
                                   evidences);
    }

    {
        std::lock_guard<std::mutex> lock(m_targetedScanMutex);
        m_consumedTargetedScanIds.insert(request.requestId);
    }
}
