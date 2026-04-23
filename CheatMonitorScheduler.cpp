#include "CheatMonitor.h"
#include "CheatMonitorEngine.h"
#include "ISensor.h"
#include "CheatConfigManager.h"
#include "Logger.h"

namespace
{
int ClampToPositiveInterval(int value, int fallback)
{
    if (value <= 0) return fallback;
    return value;
}

uint32_t ClampToRange(uint32_t value, uint32_t minValue, uint32_t maxValue)
{
    return std::max(minValue, std::min(value, maxValue));
}

bool HasQueuedScanRequest(const std::deque<CheatMonitorEngine::TargetedScanRequest> &queue, const std::string &requestId)
{
    return std::any_of(queue.begin(), queue.end(),
                       [&](const CheatMonitorEngine::TargetedScanRequest &queued) { return queued.requestId == requestId; });
}
}  // namespace

void CheatMonitorEngine::WakeControlThread()
{
    m_controlWakeRequested.store(true, std::memory_order_relaxed);
    m_controlCv.notify_one();
}

void CheatMonitorEngine::WakeScanThread()
{
    m_scanWakeRequested.store(true, std::memory_order_relaxed);
    m_scanCv.notify_one();
}

void CheatMonitorEngine::WakeMonitor()
{
    WakeControlThread();
    WakeScanThread();
}

bool CheatMonitorEngine::JoinThreadWithTimeout(std::thread &thread, uint32_t timeoutMs, const char *threadName,
                                               bool detachOnTimeout)
{
    if (!thread.joinable()) return true;

#ifdef _WIN32
    HANDLE nativeHandle = static_cast<HANDLE>(thread.native_handle());
    const DWORD waitResult = WaitForSingleObject(nativeHandle, timeoutMs);
    if (waitResult == WAIT_OBJECT_0)
    {
        thread.join();
        return true;
    }

    if (waitResult == WAIT_TIMEOUT)
    {
        if (detachOnTimeout)
        {
            LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM,
                          "%s did not exit within %u ms, detaching stale thread handle", threadName, timeoutMs);
            thread.detach();
            return false;
        }
        thread.join();
        return true;
    }

    LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM, "WaitForSingleObject failed on %s (code=%lu), detaching thread",
                  threadName, GetLastError());
    thread.detach();
    return false;
#else
    (void)timeoutMs;
    (void)threadName;
    (void)detachOnTimeout;
    thread.join();
    return true;
#endif
}

void CheatMonitorEngine::StartControlThread()
{
    std::lock_guard<std::mutex> lock(m_threadLifecycleMutex);
    if (!m_isSystemActive.load() || m_controlThread.joinable()) return;

    const uint64_t generation = m_controlGeneration.fetch_add(1, std::memory_order_relaxed) + 1;
    m_controlThreadShouldRun.store(true, std::memory_order_relaxed);
    m_controlWakeRequested.store(false, std::memory_order_relaxed);
    m_controlThread = std::thread(&CheatMonitorEngine::ControlLoop, this, generation);
}

void CheatMonitorEngine::StopControlThread(bool allowDetachOnTimeout)
{
    std::thread threadToStop;
    {
        std::lock_guard<std::mutex> lock(m_threadLifecycleMutex);
        m_controlThreadShouldRun.store(false, std::memory_order_relaxed);
        m_controlWakeRequested.store(true, std::memory_order_relaxed);
        m_controlCv.notify_all();
        if (m_controlThread.joinable()) threadToStop = std::move(m_controlThread);
    }

    if (threadToStop.joinable())
    {
        JoinThreadWithTimeout(threadToStop, kControlThreadJoinTimeoutMs, "ControlThread", allowDetachOnTimeout);
    }
}

void CheatMonitorEngine::StartScanThread()
{
    std::lock_guard<std::mutex> lock(m_threadLifecycleMutex);
    if (!m_isSystemActive.load() || m_scanThread.joinable()) return;

    const uint64_t generation = m_scanGeneration.fetch_add(1, std::memory_order_relaxed) + 1;
    m_scanThreadShouldRun.store(true, std::memory_order_relaxed);
    m_scanWakeRequested.store(false, std::memory_order_relaxed);
    m_scanThread = std::thread(&CheatMonitorEngine::ScanLoop, this, generation);
}

void CheatMonitorEngine::StopScanThread(bool allowDetachOnTimeout)
{
    std::thread threadToStop;
    {
        std::lock_guard<std::mutex> lock(m_threadLifecycleMutex);
        m_scanThreadShouldRun.store(false, std::memory_order_relaxed);
        m_scanWakeRequested.store(true, std::memory_order_relaxed);
        m_scanCv.notify_all();
        if (m_scanThread.joinable()) threadToStop = std::move(m_scanThread);
    }

    if (threadToStop.joinable())
    {
        JoinThreadWithTimeout(threadToStop, kScanThreadJoinTimeoutMs, "ScanThread", allowDetachOnTimeout);
    }
}

uint32_t CheatMonitorEngine::GetScanWatchdogStallSeconds() const
{
    return ClampToRange(static_cast<uint32_t>(CheatConfigManager::GetInstance().GetScanWatchdogStallSeconds()), 3, 30);
}

uint32_t CheatMonitorEngine::GetControlWatchdogStallSeconds() const
{
    return ClampToRange(static_cast<uint32_t>(CheatConfigManager::GetInstance().GetControlWatchdogStallSeconds()), 3, 30);
}

bool CheatMonitorEngine::ConsumeThreadRebuildBudget(std::deque<std::chrono::steady_clock::time_point> &history,
                                                    const char *threadName)
{
    if (!threadName) return false;

    const uint32_t maxCount =
            ClampToRange(static_cast<uint32_t>(CheatConfigManager::GetInstance().GetThreadRebuildLimitCount()),
                         1, 30);
    const uint32_t windowSeconds =
            ClampToRange(static_cast<uint32_t>(CheatConfigManager::GetInstance().GetThreadRebuildLimitWindowSeconds()),
                         5, 600);

    const auto now = std::chrono::steady_clock::now();
    const auto cutoff = now - std::chrono::seconds(windowSeconds);

    std::lock_guard<std::mutex> lock(m_watchdogRebuildMutex);
    while (!history.empty() && history.front() < cutoff)
    {
        history.pop_front();
    }

    if (history.size() >= maxCount)
    {
        static std::unordered_map<std::string, std::chrono::steady_clock::time_point> s_lastLimitLogs;
        const auto it = s_lastLimitLogs.find(threadName);
        if (it == s_lastLimitLogs.end() || now - it->second > std::chrono::seconds(5))
        {
            s_lastLimitLogs[threadName] = now;
            std::string detail = std::string(threadName) + " rebuild suppressed by rate limiter (limit=" +
                                 std::to_string(maxCount) + ", window=" + std::to_string(windowSeconds) + "s)";
            LOG_WARNING(AntiCheatLogger::LogCategory::SYSTEM, detail);
            SendServerLog("WARNING", "SYSTEM", detail);
            AddEvidence(anti_cheat::RUNTIME_ERROR, detail);
        }
        return false;
    }

    history.push_back(now);
    return true;
}

void CheatMonitorEngine::RebuildScanThread(const char *reason)
{
    if (!m_isSystemActive.load()) return;
    if (!ConsumeThreadRebuildBudget(m_scanRebuildHistory, "ScanThread")) return;

    std::string reasonText = reason ? reason : "unknown";
    std::string detail = "Scan thread watchdog triggered DEGRADED mode, rebuilding scan thread. reason=" + reasonText;
    LOG_ERROR(AntiCheatLogger::LogCategory::SYSTEM, detail);
    SendServerLog("ERROR", "SYSTEM", detail);
    AddEvidence(anti_cheat::RUNTIME_ERROR, detail);
    m_scanThreadDegraded.store(true, std::memory_order_relaxed);

    std::thread staleThread;
    {
        std::lock_guard<std::mutex> lock(m_threadLifecycleMutex);
        m_scanThreadShouldRun.store(false, std::memory_order_relaxed);
        m_scanWakeRequested.store(true, std::memory_order_relaxed);
        m_scanCv.notify_all();
        if (m_scanThread.joinable()) staleThread = std::move(m_scanThread);

        const uint64_t newGeneration = m_scanGeneration.fetch_add(1, std::memory_order_relaxed) + 1;
        m_scanThreadShouldRun.store(true, std::memory_order_relaxed);
        m_scanWakeRequested.store(false, std::memory_order_relaxed);
        m_scanThread = std::thread(&CheatMonitorEngine::ScanLoop, this, newGeneration);
    }

    if (staleThread.joinable())
    {
        JoinThreadWithTimeout(staleThread, kScanThreadJoinTimeoutMs, "ScanThread(stale)", true);
    }
}

void CheatMonitorEngine::RebuildControlThread(const char *reason)
{
    if (!m_isSystemActive.load()) return;
    if (!ConsumeThreadRebuildBudget(m_controlRebuildHistory, "ControlThread")) return;

    std::string reasonText = reason ? reason : "unknown";
    std::string detail = "Control thread watchdog triggered DEGRADED mode, rebuilding control thread. reason=" + reasonText;
    LOG_ERROR(AntiCheatLogger::LogCategory::SYSTEM, detail);
    SendServerLog("ERROR", "SYSTEM", detail);
    AddEvidence(anti_cheat::RUNTIME_ERROR, detail);
    m_controlThreadDegraded.store(true, std::memory_order_relaxed);

    std::thread staleThread;
    {
        std::lock_guard<std::mutex> lock(m_threadLifecycleMutex);
        m_controlThreadShouldRun.store(false, std::memory_order_relaxed);
        m_controlWakeRequested.store(true, std::memory_order_relaxed);
        m_controlCv.notify_all();
        if (m_controlThread.joinable()) staleThread = std::move(m_controlThread);

        const uint64_t newGeneration = m_controlGeneration.fetch_add(1, std::memory_order_relaxed) + 1;
        m_controlThreadShouldRun.store(true, std::memory_order_relaxed);
        m_controlWakeRequested.store(false, std::memory_order_relaxed);
        m_controlThread = std::thread(&CheatMonitorEngine::ControlLoop, this, newGeneration);
    }

    if (staleThread.joinable())
    {
        JoinThreadWithTimeout(staleThread, kControlThreadJoinTimeoutMs, "ControlThread(stale)", true);
    }
}

void CheatMonitorEngine::EvaluateScanThreadWatchdog(uint64_t &lastProgressCounter, uint32_t &stalledSeconds)
{
    if (!m_isSystemActive.load()) return;

    if (!m_scanThreadAlive.load(std::memory_order_relaxed))
    {
        stalledSeconds = 0;
        RebuildScanThread("scan thread not alive");
        lastProgressCounter = m_scanProgressCounter.load(std::memory_order_relaxed);
        return;
    }

    const uint64_t currentProgress = m_scanProgressCounter.load(std::memory_order_relaxed);
    if (currentProgress != lastProgressCounter)
    {
        lastProgressCounter = currentProgress;
        stalledSeconds = 0;
        if (m_scanThreadDegraded.exchange(false, std::memory_order_relaxed))
        {
            SendServerLog("INFO", "SYSTEM", "Scan thread recovered from DEGRADED mode");
        }
        return;
    }

    stalledSeconds++;
    if (stalledSeconds < GetScanWatchdogStallSeconds()) return;

    stalledSeconds = 0;
    RebuildScanThread("scan progress heartbeat stalled");
    lastProgressCounter = m_scanProgressCounter.load(std::memory_order_relaxed);
}

void CheatMonitorEngine::EvaluateControlThreadWatchdog(uint64_t &lastProgressCounter, uint32_t &stalledSeconds)
{
    if (!m_isSystemActive.load()) return;

    if (!m_controlThreadAlive.load(std::memory_order_relaxed))
    {
        stalledSeconds = 0;
        RebuildControlThread("control thread not alive");
        lastProgressCounter = m_controlProgressCounter.load(std::memory_order_relaxed);
        return;
    }

    const uint64_t currentProgress = m_controlProgressCounter.load(std::memory_order_relaxed);
    if (currentProgress != lastProgressCounter)
    {
        lastProgressCounter = currentProgress;
        stalledSeconds = 0;
        if (m_controlThreadDegraded.exchange(false, std::memory_order_relaxed))
        {
            SendServerLog("INFO", "SYSTEM", "Control thread recovered from DEGRADED mode");
        }
        return;
    }

    stalledSeconds++;
    if (stalledSeconds < GetControlWatchdogStallSeconds()) return;

    stalledSeconds = 0;
    RebuildControlThread("control progress heartbeat stalled");
    lastProgressCounter = m_controlProgressCounter.load(std::memory_order_relaxed);
}

void CheatMonitorEngine::MarkScanThreadProgress(uint64_t generation)
{
    if (generation != m_scanGeneration.load(std::memory_order_relaxed)) return;
    m_scanProgressCounter.fetch_add(1, std::memory_order_relaxed);
}

void CheatMonitorEngine::MarkControlThreadProgress(uint64_t generation)
{
    if (generation != m_controlGeneration.load(std::memory_order_relaxed)) return;
    m_controlProgressCounter.fetch_add(1, std::memory_order_relaxed);
}

uint64_t CheatMonitorEngine::BuildSessionGuardValue(bool active)
{
    std::lock_guard<std::mutex> lock(m_sessionMutex);

    uint64_t userHash = static_cast<uint64_t>(m_currentUserId) * 0x9e3779b185ebca87ull;
    for (char c : m_currentUserName)
    {
        userHash ^= static_cast<unsigned char>(c);
        userHash *= 1099511628211ull;
    }

    const uint64_t activeSalt = active ? 0xA1B2C3D4E5F60718ull : 0x1F2E3D4C5B6A7988ull;
    return m_sessionGuardSecret ^ userHash ^ activeSalt;
}

void CheatMonitorEngine::UpdateSessionGuard(bool active)
{
    m_sessionStateGuard.store(BuildSessionGuardValue(active), std::memory_order_relaxed);
}

bool CheatMonitorEngine::ValidateAndRepairSessionState()
{
    const bool expected = m_expectedSessionActive.load(std::memory_order_relaxed);
    const bool observed = m_isSessionActive.load(std::memory_order_relaxed);
    const uint64_t expectedGuard = BuildSessionGuardValue(expected);
    const uint64_t observedGuard = m_sessionStateGuard.load(std::memory_order_relaxed);

    if (observed == expected && observedGuard == expectedGuard) return true;

    m_isSessionActive.store(expected, std::memory_order_relaxed);
    m_sessionStateGuard.store(expectedGuard, std::memory_order_relaxed);

    const uint64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                                   std::chrono::system_clock::now().time_since_epoch())
                                   .count();
    const uint64_t lastAlert = m_lastSessionGuardAlertMs.load(std::memory_order_relaxed);
    if (lastAlert != 0 && nowMs - lastAlert < 5000) return false;
    m_lastSessionGuardAlertMs.store(nowMs, std::memory_order_relaxed);

    std::string detail = "Session state tamper suspected: observed_active=" + std::to_string(observed ? 1 : 0) +
                         ", expected_active=" + std::to_string(expected ? 1 : 0) +
                         ", guard_match=" + std::to_string(observedGuard == expectedGuard ? 1 : 0);
    LOG_ERROR(AntiCheatLogger::LogCategory::SYSTEM, detail);
    SendServerLog("ERROR", "SYSTEM", detail);
    AddEvidence(anti_cheat::RUNTIME_ERROR, detail);
    return false;
}

void CheatMonitorEngine::ControlLoop(uint64_t generation)
{
    m_controlThreadAlive.store(true, std::memory_order_relaxed);

    try
    {
        InitializeSystem();
        if (generation == m_controlGeneration.load(std::memory_order_relaxed))
        {
            StartScanThread();
        }

        auto next_report_upload = std::chrono::steady_clock::now();
        auto next_sensor_stats_upload = std::chrono::steady_clock::now();
        auto next_snapshot_upload = std::chrono::steady_clock::now();
        auto next_heartbeat_upload = std::chrono::steady_clock::now();

        uint64_t lastScanProgressCounter = m_scanProgressCounter.load(std::memory_order_relaxed);
        uint32_t scanStalledSeconds = 0;

        while (m_isSystemActive.load())
        {
            if (!m_controlThreadShouldRun.load(std::memory_order_relaxed)) break;
            if (generation != m_controlGeneration.load(std::memory_order_relaxed)) break;

            const auto tickStart = std::chrono::steady_clock::now();
            const auto nextTick = tickStart + std::chrono::seconds(1);

            {
                std::unique_lock<std::mutex> lk(m_controlCvMutex);
                m_controlCv.wait_until(lk, nextTick, [&]() {
                    return !m_isSystemActive.load() || !m_controlThreadShouldRun.load(std::memory_order_relaxed) ||
                           generation != m_controlGeneration.load(std::memory_order_relaxed) ||
                           m_controlWakeRequested.load(std::memory_order_relaxed);
                });
                m_controlWakeRequested.store(false, std::memory_order_relaxed);
            }

            if (!m_isSystemActive.load()) break;
            if (!m_controlThreadShouldRun.load(std::memory_order_relaxed)) break;
            if (generation != m_controlGeneration.load(std::memory_order_relaxed)) break;

            ValidateAndRepairSessionState();
            ProcessInboundTargetedScans();
            EvaluateScanThreadWatchdog(lastScanProgressCounter, scanStalledSeconds);

            const auto now = std::chrono::steady_clock::now();

            if (now >= next_heartbeat_upload)
            {
                UploadHeartbeatReport();
                const int seconds = ClampToPositiveInterval(CheatConfigManager::GetInstance().GetHeartbeatIntervalSeconds(), 1);
                next_heartbeat_upload = now + std::chrono::seconds(seconds);
            }

            if (!m_isSessionActive.load() || !m_hasServerConfig.load())
            {
                MarkControlThreadProgress(generation);
                continue;
            }

            if (now >= next_report_upload)
            {
                UploadEvidenceReport();
                const int minutes = ClampToPositiveInterval(CheatConfigManager::GetInstance().GetReportUploadIntervalMinutes(), 1);
                next_report_upload = now + std::chrono::minutes(minutes);
            }

            if (now >= next_sensor_stats_upload)
            {
                UploadSensorExecutionStatsReport();
                const int minutes =
                        ClampToPositiveInterval(CheatConfigManager::GetInstance().GetSensorStatsUploadIntervalMinutes(), 1);
                next_sensor_stats_upload = now + std::chrono::minutes(minutes);
            }

            if (now >= next_snapshot_upload)
            {
                if (CheatConfigManager::GetInstance().IsSnapshotUploadEnabled()) UploadSnapshotReport();
                const int minutes =
                        ClampToPositiveInterval(CheatConfigManager::GetInstance().GetSnapshotUploadIntervalMinutes(), 1);
                next_snapshot_upload = now + std::chrono::minutes(minutes);
            }

            MarkControlThreadProgress(generation);
        }
    }
    catch (const std::exception &e)
    {
        std::string detail = std::string("Control thread exited with exception: ") + e.what();
        LOG_ERROR(AntiCheatLogger::LogCategory::SYSTEM, detail);
        SendServerLog("ERROR", "SYSTEM", detail);
        AddEvidence(anti_cheat::RUNTIME_ERROR, detail);
    }
    catch (...)
    {
        std::string detail = "Control thread exited with unknown exception";
        LOG_ERROR(AntiCheatLogger::LogCategory::SYSTEM, detail);
        SendServerLog("ERROR", "SYSTEM", detail);
        AddEvidence(anti_cheat::RUNTIME_ERROR, detail);
    }

    m_controlThreadAlive.store(false, std::memory_order_relaxed);

    if (generation == m_controlGeneration.load(std::memory_order_relaxed))
    {
        StopScanThread(true);
    }
}

void CheatMonitorEngine::ScanLoop(uint64_t generation)
{
    m_scanThreadAlive.store(true, std::memory_order_relaxed);

    try
    {
        auto next_light_scan = std::chrono::steady_clock::now();
        auto next_heavy_scan = std::chrono::steady_clock::now();

        uint64_t lastControlProgressCounter = m_controlProgressCounter.load(std::memory_order_relaxed);
        uint32_t controlStalledSeconds = 0;

        while (m_isSystemActive.load())
        {
            if (!m_scanThreadShouldRun.load(std::memory_order_relaxed)) break;
            if (generation != m_scanGeneration.load(std::memory_order_relaxed)) break;

            auto earliest = std::chrono::steady_clock::now() + std::chrono::seconds(1);
            if (m_isSessionActive.load() && m_hasServerConfig.load())
            {
                earliest = std::min(earliest, std::min(next_light_scan, next_heavy_scan));
            }

            {
                std::unique_lock<std::mutex> lk(m_scanCvMutex);
                m_scanCv.wait_until(lk, earliest, [&]() {
                    if (!m_isSystemActive.load()) return true;
                    if (!m_scanThreadShouldRun.load(std::memory_order_relaxed)) return true;
                    if (generation != m_scanGeneration.load(std::memory_order_relaxed)) return true;
                    if (m_scanWakeRequested.load(std::memory_order_relaxed)) return true;

                    std::lock_guard<std::mutex> queueLock(m_targetedScanMutex);
                    return !m_targetedScanQueue.empty();
                });
                m_scanWakeRequested.store(false, std::memory_order_relaxed);
            }

            if (!m_isSystemActive.load()) break;
            if (!m_scanThreadShouldRun.load(std::memory_order_relaxed)) break;
            if (generation != m_scanGeneration.load(std::memory_order_relaxed)) break;

            EvaluateControlThreadWatchdog(lastControlProgressCounter, controlStalledSeconds);

            if (!m_isSessionActive.load() || !m_hasServerConfig.load())
            {
                MarkScanThreadProgress(generation);
                continue;
            }

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

            MarkScanThreadProgress(generation);
        }
    }
    catch (const std::exception &e)
    {
        std::string detail = std::string("Scan thread exited with exception: ") + e.what();
        LOG_ERROR(AntiCheatLogger::LogCategory::SYSTEM, detail);
        SendServerLog("ERROR", "SYSTEM", detail);
        AddEvidence(anti_cheat::RUNTIME_ERROR, detail);
    }
    catch (...)
    {
        std::string detail = "Scan thread exited with unknown exception";
        LOG_ERROR(AntiCheatLogger::LogCategory::SYSTEM, detail);
        SendServerLog("ERROR", "SYSTEM", detail);
        AddEvidence(anti_cheat::RUNTIME_ERROR, detail);
    }

    m_scanThreadAlive.store(false, std::memory_order_relaxed);
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
        std::lock_guard<std::mutex> lock(m_targetedScanIngressMutex);
        m_targetedScanIngressQueue.clear();
    }
    {
        std::lock_guard<std::mutex> lock(m_targetedScanMutex);
        m_targetedScanQueue.clear();
        m_consumedTargetedScanIds.clear();
    }
    m_expectedSessionActive.store(false, std::memory_order_relaxed);
    UpdateSessionGuard(false);
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
    m_lightScanCount++;
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
    m_heavyScanCount++;
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

    {
        std::lock_guard<std::mutex> lock(m_targetedScanMutex);
        if (m_consumedTargetedScanIds.count(requestId) > 0) return;
        if (HasQueuedScanRequest(m_targetedScanQueue, requestId)) return;
    }

    bool added = false;
    {
        std::lock_guard<std::mutex> lock(m_targetedScanIngressMutex);
        if (!HasQueuedScanRequest(m_targetedScanIngressQueue, requestId))
        {
            m_targetedScanIngressQueue.push_back(TargetedScanRequest{requestId, sensorName});
            added = true;
        }
    }
    if (added) WakeControlThread();
}

void CheatMonitorEngine::ProcessInboundTargetedScans()
{
    std::deque<TargetedScanRequest> inboundRequests;
    {
        std::lock_guard<std::mutex> lock(m_targetedScanIngressMutex);
        if (m_targetedScanIngressQueue.empty()) return;
        inboundRequests.swap(m_targetedScanIngressQueue);
    }

    bool wakeScanThread = false;
    while (!inboundRequests.empty())
    {
        TargetedScanRequest request = inboundRequests.front();
        inboundRequests.pop_front();

        bool accepted = false;
        {
            std::lock_guard<std::mutex> lock(m_targetedScanMutex);
            if (m_consumedTargetedScanIds.count(request.requestId) == 0 &&
                !HasQueuedScanRequest(m_targetedScanQueue, request.requestId))
            {
                m_targetedScanQueue.push_back(request);
                accepted = true;
            }
        }

        if (!accepted) continue;

        wakeScanThread = true;
        SendServerLog("INFO", "SYSTEM",
                      "ACK targeted sensor request accepted: request_id=" + request.requestId + ", sensor=" +
                              request.sensorName);
    }

    if (wakeScanThread) WakeScanThread();
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
            size_t current_len = m_evidences.size();
            if (current_len > evidence_begin)
            {
                for (size_t i = evidence_begin; i < current_len; ++i)
                {
                    evidences.push_back(m_evidences[i]);
                }
                m_evidences.erase(m_evidences.begin() + evidence_begin, m_evidences.end());
            }
        }
        UploadTargetedSensorReport(request.requestId, request.sensorName, result, failureReason, durationMs, notes, evidences);
    }

    {
        std::lock_guard<std::mutex> lock(m_targetedScanMutex);
        m_consumedTargetedScanIds.insert(request.requestId);
    }
}
