#pragma once

#include "ISensor.h"
#include "ScanContext.h"
#include "CheatConfigManager.h"
#include "HardwareInfoCollector.h"
#include "WMIProcessMonitor.h"
#include "utils/SystemUtils.h"
#include "utils/Utils.h"
#include "Logger.h"
#include "anti_cheat.pb.h"

#include <windows.h>
#include <atomic>
#include <thread>
#include <condition_variable>
#include <mutex>
#include <unordered_set>
#include <set>
#include <map>
#include <vector>
#include <deque>
#include <random>
#include <algorithm>

struct CheatMonitorImpl
{
    CheatMonitorImpl();
    ~CheatMonitorImpl();

    SystemUtils::WindowsVersion m_windowsVersion;

    // === System State ===
    std::atomic<bool> m_isSystemActive = false;
    std::atomic<bool> m_isSessionActive = false;
    std::atomic<bool> m_hasServerConfig = false;
    std::atomic<bool> m_processBaselineEstablished = false;

    // === Threading ===
    std::thread m_monitorThread;
    std::condition_variable m_cv;
    std::mutex m_cvMutex;

    // === Module Paths ===
    std::mutex m_modulePathsMutex;
    std::unordered_set<std::wstring> m_legitimateModulePaths;

    // === Session State ===
    std::mutex m_sessionMutex;
    uint32_t m_currentUserId = 0;
    std::string m_currentUserName;
    std::set<std::pair<anti_cheat::CheatCategory, std::string>> m_uniqueEvidence;
    std::vector<anti_cheat::Evidence> m_evidences;
    bool m_evidenceOverflowed = false;
    std::map<std::pair<uint32_t, anti_cheat::CheatCategory>, std::chrono::steady_clock::time_point> m_lastReported;

    // === Sensor Stats ===
    std::mutex m_sensorStatsMutex;
    std::unordered_map<std::string, anti_cheat::SensorExecutionStats> m_sensorExecutionStats;

    // === Module Signature Cache ===
    mutable std::mutex m_signatureCacheMutex;
    enum class SignatureVerdict
    {
        UNKNOWN,
        SIGNED_AND_TRUSTED,
        UNSIGNED_OR_UNTRUSTED,
        VERIFICATION_FAILED
    };
    std::unordered_map<std::wstring, std::pair<SignatureVerdict, std::chrono::steady_clock::time_point>>
            m_moduleSignatureCache;

    // === Throttling ===
    std::unordered_map<std::wstring, std::chrono::steady_clock::time_point> m_sigThrottleUntil;

    // === Cursors ===
    size_t m_handleCursorOffset = 0;
    size_t m_moduleCursorOffset = 0;
    size_t m_processCursorOffset = 0;

    // === PID Throttling ===
    std::unordered_map<DWORD, std::chrono::steady_clock::time_point> m_pidThrottleUntil;

    // === Process Signature Cache ===
    std::unordered_map<std::wstring, std::pair<Utils::SignatureStatus, std::chrono::steady_clock::time_point>>
            m_processSigCache;
    std::unordered_map<std::wstring, std::chrono::steady_clock::time_point> m_processSigThrottleUntil;

    enum ProcessVerdict
    {
        SIGNED_AND_TRUSTED,
        UNSIGNED_OR_UNTRUSTED
    };

    // === Baselines ===
    std::unordered_map<std::wstring, std::vector<uint8_t>> m_moduleBaselineHashes;
    HMODULE m_hSelfModule = NULL;
    std::vector<uint8_t> m_selfModuleBaselineHash;
    std::unordered_map<std::string, std::vector<uint8_t>> m_iatBaselineHashes;
    uintptr_t m_vehListAddress = 0;

    mutable std::mutex m_baselineMutex;
    std::set<DWORD> m_knownThreadIds;
    std::set<HMODULE> m_knownModules;

    // === Subsystems ===
    std::unique_ptr<anti_cheat::HardwareInfoCollector> m_hwCollector;
    std::unique_ptr<anti_cheat::WMIProcessMonitor> m_wmiMonitor;

    // === Others ===
    std::atomic<uintptr_t> m_gameWindowHandle{0};
    std::random_device m_rd;
    mutable std::mt19937 m_rng{std::random_device{}()};

    // === Sensors ===
    size_t m_lightSensorIndex = 0;
    size_t m_heavySensorIndex = 0;
    std::vector<std::unique_ptr<ISensor>> m_lightweightSensors;
    std::vector<std::unique_ptr<ISensor>> m_heavyweightSensors;
    std::unordered_map<std::string, ISensor *> m_sensorRegistry;

    struct TargetedScanRequest
    {
        std::string requestId;
        std::string sensorName;
    };
    std::mutex m_targetedScanMutex;
    std::deque<TargetedScanRequest> m_targetedScanQueue;
    std::unordered_set<std::string> m_consumedTargetedScanIds;

    // === Self Integrity ===
    std::vector<uint8_t> m_isAddressInLegitimateModulePrologue;
    void InitializeSelfIntegrityBaseline();
    void CheckSelfIntegrity();

    // === DLL Notification ===
    PVOID m_dllNotificationCookie = nullptr;
    static VOID CALLBACK DllLoadCallback(ULONG NotificationReason, const LDR_DLL_NOTIFICATION_DATA *NotificationData, PVOID Context);
    void RegisterDllNotification();
    void UnregisterDllNotification();
    void OnDllLoaded(const LDR_DLL_LOAD_NOTIFICATION_DATA &data);

    // === Process Events ===
    void OnProcessCreated(DWORD pid, const std::wstring &name);

    enum class ExecutionStatus : int
    {
        SUCCESS = 0,
        FAILURE = 1,
        TIMEOUT = 2,
        EXCEPTION = 3
    };

    void InitializeSystem();
    void InitializeProcessBaseline();
    void ResetSessionState();
    void OnConfigUpdated();
    void MonitorLoop();

    // Helpers
    const std::chrono::milliseconds GetLightScanInterval() const;
    const std::chrono::milliseconds GetHeavyScanInterval() const;
    void ExecuteLightweightSensors();
    void ExecuteHeavyweightSensors();
    SensorExecutionResult ExecuteAndMonitorSensor(ISensor *sensor, const char *name, bool isHeavyweight,
                                                  ScanContext &context,
                                                  anti_cheat::SensorFailureReason *outFailure = nullptr,
                                                  int *outDurationMs = nullptr);
    void AddRandomJitter();
    void WakeMonitor();
    void ProcessPendingTargetedScans();
    void RunTargetedSensorScan(const TargetedScanRequest &request);
    void SubmitTargetedScanRequest(const std::string &requestId, const std::string &sensorName);
    bool TryDequeueTargetedScan(TargetedScanRequest &outRequest);
    void UploadTargetedSensorReport(const std::string &requestId, const std::string &sensorName,
                                    SensorExecutionResult result, anti_cheat::SensorFailureReason failureReason,
                                    int duration_ms, const std::string &notes,
                                    const std::vector<anti_cheat::Evidence> &evidences);

    void UploadHardwareReport();
    void UploadEvidenceReport();
    void UploadTelemetryMetricsReport(const anti_cheat::TelemetryMetrics &metrics);
    void UploadSnapshotReport();
    void SendReport(const anti_cheat::Report &report);
    void SendServerLog(const std::string &log_level, const std::string &log_category, const std::string &log_message);
    void RecordSensorExecutionStats(const char *name, int duration_ms, SensorExecutionResult result,
                                    anti_cheat::SensorFailureReason failureReason = anti_cheat::UNKNOWN_FAILURE);
    void UploadSensorExecutionStatsReport();
    void RecordSensorWorkloadCounters(const std::string &name, uint64_t snapshot_size, uint64_t attempts,
                                      uint64_t hits);
    void AddEvidence(anti_cheat::CheatCategory category, const std::string &description);

    bool IsCurrentOsSupported() const;
    uintptr_t FindVehListAddress();
    void HardenProcessAndThreads();
    void CheckParentProcessAtStartup();
    void DetectVirtualMachine();
    void DetectVmByCpuid();
    void DetectVmByRegistry();
    void DetectVmByMacAddress();
    void VerifyModuleSignature(HMODULE hModule);
    bool IsAddressInLegitimateModule(PVOID address, std::wstring &outModulePath);
    bool IsAddressInLegitimateModule(PVOID address);

    std::chrono::steady_clock::time_point m_lastSnapshotUploadTime;
    std::vector<anti_cheat::ThreadSnapshot> CollectThreadSnapshots();
    std::vector<anti_cheat::ModuleSnapshot> CollectModuleSnapshots();
    std::string GetCertificateThumbprint(const std::wstring &filePath);
    std::string CalculateSHA256String(const BYTE *data, size_t size);

    // Removed CheckIatHooks as it is now in IatHookSensor
    // void CheckIatHooks(ScanContext &context, const BYTE *baseAddress, const IMAGE_IMPORT_DESCRIPTOR *pImportDesc);

    // Dynamic Baseline Update
    void UpdateModuleBaselineHash(const std::wstring &modulePath, const std::vector<uint8_t> &hash)
    {
        {
            std::lock_guard<std::mutex> lock(m_baselineMutex);
            m_moduleBaselineHashes[modulePath] = hash;
        }
        std::wstring lowerPath = modulePath;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
        {
            std::lock_guard<std::mutex> lock(m_modulePathsMutex);
            m_legitimateModulePaths.insert(lowerPath);
        }
        LOG_DEBUG_F(AntiCheatLogger::LogCategory::SYSTEM, "UpdateModuleBaselineHash: Added trusted module to baseline and list: %s",
                    Utils::WideToString(modulePath).c_str());
    }
};
