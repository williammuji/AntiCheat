#pragma once

#include <vector>
#include <string>
#include <memory>
#include <unordered_set>
#include <unordered_map>
#include <set>
#include <windows.h>
#include "anti_cheat.pb.h"
#include "utils/SystemUtils.h"
#include "utils/Utils.h"

// Forward declarations
struct CheatMonitorImpl;
class CheatConfigManager;

class ScanContext
{
   private:
    CheatMonitorImpl *m_pimpl;
    bool m_isTargetedScan = false;

   public:
    // Caches
    std::vector<HMODULE> CachedModules;
    std::vector<MEMORY_BASIC_INFORMATION> CachedMemoryRegions;
    bool IsMemoryCacheValid = false;

    explicit ScanContext(CheatMonitorImpl *pimpl, bool targetedScan = false);
    ~ScanContext();

    void RefreshModuleCache();
    void RefreshMemoryCache();
    bool IsTargetedScan() const;

    // Services for sensors
    void AddEvidence(anti_cheat::CheatCategory category, const std::string &description);

    // Configuration Access
    std::shared_ptr<const std::vector<std::wstring>> GetHarmfulProcessNames() const;
    std::shared_ptr<const std::vector<std::wstring>> GetHarmfulKeywords() const;
    std::shared_ptr<const std::unordered_set<std::wstring>> GetWhitelistedProcessPaths() const;
    std::shared_ptr<const std::unordered_set<std::wstring>> GetWhitelistedWindowKeywords() const;
    std::shared_ptr<const std::unordered_set<std::wstring>> GetWhitelistedVEHModules() const;
    std::shared_ptr<const std::unordered_set<std::wstring>> GetWhitelistedSystemModules() const;
    std::shared_ptr<const std::unordered_set<std::wstring>> GetWhitelistedIntegrityIgnoreList() const;

    // Baseline Access
    const std::unordered_map<std::string, std::vector<uint8_t>> &GetIatBaselineHashes() const;
    const std::unordered_map<std::wstring, std::vector<uint8_t>> &GetModuleBaselineHashes() const;
    void UpdateModuleBaselineHash(const std::wstring &modulePath, const std::vector<uint8_t> &hash);
    const uintptr_t GetVehListAddress() const;

    // OS Info
    SystemUtils::WindowsVersion GetWindowsVersion() const;
    bool IsCurrentOsSupported() const;

    // Pimpl Access Helper Wrappers
    bool IsAddressInLegitimateModule(PVOID address, std::wstring &outModulePath);
    bool IsAddressInLegitimateModule(PVOID address);

    std::shared_ptr<const std::unordered_set<std::wstring>> GetKnownGoodHandleHolders() const;

    void UploadTelemetryMetricsReport(const anti_cheat::TelemetryMetrics &metrics);
    void SendServerLog(const std::string &log_level, const std::string &log_category, const std::string &log_message);
    void RecordSensorWorkloadCounters(const std::string &name, uint64_t snapshot_size, uint64_t attempts, uint64_t hits);

    // Known State Access
    std::set<DWORD> GetKnownThreadIds() const;
    std::set<HMODULE> GetKnownModules() const;
    bool InsertKnownThreadId(DWORD threadId);
    bool IsModuleKnown(HMODULE hModule) const;
    bool InsertKnownModule(HMODULE hModule);

    void VerifyModuleSignature(HMODULE hModule);
    void CheckSelfIntegrity();
    const HMODULE GetSelfModuleHandle() const;

    // Cursor Access
    size_t GetHandleCursorOffset() const;
    void SetHandleCursorOffset(size_t v);
    size_t GetModuleCursorOffset() const;
    void SetModuleCursorOffset(size_t v);
    size_t GetProcessCursorOffset() const;
    void SetProcessCursorOffset(size_t v);

    std::unordered_map<DWORD, std::chrono::steady_clock::time_point> &GetPidThrottleUntil();
    std::unordered_map<std::wstring, std::pair<Utils::SignatureStatus, std::chrono::steady_clock::time_point>> &
    GetProcessSigCache();
    std::unordered_map<std::wstring, std::chrono::steady_clock::time_point> &GetProcessSigThrottleUntil();
};
