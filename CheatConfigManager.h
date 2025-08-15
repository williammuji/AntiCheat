#pragma once

#include "anti_cheat.pb.h"
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

class CheatConfigManager
{
   public:
    static CheatConfigManager& GetInstance();

    CheatConfigManager(const CheatConfigManager&) = delete;
    CheatConfigManager& operator=(const CheatConfigManager&) = delete;

    void UpdateConfigFromServer(const std::string& server_data);

    // --- Getters ---
    int32_t GetBaseScanInterval() const;
    int32_t GetHeavyScanIntervalMinutes() const;
    int32_t GetReportUploadIntervalMinutes() const;

    std::shared_ptr<const std::vector<std::wstring>> GetHarmfulProcessNames() const;
    std::shared_ptr<const std::vector<std::wstring>> GetHarmfulKeywords() const;
    std::shared_ptr<const std::unordered_set<std::wstring>> GetWhitelistedVEHModules() const;
    std::shared_ptr<const std::unordered_set<std::wstring>> GetWhitelistedProcessPaths() const;
    std::shared_ptr<const std::unordered_set<std::wstring>> GetWhitelistedWindowKeywords() const;
    std::shared_ptr<const std::unordered_set<std::wstring>> GetKnownGoodProcesses() const;

    // --- 行为控制参数 ---
    int32_t GetSuspiciousHandleTTLMinutes() const;
    int32_t GetReportCooldownMinutes() const;
    int32_t GetIllegalCallReportCooldownMinutes() const;
    int32_t GetJitterMilliseconds() const;

    // --- 容量与预算控制 ---
    int32_t GetMaxEvidencesPerSession() const;
    int32_t GetMaxIllegalSources() const;
    int32_t GetLightScanBudgetMs() const;
    int32_t GetHeavyScanBudgetMs() const;

    // --- 容量与缓存控制 ---
    int32_t GetMaxMouseMoveEvents() const;
    int32_t GetMaxMouseClickEvents() const;
    int32_t GetMaxKeyboardEvents() const;
    int32_t GetProcessCacheDurationMinutes() const;
    int32_t GetSignatureCacheDurationMinutes() const;

    // --- 输入自动化检测参数 ---
    int32_t GetKeyboardMacroMinSequenceLength() const;
    int32_t GetKeyboardMacroMinPatternLength() const;

   private:
    struct ConfigData
    {
        std::unique_ptr<anti_cheat::ClientConfig> config;
        std::vector<std::wstring> harmfulProcessNames_w;
        std::vector<std::wstring> harmfulKeywords_w;
        std::unordered_set<std::wstring> whitelistedVEHModules_w;
        std::unordered_set<std::wstring> whitelistedProcessPaths_w;
        std::unordered_set<std::wstring> whitelistedWindowKeywords_w;
        std::unordered_set<std::wstring> knownGoodProcesses_w;

        ConfigData() : config(std::make_unique<anti_cheat::ClientConfig>())
        {
        }
    };

    CheatConfigManager();
    ~CheatConfigManager() = default;

    std::shared_ptr<ConfigData> GetCurrentConfig() const;

    void SetDefaultValues(ConfigData& configData);
    void UpdateWideStringCaches(ConfigData& configData);
    bool VerifySignature(const anti_cheat::ClientConfig& config) const;
    std::string CalculateHash(const std::string& data) const;
    std::string GetServerPublicKey() const;

    mutable std::mutex m_mutex;
    std::shared_ptr<ConfigData> m_configData;
};