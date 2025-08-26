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

    int32_t GetProcessCacheDurationMinutes() const;
    int32_t GetSignatureCacheDurationMinutes() const;



    // [新增] 安全和性能阈值
    int32_t GetMaxVehHandlersToScan() const;
    int32_t GetMaxHandlesToScan() const;

    // [已弃用] 传统传感器开关（现在由灰度分组控制）
    bool IsVehScanEnabledLegacy() const;  // 旧版本的VEH开关
    bool IsHandleScanEnabledLegacy() const;  // 旧版本的Handle开关
    
    // [已弃用] 字符串格式的灰度分组
    std::string GetRolloutGroup() const;
    
    // 新的灰度分组策略
    anti_cheat::RolloutGroup GetRolloutGroupEnum() const;   // 获取枚举格式的分组
    bool IsVehScanEnabled() const;                          // 基于灰度分组判断是否开启VEH扫描
    bool IsHandleScanEnabled() const;                       // 基于灰度分组判断是否开启Handle扫描
    std::string GetRolloutGroupName() const;                // 获取灰度分组的可读名称
    
    // [新增] 基于rollout_group_enum推导最低OS版本
    anti_cheat::OsMinimum GetRequiredMinOs() const;         // 根据灰度分组推导最低OS版本要求

    // [新增] 生产环境配置参数（减少硬编码）
    int32_t GetVehScanTimeoutMs() const;           // VEH扫描超时时间
    int32_t GetIatScanTimeoutMs() const;           // IAT扫描超时时间
    int32_t GetMemoryScanChunkSize() const;        // 内存扫描块大小
    int32_t GetCpuYieldInterval() const;           // CPU让出间隔
    int32_t GetMaxRetryAttempts() const;           // 最大重试次数
    int32_t GetBackoffBaseMs() const;              // 退避基础时间(毫秒)
    int32_t GetMaxBackoffMs() const;               // 最大退避时间(毫秒)
    int32_t GetPerformanceReportInterval() const;  // 性能报告间隔(次)

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
    // 客户端不再进行配置签名校验

    mutable std::mutex m_mutex;
    std::shared_ptr<ConfigData> m_configData;
};