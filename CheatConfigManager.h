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
    int32_t GetReportCooldownMinutes() const;
    int32_t GetJitterMilliseconds() const;

    // --- 容量控制 ---
    int32_t GetMaxEvidencesPerSession() const;

    // --- 容量与缓存控制 ---
    int32_t GetProcessCacheDurationMinutes() const;
    int32_t GetSignatureCacheDurationMinutes() const;

    // --- 签名验证节流控制 ---
    int32_t GetSignatureVerificationThrottleSeconds() const;
    int32_t GetSignatureVerificationFailureThrottleMs() const;

    // [新增] 安全和性能阈值
    int32_t GetMaxVehHandlersToScan() const;
    int32_t GetMaxCodeSectionSize() const;  // MemoryScanSensor: 最大代码节大小(字节)

    // [新增] 获取配置的OS版本要求
    std::string GetMinOsVersionName() const;        // 获取OS版本的可读名称
    anti_cheat::OsVersion GetMinOsVersion() const;  // 获取配置的最低OS版本要求

    // [新增] 通用配置参数（所有Sensor共用）
    int32_t GetHeavyScanBudgetMs() const;  // 重量级扫描预算时间(毫秒)

    // [新增] MemorySecuritySensor配置参数
    int32_t GetMinMemoryRegionSize() const;  // 最小内存区域大小(字节)
    int32_t GetMaxMemoryRegionSize() const;  // 最大内存区域大小(字节)

    // [新增] EnvironmentSensor配置参数
    int32_t GetMaxProcessesToScan() const;  // 最大进程扫描数量

    // [新增] 性能调优参数
    int32_t GetMaxWindowCount() const;                    // 最大窗口数量限制
    int32_t GetMaxHandleScanCount() const;                // 最大句柄扫描数量
    int32_t GetInitialBufferSizeMb() const;               // 初始缓冲区大小(MB)
    int32_t GetMaxBufferSizeMb() const;                   // 最大缓冲区大小(MB)
    int32_t GetSensorStatsUploadIntervalMinutes() const;  // 传感器统计上报间隔(分钟)

    // [新增] 时间片扫描限额（游标式遍历）
    int32_t GetMaxPidAttemptsPerScan() const;   // 每次句柄扫描最多尝试的新PID数量
    int32_t GetMaxModulesPerScan() const;       // 每次模块完整性扫描最多处理的模块数量
    int32_t GetPidThrottleMinutes() const;      // PID节流时长（分钟）


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
        // 简化版：无禁用名单

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
