#pragma once

// Define WIN32_LEAN_AND_MEAN to exclude rarely-used APIs from Windows.h,
// including the old winsock.h, which prevents conflicts with winsock2.h.
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>
#include <vector>
#include <mutex>
#include <memory>
#include <unordered_set>
#include "anti_cheat.pb.h"

// 前向声明，避免在头文件中包含完整的实现
namespace anti_cheat
{
class ClientConfig;
}

class CheatConfigManager
{
   public:
    // 获取单例实例
    static CheatConfigManager& GetInstance();

    // 在与服务器通讯后调用，用服务器下发的数据更新配置
    // 数据应为序列化后的 ClientConfig protobuf
    void UpdateConfigFromServer(const std::string& server_data);

    // --- 配置项的 Getter ---
    // 为了线程安全，所有getter都应在内部加锁

    int32_t GetBaseScanInterval() const;
    int32_t GetHeavyScanIntervalMinutes() const;
    int32_t GetReportUploadIntervalMinutes() const;
    const std::vector<std::wstring>& GetHarmfulProcessNames() const;
    const std::vector<std::wstring>& GetHarmfulKeywords() const;
    const std::unordered_set<std::wstring>& GetWhitelistedVEHModules() const;
    const std::unordered_set<std::wstring>& GetWhitelistedProcessPaths() const;
    const std::unordered_set<std::wstring>& GetWhitelistedWindowKeywords() const;
    const std::unordered_set<std::wstring>& GetKnownGoodProcesses() const;

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
    CheatConfigManager();
    ~CheatConfigManager() = default;

    // 禁用拷贝和赋值构造函数
    CheatConfigManager(const CheatConfigManager&) = delete;
    CheatConfigManager& operator=(const CheatConfigManager&) = delete;

    void SetDefaultValues();        // 设置硬编码的默认值
    void UpdateWideStringCaches();  // 更新宽字符版本的缓存

    // 安全相关辅助函数
    bool VerifySignature(const anti_cheat::ClientConfig& config) const;
    std::string CalculateHash(const std::string& data) const;
    std::string GetServerPublicKey() const;

    // 内部状态
    std::unique_ptr<anti_cheat::ClientConfig> m_config;
    mutable std::mutex m_mutex;

    // 为频繁访问的字符串列表提供宽字符缓存，避免重复转换
    std::vector<std::wstring> m_harmfulProcessNames_w;
    std::vector<std::wstring> m_harmfulKeywords_w;
    std::unordered_set<std::wstring> m_whitelistedVEHModules_w;
    std::unordered_set<std::wstring> m_whitelistedProcessPaths_w;
    std::unordered_set<std::wstring> m_whitelistedWindowKeywords_w;
    std::unordered_set<std::wstring> m_knownGoodProcesses_w;
};