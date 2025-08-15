#include "CheatConfigManager.h"
#include "CheatMonitor.h"  // 为了访问 Utils::StringToWide 和通知 CheatMonitor
#include <stdexcept>
#include <algorithm>   // for std::replace
#include <Wincrypt.h>  // for Crypt* functions
#include <memory>      // for std::shared_ptr

#pragma comment(lib, "crypt32.lib")  // For Crypt* functions

// --- Utils命名空间函数声明，因为它们在CheatMonitor.cpp中 ---
namespace Utils
{
std::wstring StringToWide(const std::string& str);
std::string WideToString(const std::wstring& wstr);
}  // namespace Utils

// --- 单例实现 ---
CheatConfigManager& CheatConfigManager::GetInstance()
{
    static CheatConfigManager instance;
    return instance;
}

CheatConfigManager::CheatConfigManager() : m_configData(std::make_shared<ConfigData>())
{
    // 启动后这组数据等服务器下发，再设置m_isSessionActive为true
    // SetDefaultValues(*m_configData);
}

// --- 私有辅助函数 ---
std::shared_ptr<CheatConfigManager::ConfigData> CheatConfigManager::GetCurrentConfig() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_configData;
}

// --- 公共接口实现 ---

void CheatConfigManager::UpdateConfigFromServer(const std::string& server_data)
{
    auto new_config_proto = std::make_unique<anti_cheat::ClientConfig>();
    if (!new_config_proto->ParseFromString(server_data))
    {
        // Log error: "Failed to parse server config"
        return;
    }

    if (!VerifySignature(*new_config_proto))
    {
        // Log error: "Server config signature verification failed"
        return;
    }

    // 创建新的配置数据副本
    auto new_config_data = std::make_shared<ConfigData>();
    new_config_data->config = std::move(new_config_proto);
    UpdateWideStringCaches(*new_config_data);

    // 原子地交换指针
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_configData = std::move(new_config_data);
    }

    // 通知 CheatMonitor 配置已更新
    CheatMonitor::GetInstance().OnServerConfigUpdated();
}

// --- Getters ---

int32_t CheatConfigManager::GetBaseScanInterval() const
{
    return GetCurrentConfig()->config->base_scan_interval_seconds();
}

int32_t CheatConfigManager::GetHeavyScanIntervalMinutes() const
{
    return GetCurrentConfig()->config->heavy_scan_interval_minutes();
}

int32_t CheatConfigManager::GetReportUploadIntervalMinutes() const
{
    return GetCurrentConfig()->config->report_upload_interval_minutes();
}

std::shared_ptr<const std::vector<std::wstring>> CheatConfigManager::GetHarmfulProcessNames() const
{
    auto config = GetCurrentConfig();
    return std::shared_ptr<const std::vector<std::wstring>>(config, &config->harmfulProcessNames_w);
}

std::shared_ptr<const std::vector<std::wstring>> CheatConfigManager::GetHarmfulKeywords() const
{
    auto config = GetCurrentConfig();
    return std::shared_ptr<const std::vector<std::wstring>>(config, &config->harmfulKeywords_w);
}

std::shared_ptr<const std::unordered_set<std::wstring>> CheatConfigManager::GetWhitelistedVEHModules() const
{
    auto config = GetCurrentConfig();
    return std::shared_ptr<const std::unordered_set<std::wstring>>(config, &config->whitelistedVEHModules_w);
}

std::shared_ptr<const std::unordered_set<std::wstring>> CheatConfigManager::GetWhitelistedProcessPaths() const
{
    auto config = GetCurrentConfig();
    return std::shared_ptr<const std::unordered_set<std::wstring>>(config, &config->whitelistedProcessPaths_w);
}

std::shared_ptr<const std::unordered_set<std::wstring>> CheatConfigManager::GetWhitelistedWindowKeywords() const
{
    auto config = GetCurrentConfig();
    return std::shared_ptr<const std::unordered_set<std::wstring>>(config, &config->whitelistedWindowKeywords_w);
}

std::shared_ptr<const std::unordered_set<std::wstring>> CheatConfigManager::GetKnownGoodProcesses() const
{
    auto config = GetCurrentConfig();
    return std::shared_ptr<const std::unordered_set<std::wstring>>(config, &config->knownGoodProcesses_w);
}

// --- 行为控制参数 ---
int32_t CheatConfigManager::GetSuspiciousHandleTTLMinutes() const
{
    return GetCurrentConfig()->config->suspicious_handle_ttl_minutes();
}
int32_t CheatConfigManager::GetReportCooldownMinutes() const
{
    return GetCurrentConfig()->config->report_cooldown_minutes();
}
int32_t CheatConfigManager::GetIllegalCallReportCooldownMinutes() const
{
    return GetCurrentConfig()->config->illegal_call_report_cooldown_minutes();
}
int32_t CheatConfigManager::GetJitterMilliseconds() const
{
    return GetCurrentConfig()->config->jitter_milliseconds();
}

// --- 容量与预算控制 ---
int32_t CheatConfigManager::GetMaxEvidencesPerSession() const
{
    return GetCurrentConfig()->config->max_evidences_per_session();
}
int32_t CheatConfigManager::GetMaxIllegalSources() const
{
    return GetCurrentConfig()->config->max_illegal_sources();
}
int32_t CheatConfigManager::GetLightScanBudgetMs() const
{
    return GetCurrentConfig()->config->light_scan_budget_ms();
}
int32_t CheatConfigManager::GetHeavyScanBudgetMs() const
{
    return GetCurrentConfig()->config->heavy_scan_budget_ms();
}

// --- 容量与缓存控制 ---
int32_t CheatConfigManager::GetMaxMouseMoveEvents() const
{
    return GetCurrentConfig()->config->max_mouse_move_events();
}
int32_t CheatConfigManager::GetMaxMouseClickEvents() const
{
    return GetCurrentConfig()->config->max_mouse_click_events();
}
int32_t CheatConfigManager::GetMaxKeyboardEvents() const
{
    return GetCurrentConfig()->config->max_keyboard_events();
}
int32_t CheatConfigManager::GetProcessCacheDurationMinutes() const
{
    return GetCurrentConfig()->config->process_cache_duration_minutes();
}
int32_t CheatConfigManager::GetSignatureCacheDurationMinutes() const
{
    return GetCurrentConfig()->config->signature_cache_duration_minutes();
}

// --- 输入自动化检测参数 ---
int32_t CheatConfigManager::GetKeyboardMacroMinSequenceLength() const
{
    return GetCurrentConfig()->config->keyboard_macro_min_sequence_length();
}
int32_t CheatConfigManager::GetKeyboardMacroMinPatternLength() const
{
    return GetCurrentConfig()->config->keyboard_macro_min_pattern_length();
}

// --- 私有辅助函数 ---

void CheatConfigManager::SetDefaultValues(ConfigData& configData)
{
    // 这些值应该与你之前在 Pimpl 中的硬编码值一致
    configData.config->set_base_scan_interval_seconds(15);
    configData.config->set_heavy_scan_interval_minutes(30);
    configData.config->set_report_upload_interval_minutes(15);

    configData.config->clear_harmful_process_names();
    configData.config->add_harmful_process_names("cheatengine");
    configData.config->add_harmful_process_names("ollydbg");
    configData.config->add_harmful_process_names("x64dbg");
    configData.config->add_harmful_process_names("ida64");
    configData.config->add_harmful_process_names("fiddler");

    configData.config->clear_harmful_keywords();
    configData.config->add_harmful_keywords("外挂");
    configData.config->add_harmful_keywords("辅助");
    configData.config->add_harmful_keywords("cheat engine");
    configData.config->add_harmful_keywords("memory editor");

    configData.config->clear_whitelisted_window_keywords();
    configData.config->add_whitelisted_window_keywords(Utils::WideToString(L"visual studio"));
    configData.config->add_whitelisted_window_keywords(Utils::WideToString(L"obs"));
    configData.config->add_whitelisted_window_keywords(Utils::WideToString(L"discord"));

    configData.config->clear_known_good_processes();
    configData.config->add_known_good_processes("explorer.exe");
    configData.config->add_known_good_processes("svchost.exe");
    configData.config->add_known_good_processes("lsass.exe");
    configData.config->add_known_good_processes("wininit.exe");
    configData.config->add_known_good_processes("services.exe");
    configData.config->add_known_good_processes("sogoucloud.exe");
    configData.config->add_known_good_processes("sogouinput.exe");
    configData.config->add_known_good_processes("qqpinyin.exe");
    configData.config->add_known_good_processes("msime.exe");
    configData.config->add_known_good_processes("chsime.exe");
    configData.config->add_known_good_processes("nvcontainer.exe");
    configData.config->add_known_good_processes("nvidia share.exe");
    configData.config->add_known_good_processes("amdow.exe");
    configData.config->add_known_good_processes("radeonsoftware.exe");
    configData.config->add_known_good_processes("yy.exe");
    configData.config->add_known_good_processes("yylive.exe");
    configData.config->add_known_good_processes("qt.exe");
    configData.config->add_known_good_processes("360safe.exe");
    configData.config->add_known_good_processes("360sd.exe");
    configData.config->add_known_good_processes("qqpctray.exe");
    configData.config->add_known_good_processes("huorong.exe");
    configData.config->add_known_good_processes("wspsafesvc.exe");

    // --- 行为控制参数 ---
    configData.config->set_suspicious_handle_ttl_minutes(2);
    configData.config->set_report_cooldown_minutes(30);
    configData.config->set_illegal_call_report_cooldown_minutes(5);
    configData.config->set_jitter_milliseconds(5000);

    // --- 容量与预算控制 ---
    configData.config->set_max_evidences_per_session(512);
    configData.config->set_max_illegal_sources(1024);
    configData.config->set_light_scan_budget_ms(6000);
    configData.config->set_heavy_scan_budget_ms(30000);

    // --- 容量与缓存控制 ---
    configData.config->set_max_mouse_move_events(5000);
    configData.config->set_max_mouse_click_events(500);
    configData.config->set_max_keyboard_events(2048);
    configData.config->set_process_cache_duration_minutes(15);
    configData.config->set_signature_cache_duration_minutes(60);

    // --- 输入自动化检测参数 ---
    configData.config->set_keyboard_macro_min_sequence_length(40);
    configData.config->set_keyboard_macro_min_pattern_length(10);

    configData.config->set_config_version("default_fallback_v1");

    // 为默认配置生成一个“签名”
    std::string serialized_config;
    configData.config->SerializeToString(&serialized_config);
    configData.config->set_config_signature(CalculateHash(serialized_config + GetServerPublicKey()));

    UpdateWideStringCaches(configData);
}

void CheatConfigManager::UpdateWideStringCaches(ConfigData& configData)
{
    auto convert_to_vector = [](const auto& source, auto& dest) {
        dest.clear();
        dest.reserve(source.size());
        for (const auto& s : source)
        {
            dest.push_back(Utils::StringToWide(s));
        }
    };

    auto convert_to_set = [](const auto& source, auto& dest) {
        dest.clear();
        for (const auto& s : source)
        {
            dest.insert(Utils::StringToWide(s));
        }
    };

    convert_to_vector(configData.config->harmful_process_names(), configData.harmfulProcessNames_w);
    convert_to_vector(configData.config->harmful_keywords(), configData.harmfulKeywords_w);
    convert_to_set(configData.config->whitelisted_veh_modules(), configData.whitelistedVEHModules_w);
    convert_to_set(configData.config->whitelisted_process_paths(), configData.whitelistedProcessPaths_w);
    convert_to_set(configData.config->whitelisted_window_keywords(), configData.whitelistedWindowKeywords_w);
    convert_to_set(configData.config->known_good_processes(), configData.knownGoodProcesses_w);
}

// --- 安全相关函数 ---

std::string CheatConfigManager::GetServerPublicKey() const
{
    // 这是一个占位符公钥。在实际生产中，您需要替换为您真实的公钥，
    // 并使用更健壮的混淆技术来保护它。
    const unsigned char g_encryptedPublicKey[] = {
            0x75, 0x6d, 0x66, 0x77, 0x48, 0x73, 0x45, 0x0c, 0x57, 0x65, 0x73, 0x7e, 0x0c, 0x41, 0x63, 0x61, 0x6c, 0x49,
            0x63, 0x79, 0x0c, 0x5d, 0x69, 0x6e, 0x6e, 0x49, 0x67, 0x73, 0x0c, 0x46, 0x6f, 0x72, 0x0c, 0x4b, 0x6e, 0x7e,
            0x66, 0x43, 0x68, 0x65, 0x61, 0x7e, 0x0c, 0x53, 0x7d, 0x73, 0x7e, 0x65, 0x6d, 0x0c, 0x3d, 0x0c, 0x1f, 0x1c};
    const char g_xorKey[] = "a_very_secret_random_key";

    std::string key;
    key.reserve(sizeof(g_encryptedPublicKey));
    for (size_t i = 0; i < sizeof(g_encryptedPublicKey); ++i)
    {
        key += g_encryptedPublicKey[i] ^ g_xorKey[i % (sizeof(g_xorKey) - 1)];
    }
    return key;
}

bool CheatConfigManager::VerifySignature(const anti_cheat::ClientConfig& config) const
{
    if (!config.has_config_signature())
        return false;

    std::string signature = config.config_signature();

    // 创建一个不包含签名的副本用于哈希计算
    anti_cheat::ClientConfig config_copy = config;
    config_copy.clear_config_signature();

    std::string serialized_data;
    if (!config_copy.SerializeToString(&serialized_data))
    {
        return false;
    }

    // 在实际应用中，这里会用公钥解密签名，或者用公钥验证哈希
    // 此处我们模拟：服务器计算 hash(config_data + private_key), 客户端计算 hash(config_data + public_key)
    // 这是一个简化的对称模拟，真实场景应为非对称
    std::string expected_hash = CalculateHash(serialized_data + GetServerPublicKey());

    return signature == expected_hash;
}

std::string CheatConfigManager::CalculateHash(const std::string& data) const
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    std::string hashResult;
    std::vector<BYTE> hashBuffer;

    // 1. 获取加密服务提供程序(CSP)的句柄。
    // PROV_RSA_AES 在 Windows XP SP2 及以上版本可用，并支持 SHA-1。
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        goto cleanup;
    }

    // 2. 创建一个哈希对象。
    if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash))
    {
        goto cleanup;
    }

    // 3. 对数据进行哈希计算。
    if (!CryptHashData(hHash, (const BYTE*)data.c_str(), data.length(), 0))
    {
        goto cleanup;
    }

    // 4. 获取哈希值。
    DWORD cbHash = 0;
    DWORD cbData = sizeof(DWORD);
    if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&cbHash, &cbData, 0))
    {
        goto cleanup;
    }

    hashBuffer.resize(cbHash);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hashBuffer.data(), &cbHash, 0))
    {
        goto cleanup;
    }

    hashResult.assign(reinterpret_cast<char*>(hashBuffer.data()), hashBuffer.size());

cleanup:
    if (hHash)
        CryptDestroyHash(hHash);
    if (hProv)
        CryptReleaseContext(hProv, 0);
    return hashResult;
}