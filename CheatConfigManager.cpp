#include "CheatConfigManager.h"
#include "CheatMonitor.h"  // 为了访问 Utils::StringToWide
#include <fstream>
#include <filesystem>
#include <stdexcept>
#include <Wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")

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

CheatConfigManager::CheatConfigManager() : m_config(std::make_unique<anti_cheat::ClientConfig>())
{
    LoadConfigFromFile();
}

// --- 公共接口实现 ---

void CheatConfigManager::LoadConfigFromFile()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    std::wstring path = GetConfigFilePath();
    std::ifstream file(path, std::ios::binary);

    if (!file.is_open())
    {
        // 文件不存在，使用默认值并尝试创建缓存文件
        SetDefaultValues();
        std::string serialized_config;
        if (m_config->SerializeToString(&serialized_config))
        {
            std::string encrypted_data = EncryptData(serialized_config);
            if (!encrypted_data.empty())
            {
                // 确保目录存在
                std::filesystem::path fs_path(path);
                if (!std::filesystem::exists(fs_path.parent_path()))
                {
                    std::filesystem::create_directories(fs_path.parent_path());
                }
                std::ofstream outfile(path, std::ios::binary);
                outfile.write(encrypted_data.c_str(), encrypted_data.size());
            }
        }
        return;
    }

    std::string encrypted_data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();

    if (encrypted_data.empty())
    {
        SetDefaultValues();
        return;
    }

    std::string decrypted_data = DecryptData(encrypted_data);
    if (decrypted_data.empty())
    {
        // 解密失败，可能文件损坏或来自不同机器
        SetDefaultValues();
        return;
    }

    auto new_config = std::make_unique<anti_cheat::ClientConfig>();
    if (!new_config->ParseFromString(decrypted_data) || !VerifySignature(*new_config))
    {
        // 解析或验签失败，文件被篡改
        SetDefaultValues();
        return;
    }

    // 一切正常，替换当前配置
    m_config = std::move(new_config);
    UpdateWideStringCaches();
}

void CheatConfigManager::UpdateConfigFromServer(const std::string& server_data)
{
    auto new_config = std::make_unique<anti_cheat::ClientConfig>();
    if (!new_config->ParseFromString(server_data))
    {
        // Log error: "Failed to parse server config"
        return;
    }

    if (!VerifySignature(*new_config))
    {
        // Log error: "Server config signature verification failed"
        return;
    }

    std::lock_guard<std::mutex> lock(m_mutex);
    m_config = std::move(new_config);
    UpdateWideStringCaches();

    // 将新配置加密并写入本地缓存
    std::string encrypted_data = EncryptData(server_data);
    if (!encrypted_data.empty())
    {
        std::wstring path = GetConfigFilePath();
        // 确保目录存在
        std::filesystem::path fs_path(path);
        if (!std::filesystem::exists(fs_path.parent_path()))
        {
            std::filesystem::create_directories(fs_path.parent_path());
        }
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        file.write(encrypted_data.c_str(), encrypted_data.size());
    }
}

// --- Getters ---

int32_t CheatConfigManager::GetBaseScanInterval() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config->base_scan_interval_seconds();
}

int32_t CheatConfigManager::GetHeavyScanIntervalMinutes() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config->heavy_scan_interval_minutes();
}

int32_t CheatConfigManager::GetReportUploadIntervalMinutes() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config->report_upload_interval_minutes();
}

const std::vector<std::wstring>& CheatConfigManager::GetHarmfulProcessNames() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_harmfulProcessNames_w;
}

const std::vector<std::wstring>& CheatConfigManager::GetHarmfulKeywords() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_harmfulKeywords_w;
}

const std::unordered_set<std::wstring>& CheatConfigManager::GetWhitelistedVEHModules() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_whitelistedVEHModules_w;
}

const std::unordered_set<std::wstring>& CheatConfigManager::GetWhitelistedProcessPaths() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_whitelistedProcessPaths_w;
}

const std::unordered_set<std::wstring>& CheatConfigManager::GetWhitelistedWindowKeywords() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_whitelistedWindowKeywords_w;
}

const std::unordered_set<std::wstring>& CheatConfigManager::GetKnownGoodProcesses() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_knownGoodProcesses_w;
}

// --- 行为控制参数 ---
int32_t CheatConfigManager::GetSuspiciousHandleTTLMinutes() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config->suspicious_handle_ttl_minutes();
}
int32_t CheatConfigManager::GetReportCooldownMinutes() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config->report_cooldown_minutes();
}
int32_t CheatConfigManager::GetIllegalCallReportCooldownMinutes() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config->illegal_call_report_cooldown_minutes();
}
int32_t CheatConfigManager::GetJitterMilliseconds() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config->jitter_milliseconds();
}

// --- 容量与预算控制 ---
int32_t CheatConfigManager::GetMaxEvidencesPerSession() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config->max_evidences_per_session();
}
int32_t CheatConfigManager::GetMaxIllegalSources() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config->max_illegal_sources();
}
int32_t CheatConfigManager::GetLightScanBudgetMs() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config->light_scan_budget_ms();
}
int32_t CheatConfigManager::GetHeavyScanBudgetMs() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config->heavy_scan_budget_ms();
}

// --- 容量与缓存控制 ---
int32_t CheatConfigManager::GetMaxMouseMoveEvents() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config->max_mouse_move_events();
}
int32_t CheatConfigManager::GetMaxMouseClickEvents() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config->max_mouse_click_events();
}
int32_t CheatConfigManager::GetMaxKeyboardEvents() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config->max_keyboard_events();
}
int32_t CheatConfigManager::GetProcessCacheDurationMinutes() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config->process_cache_duration_minutes();
}
int32_t CheatConfigManager::GetSignatureCacheDurationMinutes() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config->signature_cache_duration_minutes();
}

// --- 输入自动化检测参数 ---
int32_t CheatConfigManager::GetKeyboardMacroMinSequenceLength() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config->keyboard_macro_min_sequence_length();
}
int32_t CheatConfigManager::GetKeyboardMacroMinPatternLength() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config->keyboard_macro_min_pattern_length();
}

// --- 私有辅助函数 ---

void CheatConfigManager::SetDefaultValues()
{
    // 这些值应该与你之前在 Pimpl 中的硬编码值一致
    m_config->set_base_scan_interval_seconds(15);
    m_config->set_heavy_scan_interval_minutes(120);
    m_config->set_report_upload_interval_minutes(15);

    m_config->clear_harmful_process_names();
    m_config->add_harmful_process_names("cheatengine");
    m_config->add_harmful_process_names("ollydbg");
    m_config->add_harmful_process_names("x64dbg");
    m_config->add_harmful_process_names("ida64");
    m_config->add_harmful_process_names("fiddler");

    m_config->clear_harmful_keywords();
    m_config->add_harmful_keywords("外挂");
    m_config->add_harmful_keywords("辅助");
    m_config->add_harmful_keywords("cheat engine");
    m_config->add_harmful_keywords("memory editor");

    m_config->clear_whitelisted_window_keywords();
    m_config->add_whitelisted_window_keywords(Utils::WideToString(L"visual studio"));
    m_config->add_whitelisted_window_keywords(Utils::WideToString(L"obs"));
    m_config->add_whitelisted_window_keywords(Utils::WideToString(L"discord"));

    m_config->clear_known_good_processes();
    m_config->add_known_good_processes("explorer.exe");
    m_config->add_known_good_processes("svchost.exe");
    m_config->add_known_good_processes("lsass.exe");
    m_config->add_known_good_processes("wininit.exe");
    m_config->add_known_good_processes("services.exe");
    m_config->add_known_good_processes("sogoucloud.exe");
    m_config->add_known_good_processes("sogouinput.exe");
    m_config->add_known_good_processes("qqpinyin.exe");
    m_config->add_known_good_processes("msime.exe");
    m_config->add_known_good_processes("chsime.exe");
    m_config->add_known_good_processes("nvcontainer.exe");
    m_config->add_known_good_processes("nvidia share.exe");
    m_config->add_known_good_processes("amdow.exe");
    m_config->add_known_good_processes("radeonsoftware.exe");
    m_config->add_known_good_processes("yy.exe");
    m_config->add_known_good_processes("yylive.exe");
    m_config->add_known_good_processes("qt.exe");
    m_config->add_known_good_processes("360safe.exe");
    m_config->add_known_good_processes("360sd.exe");
    m_config->add_known_good_processes("qqpctray.exe");
    m_config->add_known_good_processes("huorong.exe");
    m_config->add_known_good_processes("wspsafesvc.exe");

    // --- 行为控制参数 ---
    m_config->set_suspicious_handle_ttl_minutes(2);
    m_config->set_report_cooldown_minutes(30);
    m_config->set_illegal_call_report_cooldown_minutes(5);
    m_config->set_jitter_milliseconds(5000);

    // --- 容量与预算控制 ---
    m_config->set_max_evidences_per_session(512);
    m_config->set_max_illegal_sources(1024);
    m_config->set_light_scan_budget_ms(6000);
    m_config->set_heavy_scan_budget_ms(30000);

    // --- 容量与缓存控制 ---
    m_config->set_max_mouse_move_events(5000);
    m_config->set_max_mouse_click_events(500);
    m_config->set_max_keyboard_events(2048);
    m_config->set_process_cache_duration_minutes(15);
    m_config->set_signature_cache_duration_minutes(60);

    // --- 输入自动化检测参数 ---
    m_config->set_keyboard_macro_min_sequence_length(40);
    m_config->set_keyboard_macro_min_pattern_length(10);

    m_config->set_config_version("default_fallback_v1");

    // 为默认配置生成一个“签名”
    std::string serialized_config;
    m_config->SerializeToString(&serialized_config);
    m_config->set_config_signature(CalculateHash(serialized_config + GetServerPublicKey()));

    UpdateWideStringCaches();
}

void CheatConfigManager::UpdateWideStringCaches()
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

    convert_to_vector(m_config->harmful_process_names(), m_harmfulProcessNames_w);
    convert_to_vector(m_config->harmful_keywords(), m_harmfulKeywords_w);
    convert_to_set(m_config->whitelisted_veh_modules(), m_whitelistedVEHModules_w);
    convert_to_set(m_config->whitelisted_process_paths(), m_whitelistedProcessPaths_w);
    convert_to_set(m_config->whitelisted_window_keywords(), m_whitelistedWindowKeywords_w);
    convert_to_set(m_config->known_good_processes(), m_knownGoodProcesses_w);
}

std::wstring CheatConfigManager::GetConfigFilePath() const
{
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(NULL, path, MAX_PATH);
    std::filesystem::path exePath(path);
    // 在可执行文件目录下创建一个不易读的路径
    return exePath.parent_path() / L"dat" / L"bin" / L"cfg.dat";
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

std::string CheatConfigManager::EncryptData(const std::string& plain_text) const
{
    DATA_BLOB in;
    DATA_BLOB out;
    in.pbData = (BYTE*)plain_text.c_str();
    in.cbData = plain_text.length();
    // 转换为窄字符
    std::wstring wdesc = L"AntiCheatConfig";
    std::string desc = Utils::WideToString(wdesc);  // 使用现有工具函数
    if (CryptProtectData(&in, wdesc.c_str(), NULL, NULL, NULL, CRYPTPROTECT_LOCAL_MACHINE, &out))
    {
        std::string result(reinterpret_cast<char*>(out.pbData), out.cbData);
        LocalFree(out.pbData);
        return result;
    }
    return "";
}

std::string CheatConfigManager::DecryptData(const std::string& cipher_text) const
{
    DATA_BLOB in;
    DATA_BLOB out;
    in.pbData = (BYTE*)cipher_text.c_str();
    in.cbData = cipher_text.length();

    if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, CRYPTPROTECT_LOCAL_MACHINE, &out))
    {
        std::string result(reinterpret_cast<char*>(out.pbData), out.cbData);
        LocalFree(out.pbData);
        return result;
    }
    return "";
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
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status;
    std::string hashResult;
    std::vector<BYTE> hashBuffer;

    // 打开算法句柄
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status < 0)
        goto cleanup;

    // 创建哈希对象
    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
    if (status < 0)
        goto cleanup;

    // 哈希数据
    status = BCryptHashData(hHash, (PBYTE)data.c_str(), data.length(), 0);
    if (status < 0)
        goto cleanup;

    // 获取哈希值长度
    DWORD cbHash;
    DWORD cbData;
    status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0);
    if (status < 0)
        goto cleanup;

    hashBuffer.resize(cbHash);
    status = BCryptFinishHash(hHash, hashBuffer.data(), cbHash, 0);
    if (status < 0)
        goto cleanup;

    hashResult.assign(reinterpret_cast<char*>(hashBuffer.data()), hashBuffer.size());

cleanup:
    if (hHash)
        BCryptDestroyHash(hHash);
    if (hAlg)
        BCryptCloseAlgorithmProvider(hAlg, 0);
    return hashResult;
}
