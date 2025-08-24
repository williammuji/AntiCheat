#include "CheatConfigManager.h"
#include "CheatMonitor.h"  // 为了访问 Utils::StringToWide 和通知 CheatMonitor
#include <stdexcept>
#include <algorithm>  // for std::replace
#include <Windows.h>
#include <memory>      // for std::shared_ptr
#include <ShlObj.h>    // For SHGetFolderPathW

 

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
    // 在构造函数中直接调用，以确保默认配置在启动时就绪
    SetDefaultValues(*m_configData);
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

// --- 新增的Getters ---

double CheatConfigManager::GetMouseClickStddevThreshold() const
{
    return GetCurrentConfig()->config->mouse_click_stddev_threshold();
}

int32_t CheatConfigManager::GetMouseMoveCollinearThreshold() const
{
    return GetCurrentConfig()->config->mouse_move_collinear_threshold();
}

int32_t CheatConfigManager::GetMaxVehHandlersToScan() const
{
    return GetCurrentConfig()->config->max_veh_handlers_to_scan();
}

int32_t CheatConfigManager::GetMaxHandlesToScan() const
{
    return GetCurrentConfig()->config->max_handles_to_scan();
}

bool CheatConfigManager::IsVehScanEnabled() const
{
    return GetCurrentConfig()->config->enable_veh_scan();
}

bool CheatConfigManager::IsHandleScanEnabled() const
{
    return GetCurrentConfig()->config->enable_handle_scan();
}

anti_cheat::OsMinimum CheatConfigManager::GetMinOs() const
{
    return GetCurrentConfig()->config->min_os();
}

std::string CheatConfigManager::GetRolloutGroup() const
{
    return GetCurrentConfig()->config->rollout_group();
}

// --- 私有辅助函数 ---

void CheatConfigManager::SetDefaultValues(ConfigData& configData)
{
    // 这些值应该与你之前在 Pimpl 中的硬编码值一致
    configData.config->set_base_scan_interval_seconds(15);
    configData.config->set_heavy_scan_interval_minutes(15);
    configData.config->set_report_upload_interval_minutes(15);

    // 1. 有害进程名 (Harmful Process Names)
    configData.config->clear_harmful_process_names();
    // 调试器 (Debuggers)
    configData.config->add_harmful_process_names("ollydbg");
    configData.config->add_harmful_process_names("ollyice");
    configData.config->add_harmful_process_names("x64dbg");
    configData.config->add_harmful_process_names("x32dbg");
    configData.config->add_harmful_process_names("windbg");
    configData.config->add_harmful_process_names("immunitydebugger");
    // 逆向工程 (Reverse Engineering)
    configData.config->add_harmful_process_names("ida64");
    configData.config->add_harmful_process_names("ida");
    configData.config->add_harmful_process_names("ghidra");
    configData.config->add_harmful_process_names("binaryninja");
    // 内存修改 (Memory Editors)
    configData.config->add_harmful_process_names("cheatengine");
    configData.config->add_harmful_process_names("cheatengine-x86_64");
    configData.config->add_harmful_process_names("artmoney");
    configData.config->add_harmful_process_names("wemod");
    // 网络抓包 (Packet Sniffers)
    configData.config->add_harmful_process_names("fiddler");
    configData.config->add_harmful_process_names("wireshark");
    configData.config->add_harmful_process_names("charles");
    // 国内常见工具/模拟器 (China-Specific Tools/Emulators)
    configData.config->add_harmful_process_names("anjianjingling");  // 按键精灵
    configData.config->add_harmful_process_names("guaji");           // 挂机
    configData.config->add_harmful_process_names("fuzhu");           // 辅助
    configData.config->add_harmful_process_names("xiugaiqi");        // 修改器
    configData.config->add_harmful_process_names("ydark");           // 远控
    configData.config->add_harmful_process_names("duniu");           // 毒牛/雷电模拟器
    configData.config->add_harmful_process_names("dnplayer");        // 雷电模拟器
    configData.config->add_harmful_process_names("bsplayer");        // 蓝叠模拟器
    configData.config->add_harmful_process_names("mumu");            // 网易MUMU
    configData.config->add_harmful_process_names("nox");             // 夜神模拟器
    configData.config->add_harmful_process_names("xiaoyao");         // 逍遥模拟器

    // 2. 有害关键词 (Harmful Keywords)
    configData.config->clear_harmful_keywords();
    // 中文关键词
    configData.config->add_harmful_keywords("外挂");
    configData.config->add_harmful_keywords("辅助");
    configData.config->add_harmful_keywords("作弊");
    configData.config->add_harmful_keywords("修改器");
    configData.config->add_harmful_keywords("内存");
    configData.config->add_harmful_keywords("注入");
    configData.config->add_harmful_keywords("破解");
    configData.config->add_harmful_keywords("内购");
    configData.config->add_harmful_keywords("透视");
    configData.config->add_harmful_keywords("自瞄");
    configData.config->add_harmful_keywords("秒杀");
    configData.config->add_harmful_keywords("无敌");
    configData.config->add_harmful_keywords("飞天");
    configData.config->add_harmful_keywords("遁地");
    configData.config->add_harmful_keywords("吸怪");
    configData.config->add_harmful_keywords("免CD");
    configData.config->add_harmful_keywords("无CD");
    configData.config->add_harmful_keywords("脚本");
    configData.config->add_harmful_keywords("加速");
    configData.config->add_harmful_keywords("多开");
    configData.config->add_harmful_keywords("脱机");
    configData.config->add_harmful_keywords("按键精灵");
    configData.config->add_harmful_keywords("易语言");
    configData.config->add_harmful_keywords("游戏蜂窝");
    configData.config->add_harmful_keywords("GG修改器");
    configData.config->add_harmful_keywords("风灵月影");
    configData.config->add_harmful_keywords("小幸修改器");
    configData.config->add_harmful_keywords("模拟器");
    // 英文关键词
    configData.config->add_harmful_keywords("cheat engine");
    configData.config->add_harmful_keywords("memory editor");
    configData.config->add_harmful_keywords("hack");
    configData.config->add_harmful_keywords("bot");
    configData.config->add_harmful_keywords("macro");
    configData.config->add_harmful_keywords("trainer");
    configData.config->add_harmful_keywords("injector");
    configData.config->add_harmful_keywords("debugger");
    configData.config->add_harmful_keywords("aimbot");
    configData.config->add_harmful_keywords("wallhack");
    configData.config->add_harmful_keywords("esp");
    configData.config->add_harmful_keywords("speedhack");
    configData.config->add_harmful_keywords("wemod");

    // 3. 窗口白名单 (Whitelisted Window Keywords)
    configData.config->clear_whitelisted_window_keywords();
    // IDEs & 开发者工具
    configData.config->add_whitelisted_window_keywords("visual studio");
    configData.config->add_whitelisted_window_keywords("vs code");
    configData.config->add_whitelisted_window_keywords("jetbrains");
    configData.config->add_whitelisted_window_keywords("rider");
    // 国内常见通讯社交
    configData.config->add_whitelisted_window_keywords("discord");
    configData.config->add_whitelisted_window_keywords("微信");
    configData.config->add_whitelisted_window_keywords("qq");
    configData.config->add_whitelisted_window_keywords("tim");
    configData.config->add_whitelisted_window_keywords("钉钉");
    configData.config->add_whitelisted_window_keywords("腾讯会议");
    // 直播与录屏
    configData.config->add_whitelisted_window_keywords("obs");
    configData.config->add_whitelisted_window_keywords("streamlabs");
    configData.config->add_whitelisted_window_keywords("geforce experience");
    configData.config->add_whitelisted_window_keywords("斗鱼");
    configData.config->add_whitelisted_window_keywords("虎牙");
    configData.config->add_whitelisted_window_keywords("bilibili");
    configData.config->add_whitelisted_window_keywords("哔哩哔哩");
    // 常用工具与软件
    configData.config->add_whitelisted_window_keywords("wps");
    configData.config->add_whitelisted_window_keywords("有道");
    configData.config->add_whitelisted_window_keywords("百度网盘");
    configData.config->add_whitelisted_window_keywords("迅雷");
    configData.config->add_whitelisted_window_keywords("网易云音乐");
    configData.config->add_whitelisted_window_keywords("qq音乐");
    configData.config->add_whitelisted_window_keywords("酷狗音乐");
    configData.config->add_whitelisted_window_keywords("task manager");
    configData.config->add_whitelisted_window_keywords("process explorer");
    // 游戏平台
    configData.config->add_whitelisted_window_keywords("steam");
    configData.config->add_whitelisted_window_keywords("epic games");
    configData.config->add_whitelisted_window_keywords("ubisoft connect");
    configData.config->add_whitelisted_window_keywords("wegame");  // Tencent WeGame
    configData.config->add_whitelisted_window_keywords("chromium embedded framework");

    // 4. VEH模块白名单 (Whitelisted VEH Modules)
    configData.config->clear_whitelisted_veh_modules();
    // 显卡驱动
    configData.config->add_whitelisted_veh_modules("nvwgf2umx.dll");
    configData.config->add_whitelisted_veh_modules("nvd3dumx.dll");
    configData.config->add_whitelisted_veh_modules("amdvlk64.dll");
    configData.config->add_whitelisted_veh_modules("igd10iumd64.dll");
    // 游戏平台与覆盖
    configData.config->add_whitelisted_veh_modules("gameoverlayrenderer64.dll");  // Steam
    configData.config->add_whitelisted_veh_modules("discord_hook.dll");
    configData.config->add_whitelisted_veh_modules("rtsshooks64.dll");    // RivaTuner
    configData.config->add_whitelisted_veh_modules("wegame_helper.dll");  // WeGame
    // 输入法与安全软件
    configData.config->add_whitelisted_veh_modules("sogouimebroker.dll");
    configData.config->add_whitelisted_veh_modules("sogoucloud.dll");
    configData.config->add_whitelisted_veh_modules("qqpinyinbroker.dll");
    configData.config->add_whitelisted_veh_modules("360base.dll");
    configData.config->add_whitelisted_veh_modules("qqpcexternal.dll");

    // 5. 优良进程白名单 (Known Good Processes)
    configData.config->clear_known_good_processes();
    // Windows核心进程
    configData.config->add_known_good_processes("svchost.exe");
    configData.config->add_known_good_processes("csrss.exe");
    configData.config->add_known_good_processes("wininit.exe");
    configData.config->add_known_good_processes("winlogon.exe");
    configData.config->add_known_good_processes("services.exe");
    configData.config->add_known_good_processes("lsass.exe");
    configData.config->add_known_good_processes("explorer.exe");
    configData.config->add_known_good_processes("dwm.exe");
    // 国内常见输入法
    configData.config->add_known_good_processes("sogouinput.exe");
    configData.config->add_known_good_processes("qqpinyin.exe");
    configData.config->add_known_good_processes("msime.exe");
    configData.config->add_known_good_processes("ctfmon.exe");
    // 国内常见安全软件
    configData.config->add_known_good_processes("360safe.exe");
    configData.config->add_known_good_processes("360sd.exe");
    configData.config->add_known_good_processes("qqpctray.exe");
    configData.config->add_known_good_processes("huorong.exe");
    configData.config->add_known_good_processes("ksafe.exe");  // Kingsoft
    // 游戏平台与通讯
    configData.config->add_known_good_processes("steam.exe");
    configData.config->add_known_good_processes("wegame.exe");
    configData.config->add_known_good_processes("rail.exe");  // WeGame component
    configData.config->add_known_good_processes("discord.exe");
    configData.config->add_known_good_processes("yy.exe");
    configData.config->add_known_good_processes("qq.exe");
    configData.config->add_known_good_processes("wechat.exe");
    configData.config->add_known_good_processes("tim.exe");
    // 浏览器与常用软件
    configData.config->add_known_good_processes("chrome.exe");
    configData.config->add_known_good_processes("msedge.exe");
    configData.config->add_known_good_processes("firefox.exe");
    configData.config->add_known_good_processes("wps.exe");
    configData.config->add_known_good_processes("cloudmusic.exe");
    configData.config->add_known_good_processes("bilibili.exe");
    configData.config->add_known_good_processes("dingtalk.exe");

    configData.config->clear_whitelisted_process_paths();
    wchar_t path_buffer[MAX_PATH];
    auto add_whitelisted_directory = [&](int csidl) {
        if (SUCCEEDED(SHGetFolderPathW(NULL, csidl, NULL, 0, path_buffer)))
        {
            std::wstring p = path_buffer;
            std::transform(p.begin(), p.end(), p.begin(), ::towlower);
            if (!p.empty() && p.back() != L'\\')
            {
                p += L'\\';
            }
            configData.config->add_whitelisted_process_paths(Utils::WideToString(p));
        }
    };

    add_whitelisted_directory(CSIDL_SYSTEM);
    add_whitelisted_directory(CSIDL_PROGRAM_FILES);
    add_whitelisted_directory(CSIDL_PROGRAM_FILESX86);

    if (GetWindowsDirectoryW(path_buffer, MAX_PATH) > 0)
    {
        std::wstring p = path_buffer;
        std::transform(p.begin(), p.end(), p.begin(), ::towlower);
        if (!p.empty() && p.back() != L'\\')
        {
            p += L'\\';
        }
        configData.config->add_whitelisted_process_paths(Utils::WideToString(p));
    }

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
    configData.config->set_mouse_click_stddev_threshold(10.0);
    configData.config->set_mouse_move_collinear_threshold(15);

    // --- 安全与性能阈值 ---
    configData.config->set_max_veh_handlers_to_scan(32);
    configData.config->set_max_handles_to_scan(50000);

    configData.config->set_config_version("default_fallback_v1");

    // 新增：最低OS与传感器默认开关
    configData.config->set_min_os(anti_cheat::OS_WIN7_SP1); // 初期面向 Win7 SP1+
    configData.config->set_enable_veh_scan(true);
    configData.config->set_enable_handle_scan(true);
    // 灰度分组默认值，便于服务端按需分流
    configData.config->set_rollout_group("stable");

    // 不再在客户端生成/校验配置签名：配置下发已在传输层加密与鉴权

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
// 客户端不再本地验证配置签名，依赖传输层加密与服务端鉴权
