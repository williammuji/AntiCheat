#include "CheatConfigManager.h"
#include "CheatMonitor.h"  // 为了访问 Utils::StringToWide 和通知 CheatMonitor
#include <stdexcept>
#include <algorithm>  // for std::replace
#include <Windows.h>
#include <memory>    // for std::shared_ptr
#include <ShlObj.h>  // For SHGetFolderPathW

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
int32_t CheatConfigManager::GetSignatureVerificationThrottleSeconds() const
{
    return GetCurrentConfig()->config->signature_verification_throttle_seconds();
}
int32_t CheatConfigManager::GetSignatureVerificationFailureThrottleMs() const
{
    return GetCurrentConfig()->config->signature_verification_failure_throttle_ms();
}

// --- 输入自动化检测参数 ---
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

int32_t CheatConfigManager::GetKeyboardMacroMinSequenceLength() const
{
    return GetCurrentConfig()->config->keyboard_macro_min_sequence_length();
}

int32_t CheatConfigManager::GetKeyboardMacroMinPatternLength() const
{
    return GetCurrentConfig()->config->keyboard_macro_min_pattern_length();
}

double CheatConfigManager::GetMouseClickStddevThreshold() const
{
    return GetCurrentConfig()->config->mouse_click_stddev_threshold();
}

int32_t CheatConfigManager::GetMouseMoveCollinearThreshold() const
{
    return GetCurrentConfig()->config->mouse_move_collinear_threshold();
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

int32_t CheatConfigManager::GetMaxCodeSectionSize() const
{
    return GetCurrentConfig()->config->max_code_section_size();
}

anti_cheat::OsVersion CheatConfigManager::GetMinOsVersion() const
{
    // 直接返回配置的OS版本要求
    return GetCurrentConfig()->config->min_os_version();
}

std::string CheatConfigManager::GetMinOsVersionName() const
{
    auto osVersion = GetCurrentConfig()->config->min_os_version();
    switch (osVersion)
    {
        case anti_cheat::OS_ANY:
            return "所有版本";
        case anti_cheat::OS_WIN_XP:
            return "Windows XP及以上";
        case anti_cheat::OS_WIN7_SP1:
            return "Windows 7 SP1及以上";
        case anti_cheat::OS_WIN10:
            return "Windows 10及以上";
        default:
            return "未知版本";
    }
}

// 通用配置参数（所有Sensor共用）
int32_t CheatConfigManager::GetSensorTimeoutMs() const
{
    return GetCurrentConfig()->config->sensor_timeout_ms();
}

int32_t CheatConfigManager::GetHeavyScanBudgetMs() const
{
    return GetCurrentConfig()->config->heavy_scan_budget_ms();
}

// [新增] PrivateExecutableMemorySensor配置参数getter
int32_t CheatConfigManager::GetMinMemoryRegionSize() const
{
    return GetCurrentConfig()->config->min_memory_region_size();
}

int32_t CheatConfigManager::GetMaxMemoryRegionSize() const
{
    return GetCurrentConfig()->config->max_memory_region_size();
}

// 移除maxScannedRegions相关配置，依赖budget_ms机制

// 删除不必要的数量限制和频率配置getter

// [新增] EnvironmentSensor配置参数getter
int32_t CheatConfigManager::GetMaxProcessesToScan() const
{
    return GetCurrentConfig()->config->max_processes_to_scan();
}

// [新增] 性能调优参数
int32_t CheatConfigManager::GetMaxWindowCount() const
{
    return GetCurrentConfig()->config->max_window_count();
}

int32_t CheatConfigManager::GetMaxHandleScanCount() const
{
    return GetCurrentConfig()->config->max_handle_scan_count();
}

int32_t CheatConfigManager::GetInitialBufferSizeMb() const
{
    return GetCurrentConfig()->config->initial_buffer_size_mb();
}

int32_t CheatConfigManager::GetMaxBufferSizeMb() const
{
    return GetCurrentConfig()->config->max_buffer_size_mb();
}

int32_t CheatConfigManager::GetSensorStatsUploadIntervalMinutes() const
{
    return GetCurrentConfig()->config->sensor_stats_upload_interval_minutes();
}

// --- 私有辅助函数 ---

void CheatConfigManager::SetDefaultValues(ConfigData& configData)
{
    // 生产环境优化：调整扫描和上报间隔，平衡性能与安全
    configData.config->set_base_scan_interval_seconds(45);             // 轻量级扫描间隔45秒
    configData.config->set_heavy_scan_interval_minutes(8);             // 重量级扫描间隔8分钟
    configData.config->set_report_upload_interval_minutes(30);         // 证据上报间隔30分钟
    configData.config->set_sensor_stats_upload_interval_minutes(120);  // 传感器统计上报间隔2小时

    // 1. 有害进程名 (Harmful Process Names)
    configData.config->clear_harmful_process_names();
    // 调试器 (Debuggers) - 补充常见调试器
    configData.config->add_harmful_process_names("ollydbg");
    configData.config->add_harmful_process_names("ollyice");
    configData.config->add_harmful_process_names("x64dbg");
    configData.config->add_harmful_process_names("x32dbg");
    configData.config->add_harmful_process_names("windbg");
    configData.config->add_harmful_process_names("immunitydebugger");
    configData.config->add_harmful_process_names("dnspy");        // .NET 反编译器/调试器
    configData.config->add_harmful_process_names("reflexil");     // .NET 字节码编辑器
    configData.config->add_harmful_process_names("ollyice.exe");  // 带扩展名
    configData.config->add_harmful_process_names("x64dbg.exe");   // 带扩展名
    configData.config->add_harmful_process_names("x32dbg.exe");   // 带扩展名
    // 逆向工程 (Reverse Engineering)
    configData.config->add_harmful_process_names("ida64");
    configData.config->add_harmful_process_names("ida");
    configData.config->add_harmful_process_names("ghidra");
    configData.config->add_harmful_process_names("binaryninja");
    // 内存修改 (Memory Editors) - 补充更多内存修改工具
    configData.config->add_harmful_process_names("cheatengine");
    configData.config->add_harmful_process_names("cheatengine-x86_64");
    configData.config->add_harmful_process_names("cheatengine.exe");  // 带扩展名
    configData.config->add_harmful_process_names("artmoney");
    configData.config->add_harmful_process_names("artmoney.exe");
    configData.config->add_harmful_process_names("wemod");
    configData.config->add_harmful_process_names("wemod.exe");
    configData.config->add_harmful_process_names("memoryedit");
    configData.config->add_harmful_process_names("processtoolkit");  // 进程工具包
    configData.config->add_harmful_process_names("gameguardian");    // 手机端知名工具
    configData.config->add_harmful_process_names("scanmem");         // Linux工具也防一下
    // 网络抓包 (Packet Sniffers)
    configData.config->add_harmful_process_names("fiddler");
    configData.config->add_harmful_process_names("wireshark");
    configData.config->add_harmful_process_names("charles");
    // 国内常见工具/模拟器 (China-Specific Tools/Emulators) - 大幅补充
    configData.config->add_harmful_process_names("anjianjingling");  // 按键精灵
    configData.config->add_harmful_process_names("ajjl");            // 按键精灵缩写
    configData.config->add_harmful_process_names("guaji");           // 挂机
    configData.config->add_harmful_process_names("fuzhu");           // 辅助
    configData.config->add_harmful_process_names("xiugaiqi");        // 修改器
    configData.config->add_harmful_process_names("ydark");           // 远控
    configData.config->add_harmful_process_names("duniu");           // 毒牛/雷电模拟器
    configData.config->add_harmful_process_names("dnplayer");        // 雷电模拟器
    configData.config->add_harmful_process_names("ldplayer");        // 雷电模拟器新版本
    configData.config->add_harmful_process_names("bsplayer");        // 蓝叠模拟器(误，实际是播放器)
    configData.config->add_harmful_process_names("bluestacks");      // 蓝叠模拟器正确名称
    configData.config->add_harmful_process_names("bstweaker");       // 蓝叠调优工具
    configData.config->add_harmful_process_names("mumu");            // 网易MUMU
    configData.config->add_harmful_process_names("nemuplayerui");    // MUMU模拟器
    configData.config->add_harmful_process_names("nox");             // 夜神模拟器
    configData.config->add_harmful_process_names("noxplayer");       // 夜神模拟器完整名
    configData.config->add_harmful_process_names("xiaoyao");         // 逍遥模拟器
    configData.config->add_harmful_process_names("microvirt");       // 逍遥模拟器进程
    configData.config->add_harmful_process_names("memu");            // 逍遥模拟器新版
    // 新增其他知名作弊工具
    configData.config->add_harmful_process_names("gameassistant");  // 游戏助手类
    configData.config->add_harmful_process_names("autohotkey");     // AHK自动化工具
    configData.config->add_harmful_process_names("ahk");            // AHK缩写
    configData.config->add_harmful_process_names("autoit3");        // AutoIt自动化
    // 专业进程分析工具
    configData.config->add_harmful_process_names("procexp");         // Process Explorer
    configData.config->add_harmful_process_names("procexp64");       // Process Explorer 64位
    configData.config->add_harmful_process_names("procexp.exe");     // Process Explorer带扩展名
    configData.config->add_harmful_process_names("prochacker");      // Process Hacker
    configData.config->add_harmful_process_names("prochacker.exe");  // Process Hacker带扩展名
    configData.config->add_harmful_process_names("apimonitor");      // API Monitor
    configData.config->add_harmful_process_names("apimonitor.exe");  // API Monitor带扩展名
    configData.config->add_harmful_process_names("regmon");          // Registry Monitor
    configData.config->add_harmful_process_names("filemon");         // File Monitor
    // 网络分析工具
    configData.config->add_harmful_process_names("netmon");       // Network Monitor
    configData.config->add_harmful_process_names("tcpview");      // TCPView
    configData.config->add_harmful_process_names("tcpview.exe");  // TCPView带扩展名
    // 注意：Python和AHK可能误杀合法开发者/用户，建议通过服务端配置控制
    // configData.config->add_harmful_process_names("python");      // Python脚本(风险高，可能误杀)
    // configData.config->add_harmful_process_names("py");          // Python简写(风险高，可能误杀)

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
    // 英文关键词 - 大幅补充
    configData.config->add_harmful_keywords("cheat engine");
    configData.config->add_harmful_keywords("memory editor");
    configData.config->add_harmful_keywords("hack");
    configData.config->add_harmful_keywords("hacker");
    configData.config->add_harmful_keywords("bot");
    configData.config->add_harmful_keywords("macro");
    configData.config->add_harmful_keywords("trainer");
    configData.config->add_harmful_keywords("injector");
    configData.config->add_harmful_keywords("injection");
    configData.config->add_harmful_keywords("dll inject");
    configData.config->add_harmful_keywords("code inject");
    configData.config->add_harmful_keywords("debugger");
    configData.config->add_harmful_keywords("aimbot");
    configData.config->add_harmful_keywords("wallhack");
    configData.config->add_harmful_keywords("esp");
    configData.config->add_harmful_keywords("speedhack");
    configData.config->add_harmful_keywords("speed hack");
    configData.config->add_harmful_keywords("wemod");
    configData.config->add_harmful_keywords("game trainer");
    configData.config->add_harmful_keywords("auto aim");
    configData.config->add_harmful_keywords("auto fire");
    configData.config->add_harmful_keywords("no recoil");
    configData.config->add_harmful_keywords("recoil control");
    configData.config->add_harmful_keywords("triggerbot");
    configData.config->add_harmful_keywords("radar hack");
    configData.config->add_harmful_keywords("map hack");
    configData.config->add_harmful_keywords("god mode");
    configData.config->add_harmful_keywords("infinite");
    configData.config->add_harmful_keywords("unlimited");
    configData.config->add_harmful_keywords("autohotkey");
    configData.config->add_harmful_keywords("automation");
    configData.config->add_harmful_keywords("script kiddie");
    // MMORPG特色作弊关键词
    configData.config->add_harmful_keywords("speed hack");
    configData.config->add_harmful_keywords("no clip");
    configData.config->add_harmful_keywords("fly hack");
    configData.config->add_harmful_keywords("teleport");
    configData.config->add_harmful_keywords("item dupe");
    configData.config->add_harmful_keywords("gold hack");
    configData.config->add_harmful_keywords("exp hack");
    configData.config->add_harmful_keywords("level hack");
    configData.config->add_harmful_keywords("skill hack");
    configData.config->add_harmful_keywords("cooldown hack");
    configData.config->add_harmful_keywords("mana hack");
    configData.config->add_harmful_keywords("health hack");
    configData.config->add_harmful_keywords("stamina hack");
    configData.config->add_harmful_keywords("auto farm");
    configData.config->add_harmful_keywords("auto quest");
    configData.config->add_harmful_keywords("auto combat");
    configData.config->add_harmful_keywords("auto loot");
    configData.config->add_harmful_keywords("auto trade");
    configData.config->add_harmful_keywords("auto skill");
    configData.config->add_harmful_keywords("auto potion");
    configData.config->add_harmful_keywords("auto revive");
    configData.config->add_harmful_keywords("auto follow");
    configData.config->add_harmful_keywords("auto attack");
    configData.config->add_harmful_keywords("auto move");
    configData.config->add_harmful_keywords("auto collect");
    configData.config->add_harmful_keywords("auto sell");
    configData.config->add_harmful_keywords("auto buy");
    configData.config->add_harmful_keywords("auto craft");
    configData.config->add_harmful_keywords("auto repair");
    configData.config->add_harmful_keywords("auto upgrade");
    configData.config->add_harmful_keywords("auto enhance");
    configData.config->add_harmful_keywords("auto enchant");
    configData.config->add_harmful_keywords("auto socket");
    configData.config->add_harmful_keywords("auto gem");
    configData.config->add_harmful_keywords("auto pet");
    configData.config->add_harmful_keywords("auto mount");
    configData.config->add_harmful_keywords("auto guild");
    configData.config->add_harmful_keywords("auto party");
    configData.config->add_harmful_keywords("auto raid");
    configData.config->add_harmful_keywords("auto dungeon");
    configData.config->add_harmful_keywords("auto pvp");
    configData.config->add_harmful_keywords("auto arena");
    configData.config->add_harmful_keywords("auto battleground");
    configData.config->add_harmful_keywords("auto world boss");
    configData.config->add_harmful_keywords("auto event");
    configData.config->add_harmful_keywords("auto daily");
    configData.config->add_harmful_keywords("auto weekly");
    configData.config->add_harmful_keywords("auto monthly");
    configData.config->add_harmful_keywords("auto seasonal");
    configData.config->add_harmful_keywords("auto achievement");
    configData.config->add_harmful_keywords("auto collection");
    configData.config->add_harmful_keywords("auto exploration");
    configData.config->add_harmful_keywords("auto mining");
    configData.config->add_harmful_keywords("auto fishing");
    configData.config->add_harmful_keywords("auto cooking");
    configData.config->add_harmful_keywords("auto alchemy");
    configData.config->add_harmful_keywords("auto blacksmith");
    configData.config->add_harmful_keywords("auto tailor");
    configData.config->add_harmful_keywords("auto leatherwork");
    configData.config->add_harmful_keywords("auto engineering");
    configData.config->add_harmful_keywords("auto jewelcrafting");
    configData.config->add_harmful_keywords("auto inscription");
    configData.config->add_harmful_keywords("auto herbalism");
    configData.config->add_harmful_keywords("auto skinning");
    configData.config->add_harmful_keywords("auto archaeology");
    configData.config->add_harmful_keywords("auto first aid");
    configData.config->add_harmful_keywords("auto lockpicking");
    configData.config->add_harmful_keywords("auto pickpocket");
    configData.config->add_harmful_keywords("auto stealth");
    configData.config->add_harmful_keywords("auto camouflage");
    configData.config->add_harmful_keywords("auto invisibility");
    configData.config->add_harmful_keywords("auto ghost");
    configData.config->add_harmful_keywords("auto spirit");
    configData.config->add_harmful_keywords("auto phantom");
    configData.config->add_harmful_keywords("auto shadow");

    // 3. 窗口白名单 (Whitelisted Window Keywords)
    configData.config->clear_whitelisted_window_keywords();
    // IDEs & 开发者工具 - 补充更多开发工具
    configData.config->add_whitelisted_window_keywords("visual studio");
    configData.config->add_whitelisted_window_keywords("vs code");
    configData.config->add_whitelisted_window_keywords("vscode");
    configData.config->add_whitelisted_window_keywords("jetbrains");
    configData.config->add_whitelisted_window_keywords("rider");
    configData.config->add_whitelisted_window_keywords("intellij");
    configData.config->add_whitelisted_window_keywords("pycharm");
    configData.config->add_whitelisted_window_keywords("webstorm");
    configData.config->add_whitelisted_window_keywords("clion");
    configData.config->add_whitelisted_window_keywords("datagrip");
    configData.config->add_whitelisted_window_keywords("sublime text");
    configData.config->add_whitelisted_window_keywords("notepad++");
    configData.config->add_whitelisted_window_keywords("atom");
    configData.config->add_whitelisted_window_keywords("eclipse");
    configData.config->add_whitelisted_window_keywords("android studio");
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
    // 游戏平台 - 补充更多游戏平台
    configData.config->add_whitelisted_window_keywords("steam");
    configData.config->add_whitelisted_window_keywords("epic games");
    configData.config->add_whitelisted_window_keywords("epic games launcher");
    configData.config->add_whitelisted_window_keywords("ubisoft connect");
    configData.config->add_whitelisted_window_keywords("uplay");
    configData.config->add_whitelisted_window_keywords("origin");
    configData.config->add_whitelisted_window_keywords("ea desktop");
    configData.config->add_whitelisted_window_keywords("battle.net");
    configData.config->add_whitelisted_window_keywords("battlenet");
    configData.config->add_whitelisted_window_keywords("blizzard");
    configData.config->add_whitelisted_window_keywords("wegame");  // Tencent WeGame
    configData.config->add_whitelisted_window_keywords("xbox");
    configData.config->add_whitelisted_window_keywords("microsoft store");
    configData.config->add_whitelisted_window_keywords("gog galaxy");
    configData.config->add_whitelisted_window_keywords("rockstar games launcher");
    configData.config->add_whitelisted_window_keywords("chromium embedded framework");
    // 游戏开发工具
    configData.config->add_whitelisted_window_keywords("unity editor");
    configData.config->add_whitelisted_window_keywords("unreal editor");
    configData.config->add_whitelisted_window_keywords("godot");
    configData.config->add_whitelisted_window_keywords("blender");
    configData.config->add_whitelisted_window_keywords("maya");
    configData.config->add_whitelisted_window_keywords("3ds max");
    configData.config->add_whitelisted_window_keywords("cinema 4d");
    configData.config->add_whitelisted_window_keywords("houdini");
    configData.config->add_whitelisted_window_keywords("substance");
    configData.config->add_whitelisted_window_keywords("photoshop");
    configData.config->add_whitelisted_window_keywords("illustrator");
    configData.config->add_whitelisted_window_keywords("after effects");
    configData.config->add_whitelisted_window_keywords("premiere");
    configData.config->add_whitelisted_window_keywords("audacity");
    configData.config->add_whitelisted_window_keywords("fl studio");
    configData.config->add_whitelisted_window_keywords("cubase");
    configData.config->add_whitelisted_window_keywords("pro tools");
    // 直播平台
    configData.config->add_whitelisted_window_keywords("twitch");
    configData.config->add_whitelisted_window_keywords("youtube");
    configData.config->add_whitelisted_window_keywords("facebook gaming");
    configData.config->add_whitelisted_window_keywords("mixer");
    configData.config->add_whitelisted_window_keywords("trovo");
    configData.config->add_whitelisted_window_keywords("caffeine");
    configData.config->add_whitelisted_window_keywords("dlive");
    configData.config->add_whitelisted_window_keywords("periscope");
    configData.config->add_whitelisted_window_keywords("instagram live");
    configData.config->add_whitelisted_window_keywords("tiktok live");
    configData.config->add_whitelisted_window_keywords("douyin");
    configData.config->add_whitelisted_window_keywords("kuaishou");
    configData.config->add_whitelisted_window_keywords("huya");
    configData.config->add_whitelisted_window_keywords("douyu");
    configData.config->add_whitelisted_window_keywords("bilibili live");
    configData.config->add_whitelisted_window_keywords("kuaishou live");
    configData.config->add_whitelisted_window_keywords("huya live");
    configData.config->add_whitelisted_window_keywords("douyu live");

    // 4. VEH模块白名单 (Whitelisted VEH Modules)
    configData.config->clear_whitelisted_veh_modules();
    // 显卡驱动 - 补充更多显卡驱动和相关DLL
    configData.config->add_whitelisted_veh_modules("nvwgf2umx.dll");
    configData.config->add_whitelisted_veh_modules("nvd3dumx.dll");
    configData.config->add_whitelisted_veh_modules("nvoglv64.dll");
    configData.config->add_whitelisted_veh_modules("nvapi64.dll");
    configData.config->add_whitelisted_veh_modules("nvcuda.dll");
    configData.config->add_whitelisted_veh_modules("amdvlk64.dll");
    configData.config->add_whitelisted_veh_modules("amdxc64.dll");
    configData.config->add_whitelisted_veh_modules("atiumd64.dll");
    configData.config->add_whitelisted_veh_modules("igd10iumd64.dll");
    configData.config->add_whitelisted_veh_modules("igdmcl64.dll");
    configData.config->add_whitelisted_veh_modules("ig9icd64.dll");
    configData.config->add_whitelisted_veh_modules("ig4icd64.dll");
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
    configData.config->set_report_cooldown_minutes(60);  // 从30min增加到60min，避免上报风暴
    configData.config->set_jitter_milliseconds(3000);    // 从5s减少到3s，提高响应性

    // --- 容量与预算控制 ---
    configData.config->set_max_evidences_per_session(512);

    // --- 容量与缓存控制 ---
    configData.config->set_process_cache_duration_minutes(30);    // 增加到30分钟，提高效率
    configData.config->set_signature_cache_duration_minutes(60);  // 保持60分钟

    // --- 签名验证节流控制默认值 ---
    configData.config->set_signature_verification_throttle_seconds(1);       // 减少到1秒节流
    configData.config->set_signature_verification_failure_throttle_ms(500);  // 减少到500毫秒节流

    // --- 安全与性能阈值 ---
    configData.config->set_max_veh_handlers_to_scan(32);

    // --- 通用配置参数（所有Sensor共用） ---
    configData.config->set_max_code_section_size(50 * 1024 * 1024);  // 最大代码节大小(50MB)

    // [新增] MemorySecuritySensor配置参数
    configData.config->set_min_memory_region_size(4 * 1024);  // 最小内存区域大小(4KB)
    configData.config->set_max_memory_region_size(16 * 1024 *
                                                  1024);  // 最大内存区域大小(16MB)
                                                          // 移除maxScannedRegions相关配置，依赖budget_ms机制

    // [新增] EnvironmentSensor配置参数
    configData.config->set_max_processes_to_scan(1000);  // 最大进程扫描数量(1000个)

    // [新增] 性能调优参数
    configData.config->set_max_window_count(100);         // 最大窗口数量限制(100个)
    configData.config->set_max_handle_scan_count(50000);  // 最大句柄扫描数量(50K个)
    configData.config->set_initial_buffer_size_mb(1);     // 初始缓冲区大小(1MB)
    configData.config->set_max_buffer_size_mb(4);         // 最大缓冲区大小(4MB)

    // 新增：最低OS版本要求
    configData.config->set_min_os_version(anti_cheat::OS_WIN10);  // 默认要求Windows 10+

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
