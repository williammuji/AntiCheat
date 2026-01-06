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
int32_t CheatConfigManager::GetReportCooldownMinutes() const
{
    return GetCurrentConfig()->config->report_cooldown_minutes();
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

// --- 容量与缓存控制 ---
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

// --- 输入自动化检测参数 (已删除，保留函数以兼容性) ---
// 这些函数已经在上面定义过了，这里删除重复定义

// --- 输入自动化检测参数 (已删除，保留函数以兼容性) ---

// --- 新增的Getters ---

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

int32_t CheatConfigManager::GetMaxPidAttemptsPerScan() const
{
    return GetCurrentConfig()->config->max_pid_attempts_per_scan();
}

int32_t CheatConfigManager::GetMaxModulesPerScan() const
{
    return GetCurrentConfig()->config->max_modules_per_scan();
}

int32_t CheatConfigManager::GetPidThrottleMinutes() const
{
    return GetCurrentConfig()->config->pid_throttle_minutes();
}

// [新增] 快照上报配置
int32_t CheatConfigManager::GetSnapshotUploadIntervalMinutes() const
{
    return GetCurrentConfig()->config->snapshot_upload_interval_minutes();
}

bool CheatConfigManager::IsSnapshotUploadEnabled() const
{
    return GetCurrentConfig()->config->enable_snapshot_upload();
}

// --- 模块完整性检测白名单 ---
std::shared_ptr<const std::vector<std::wstring>> CheatConfigManager::GetWhitelistedIntegrityDirs() const
{
    auto config = GetCurrentConfig();
    return std::shared_ptr<const std::vector<std::wstring>>(config, &config->whitelistedIntegrityDirs_w);
}

std::shared_ptr<const std::vector<std::wstring>> CheatConfigManager::GetWhitelistedIntegrityFiles() const
{
    auto config = GetCurrentConfig();
    return std::shared_ptr<const std::vector<std::wstring>>(config, &config->whitelistedIntegrityFiles_w);
}

// --- 私有辅助函数 ---

void CheatConfigManager::SetDefaultValues(ConfigData& configData)
{
    // 生产环境优化：调整扫描和上报间隔，平衡性能与安全
    configData.config->set_base_scan_interval_seconds(15);            // 轻量级扫描间隔15秒 (高频监测)
    configData.config->set_heavy_scan_interval_minutes(2);            // 重量级扫描间隔2分钟 (CPU低负载)
    configData.config->set_report_upload_interval_minutes(10);        // 证据上报间隔10分钟 (快速响应)
    configData.config->set_sensor_stats_upload_interval_minutes(60);  // 传感器统计上报间隔60分钟

    // 1. 有害进程名 (Harmful Process Names)
    configData.config->clear_harmful_process_names();
    // 调试器 (Debuggers)
    configData.config->add_harmful_process_names("ollydbg");
    configData.config->add_harmful_process_names("ollyice");
    configData.config->add_harmful_process_names("x64dbg");
    configData.config->add_harmful_process_names("x32dbg");
    configData.config->add_harmful_process_names("windbg");
    configData.config->add_harmful_process_names("immunitydebugger");
    configData.config->add_harmful_process_names("dnspy");
    configData.config->add_harmful_process_names("reflexil");
    configData.config->add_harmful_process_names("ollyice.exe");
    configData.config->add_harmful_process_names("x64dbg.exe");
    configData.config->add_harmful_process_names("x32dbg.exe");
    // 逆向工程 (Reverse Engineering)
    configData.config->add_harmful_process_names("ida64");
    configData.config->add_harmful_process_names("ida");
    configData.config->add_harmful_process_names("ghidra");
    configData.config->add_harmful_process_names("binaryninja");
    // 内存修改 (Memory Editors)
    configData.config->add_harmful_process_names("cheatengine");
    configData.config->add_harmful_process_names("cheatengine-x86_64");
    configData.config->add_harmful_process_names("cheatengine.exe");
    configData.config->add_harmful_process_names("artmoney");
    configData.config->add_harmful_process_names("artmoney.exe");
    configData.config->add_harmful_process_names("wemod");
    configData.config->add_harmful_process_names("wemod.exe");
    configData.config->add_harmful_process_names("memoryedit");
    configData.config->add_harmful_process_names("processtoolkit");
    configData.config->add_harmful_process_names("gameguardian");
    configData.config->add_harmful_process_names("scanmem");
    // 网络抓包 (Packet Sniffers)
    configData.config->add_harmful_process_names("fiddler");
    configData.config->add_harmful_process_names("wireshark");
    configData.config->add_harmful_process_names("charles");
    // 国内常见工具/模拟器
    configData.config->add_harmful_process_names("anjianjingling");
    configData.config->add_harmful_process_names("ajjl");
    configData.config->add_harmful_process_names("guaji");
    configData.config->add_harmful_process_names("fuzhu");
    configData.config->add_harmful_process_names("xiugaiqi");
    configData.config->add_harmful_process_names("ydark");
    configData.config->add_harmful_process_names("duniu");
    configData.config->add_harmful_process_names("dnplayer");
    configData.config->add_harmful_process_names("ldplayer");
    configData.config->add_harmful_process_names("bluestacks");
    configData.config->add_harmful_process_names("bstweaker");
    configData.config->add_harmful_process_names("mumu");
    configData.config->add_harmful_process_names("nemuplayerui");
    configData.config->add_harmful_process_names("nox");
    configData.config->add_harmful_process_names("noxplayer");
    configData.config->add_harmful_process_names("xiaoyao");
    configData.config->add_harmful_process_names("microvirt");
    configData.config->add_harmful_process_names("memu");
    // 其他作弊工具
    configData.config->add_harmful_process_names("gameassistant");
    configData.config->add_harmful_process_names("autohotkey");
    configData.config->add_harmful_process_names("ahk");
    configData.config->add_harmful_process_names("autoit3");
    // 进程分析工具
    configData.config->add_harmful_process_names("procexp");
    configData.config->add_harmful_process_names("procexp64");
    configData.config->add_harmful_process_names("procexp.exe");
    configData.config->add_harmful_process_names("prochacker");
    configData.config->add_harmful_process_names("prochacker.exe");
    configData.config->add_harmful_process_names("apimonitor");
    configData.config->add_harmful_process_names("apimonitor.exe");
    configData.config->add_harmful_process_names("regmon");
    configData.config->add_harmful_process_names("filemon");
    // 网络分析工具
    configData.config->add_harmful_process_names("netmon");
    configData.config->add_harmful_process_names("tcpview");
    configData.config->add_harmful_process_names("tcpview.exe");

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
    // IDEs & 开发者工具
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
    // 游戏平台
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
    configData.config->add_whitelisted_window_keywords("wegame");
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
    // 显卡驱动
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
    configData.config->add_whitelisted_veh_modules("gameoverlayrenderer64.dll");
    configData.config->add_whitelisted_veh_modules("discord_hook.dll");
    configData.config->add_whitelisted_veh_modules("rtsshooks64.dll");
    configData.config->add_whitelisted_veh_modules("wegame_helper.dll");
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
    // 系统服务进程
    configData.config->add_known_good_processes("taskhostw.exe");
    configData.config->add_known_good_processes("sppsvc.exe");
    configData.config->add_known_good_processes("tracker.exe");
    // 开发工具进程
    configData.config->add_known_good_processes("cl.exe");
    configData.config->add_known_good_processes("winmergeu.exe");
    // 第三方软件进程
    configData.config->add_known_good_processes("tqupdate.exe");
    configData.config->add_known_good_processes("ksnproxy.exe");
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
    configData.config->add_known_good_processes("ksafe.exe");
    // 游戏平台与通讯
    configData.config->add_known_good_processes("steam.exe");
    configData.config->add_known_good_processes("wegame.exe");
    configData.config->add_known_good_processes("rail.exe");
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
    configData.config->set_report_cooldown_minutes(10);  // 从60min减少到10min，允许更快上报不同作弊行为
    configData.config->set_jitter_milliseconds(2000);    // 从3000ms减少到2000ms，检测周期更紧凑

    // --- 容量与预算控制 ---
    configData.config->set_max_evidences_per_session(1024);

    // --- 容量与缓存控制 ---
    configData.config->set_process_cache_duration_minutes(30);    // 增加到30分钟，提高效率
    configData.config->set_signature_cache_duration_minutes(60);  // 保持60分钟

    // --- 签名验证节流控制默认值 ---
    configData.config->set_signature_verification_throttle_seconds(1);       // 减少到1秒节流
    configData.config->set_signature_verification_failure_throttle_ms(500);  // 减少到500毫秒节流

    // --- 安全与性能阈值 ---
    configData.config->set_max_veh_handlers_to_scan(32);

    // --- 通用配置参数（所有Sensor共用） ---
    configData.config->set_max_code_section_size(100 * 1024 * 1024);  // 最大代码节大小(100MB) - 覆盖大部分游戏模块
    configData.config->set_heavy_scan_budget_ms(
            2500);  // HEAVY级传感器预算(2500ms) - 为了允许扫描所有模块，增加预算

    // 注意：CRITICAL级传感器使用相同的heavy_scan_budget_ms，但通过分段扫描机制确保单次不超时
    // CRITICAL级传感器：ProcessHandle, ModuleIntegrity, ProcessAndWindowMonitor

    // [新增] MemorySecuritySensor配置参数 (HEAVY级 - 全量检测)
    configData.config->set_min_memory_region_size(64 * 1024);         // 最小内存区域大小(64KB - 覆盖中小型Shellcode)
    configData.config->set_max_memory_region_size(32 * 1024 * 1024);  // 最大内存区域大小(32MB - 覆盖大型注入模块)

    // [新增] ProcessAndWindowMonitorSensor配置参数 (CRITICAL级 - 分段扫描)
    configData.config->set_max_processes_to_scan(2000);  // 单次扫描进程数(2000个) - 优化后可覆盖绝大多数用户的所有进程
    configData.config->set_max_window_count(300);        // 最大窗口数量限制(300个) - 适应多窗口环境

    // [新增] ProcessHandleSensor配置参数 (CRITICAL级 - 分段扫描)
    configData.config->set_max_handle_scan_count(
            800000);                                   // 最大句柄扫描数量(800K) - 基于A/B测试，成功耗时仅116ms
    configData.config->set_initial_buffer_size_mb(16); // 初始缓冲区大小(16MB) - 增加以覆盖90k+句柄场景, 减少扩容
    configData.config->set_max_buffer_size_mb(64);     // 最大缓冲区大小(64MB) - 处理大量句柄场景
    configData.config->set_max_pid_attempts_per_scan(2000);  // 单次扫描最多尝试的新PID数量(2000个) - 性能富余，大幅增加覆盖率
    configData.config->set_max_modules_per_scan(512); // ModuleIntegritySensor单次扫描模块数(512个) - 尝试扫描所有模块
    configData.config->set_pid_throttle_minutes(30);  // PID节流时长(30分钟) - 避免重复扫描同一PID

    // 新增：最低OS版本要求
    configData.config->set_min_os_version(anti_cheat::OS_WIN10);  // 默认要求Windows 10+

    // 新增：快照上报配置
    configData.config->set_snapshot_upload_interval_minutes(30);  // 默认30分钟上报一次
    configData.config->set_enable_snapshot_upload(true);          // 默认启用快照上报

    // 新增：官方第三方库白名单配置
    configData.config->clear_trusted_third_party_modules();

    // 添加 fmodex.dll 配置
    auto* fmod_module = configData.config->add_trusted_third_party_modules();
    fmod_module->set_module_name("fmodex.dll");
    fmod_module->set_module_size(0);  // 0表示不检查大小
    fmod_module->add_code_hashes("sha256:placeholder_fmodex_hash");  // 实际部署时需要替换为真实哈希
    fmod_module->add_code_hashes("sha1:placeholder_fmodex_hash_sha1");  // Windows XP兼容
    fmod_module->set_description("FMOD音频引擎");
    fmod_module->set_enabled(true);

    // 添加 aksoundenginedll_d.dll 配置
    auto* ak_module = configData.config->add_trusted_third_party_modules();
    ak_module->set_module_name("aksoundenginedll_d.dll");
    ak_module->set_module_size(0);  // 0表示不检查大小
    ak_module->add_code_hashes("sha256:placeholder_ak_hash");  // 实际部署时需要替换为真实哈希
    ak_module->add_code_hashes("sha1:placeholder_ak_hash_sha1");  // Windows XP兼容
    ak_module->set_description("Audiokinetic Wwise音频引擎");
    ak_module->set_enabled(true);

    // [新增] 模块完整性检测白名单默认值
    configData.config->clear_whitelisted_integrity_dirs();
    configData.config->add_whitelisted_integrity_dirs("\\program files\\microsoft office\\");
    configData.config->add_whitelisted_integrity_dirs("\\program files (x86)\\microsoft office\\");
    configData.config->add_whitelisted_integrity_dirs("\\program files\\common files\\microsoft shared\\");
    configData.config->add_whitelisted_integrity_dirs("\\program files (x86)\\common files\\microsoft shared\\");
    configData.config->add_whitelisted_integrity_dirs("\\program files\\sangfor\\");
    configData.config->add_whitelisted_integrity_dirs("\\program files (x86)\\sangfor\\");
    configData.config->add_whitelisted_integrity_dirs("\\windows\\system32\\driverstore\\");
    configData.config->add_whitelisted_integrity_dirs("\\windows\\system32\\spool\\drivers\\");
    configData.config->add_whitelisted_integrity_dirs("\\program files\\bonjour\\");
    configData.config->add_whitelisted_integrity_dirs("\\program files (x86)\\bonjour\\");
    configData.config->add_whitelisted_integrity_dirs("\\program files\\norton internet security\\");
    configData.config->add_whitelisted_integrity_dirs("\\program files (x86)\\norton internet security\\");
    configData.config->add_whitelisted_integrity_dirs("\\windows\\syswow64\\macromed\\flash\\");

    configData.config->clear_whitelisted_integrity_files();
    configData.config->add_whitelisted_integrity_files("gameoverlayrenderer.dll");
    configData.config->add_whitelisted_integrity_files("gameoverlayrenderer64.dll");
    configData.config->add_whitelisted_integrity_files("discord_hook.dll");
    configData.config->add_whitelisted_integrity_files("discord_hook64.dll");
    configData.config->add_whitelisted_integrity_files("rtsshooks.dll");
    configData.config->add_whitelisted_integrity_files("rtsshooks64.dll");
    configData.config->add_whitelisted_integrity_files("wegame_helper.dll");

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
    convert_to_vector(configData.config->whitelisted_integrity_dirs(), configData.whitelistedIntegrityDirs_w);
    convert_to_vector(configData.config->whitelisted_integrity_files(), configData.whitelistedIntegrityFiles_w);

    // 更新官方第三方库白名单缓存
    configData.trustedThirdPartyModules.clear();
    configData.trustedThirdPartyModules.reserve(configData.config->trusted_third_party_modules_size());

    for (const auto& proto_module : configData.config->trusted_third_party_modules())
    {
        TrustedThirdPartyModule module;
        module.module_name = Utils::StringToWide(proto_module.module_name());
        module.module_size = proto_module.module_size();
        module.code_hashes.reserve(proto_module.code_hashes_size());
        for (const auto& hash : proto_module.code_hashes())
        {
            module.code_hashes.push_back(hash);
        }
        module.description = proto_module.description();
        module.enabled = proto_module.enabled();

        configData.trustedThirdPartyModules.push_back(std::move(module));
    }

    // 简化版：无禁用名单
}

// --- 安全相关函数 ---
// 客户端不再本地验证配置签名，依赖传输层加密与服务端鉴权

// --- 官方第三方库白名单相关方法 ---

std::shared_ptr<const std::vector<CheatConfigManager::TrustedThirdPartyModule>> CheatConfigManager::GetTrustedThirdPartyModules() const
{
    auto config = GetCurrentConfig();
    return std::shared_ptr<const std::vector<TrustedThirdPartyModule>>(config, &config->trustedThirdPartyModules);
}

bool CheatConfigManager::IsTrustedThirdPartyModule(const std::wstring& module_name, uint64_t module_size, const std::string& code_hash) const
{
    auto trusted_modules = GetTrustedThirdPartyModules();

    // 转换模块名为小写进行比较（不区分大小写）
    std::wstring module_name_lower = module_name;
    std::transform(module_name_lower.begin(), module_name_lower.end(), module_name_lower.begin(), ::towlower);

    for (const auto& trusted_module : *trusted_modules)
    {
        // 检查是否启用
        if (!trusted_module.enabled)
        {
            continue;
        }

        // 检查模块名（不区分大小写）
        std::wstring trusted_name_lower = trusted_module.module_name;
        std::transform(trusted_name_lower.begin(), trusted_name_lower.end(), trusted_name_lower.begin(), ::towlower);

        if (module_name_lower != trusted_name_lower)
        {
            continue;
        }

        // 检查模块大小（如果配置了大小检查）
        if (trusted_module.module_size != 0 && module_size != trusted_module.module_size)
        {
            continue;
        }

        // 检查代码哈希
        for (const auto& trusted_hash : trusted_module.code_hashes)
        {
            if (code_hash == trusted_hash)
            {
                return true;  // 找到匹配的哈希
            }
        }
    }

    return false;  // 未找到匹配的可信第三方模块
}
