#include "CheatMonitor.h"

#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <algorithm>
#include <cctype>
#include <Objbase.h>
#include <set> 
#include <intrin.h>
#include <array>
#include <filesystem>
#include <memory>
#include <numeric>

#include <Psapi.h>
#include <TlHelp32.h>
#include <Iphlpapi.h> // 为 GetAdaptersInfo 添加头文件
#include <wintrust.h> // 为 WinVerifyTrust 添加头文件
#include <Softpub.h> // 为 WINTRUST_ACTION_GENERIC_VERIFY_V2 GUID 添加头文件

#include <winternl.h> // 包含 NTSTATUS 等定义

#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib") // 为注册表函数 (Reg*) 添加库链接
#pragma comment(lib, "iphlpapi.lib") // 为 GetAdaptersInfo 添加库链接
#pragma comment(lib, "wintrust.lib") // 为 WinVerifyTrust 添加库链接

// --- 为 NtQuerySystemInformation 定义必要的结构体和类型 ---
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004L
#endif

const int SystemHandleInformation = 16;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS(WINAPI* PNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

// --- 为线程隐藏定义必要的结构体和类型 ---
typedef NTSTATUS(WINAPI* PNtSetInformationThread)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
    );

// [重构] 将函数指针定义为文件内静态变量，避免在多个函数中重复定义。
static const auto g_pNtQuerySystemInformation = reinterpret_cast<PNtQuerySystemInformation>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"));
static const auto g_pNtSetInformationThread = reinterpret_cast<PNtSetInformationThread>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationThread"));

// --- 为系统完整性检测定义必要的结构体 ---
// const int SystemCodeIntegrityInformation = 103;
typedef struct _SYSTEM_CODE_INTEGRITY_INFORMATION {
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SYSTEM_CODE_INTEGRITY_INFORMATION, *PSYSTEM_CODE_INTEGRITY_INFORMATION;

// --- 为内核调试器检测定义必要的结构体 ---
const int SystemKernelDebuggerInformation = 35;
typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION {
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

namespace Utils {
    std::string WideToString(const std::wstring& wstr) {
        if (wstr.empty()) return std::string();
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
        std::string strTo(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
        return strTo;
    }

    bool GetParentProcessInfo(DWORD& parentPid, std::string& parentName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(PROCESSENTRY32W);
        DWORD currentPid = GetCurrentProcessId();
        DWORD ppid = 0;
        if (Process32FirstW(hSnapshot, &pe)) {
            do {
                if (pe.th32ProcessID == currentPid) {
                    ppid = pe.th32ParentProcessID;
                    break;
                }
            } while (Process32NextW(hSnapshot, &pe));
        }
        if (ppid > 0) {
            if (Process32FirstW(hSnapshot, &pe)) {
                do {
                    if (pe.th32ProcessID == ppid) {
                        parentPid = ppid;
                        parentName = WideToString(pe.szExeFile);
                        CloseHandle(hSnapshot);
                        return true;
                    }
                } while (Process32NextW(hSnapshot, &pe));
            }
        }
        CloseHandle(hSnapshot);
        return false;
    }

    std::string GenerateUuid() {
        GUID guid;
        if (CoCreateGuid(&guid) == S_OK) {
            wchar_t uuid_w[40] = {0};
            StringFromGUID2(guid, uuid_w, 40);
            return WideToString(uuid_w);
        }
        return "";
    }

    struct EnumWindowsCallbackData {
        DWORD pid;
        std::vector<std::wstring> windowTitles;
    };

    BOOL CALLBACK EnumWindowsCallback(HWND hWnd, LPARAM lParam) {
        auto* pData = (EnumWindowsCallbackData*)lParam;
        DWORD processId = 0;
        GetWindowThreadProcessId(hWnd, &processId);
        if (pData->pid == processId && IsWindowVisible(hWnd)) {
            wchar_t buffer[256];
            if (GetWindowTextW(hWnd, buffer, ARRAYSIZE(buffer)) > 0) {
                pData->windowTitles.push_back(buffer);
            }
        }
        return TRUE;
    }
}

struct CheatMonitor::Pimpl {
    std::atomic<bool> m_isSystemActive = false;
    std::atomic<bool> m_isSessionActive = false;
    std::thread m_monitorThread;
    std::condition_variable m_cv;
    std::mutex m_cvMutex;

    std::mutex m_sessionMutex;
    uint32_t m_currentUserId = 0;
    std::string m_currentUserName;
    
    std::set<std::pair<anti_cheat::CheatCategory, std::string>> m_uniqueEvidence;
    std::vector<anti_cheat::Evidence> m_evidences;

    const std::vector<std::string> m_legitimateParentProcesses = {
        "yourlauncher.exe",     // 必须包含官方启动器! 请替换为真实名称 (小写)。
        "explorer.exe",         // Windows Shell
        "devenv.exe",           // Visual Studio
        "cmd.exe",              // 命令提示符
        "powershell.exe",       // PowerShell
        "Code.exe"              // Visual Studio Code
    };
    const std::vector<std::wstring> m_harmfulProcessNames = { 
        // 内存修改器 & 调试器
        L"cheatengine", L"ollydbg", L"x64dbg", L"x32dbg", L"ida64", L"ida", L"windbg",
        L"processhacker", L"artmoney", L"ghidra", L"reclass", L"reclass.net",
        // 网络抓包
        L"fiddler", L"wireshark", L"charles",
        // 自动化 & 宏
        L"autohotkey"
    };
    const std::vector<std::wstring> m_harmfulKeywords = { 
        // 中文
        L"外挂", L"辅助", L"脚本", L"注入", L"透视", L"自瞄", L"内存修改", L"调试", L"反汇编", L"吾爱破解",
        // 英文
        L"cheat engine", L"hack", L"trainer", L"bot", L"aimbot", L"wallhack", L"speedhack", 
        L"memory editor", L"debugger", L"disassembler", L"injector", L"packet editor"
    };
    // 使用 std::set 以获得更快的查找速度 (O(logN)) 并自动处理重复项
    std::set<DWORD> m_knownThreadIds;
    std::set<HMODULE> m_knownModules;
    //  硬件指纹信息，只在首次登录时收集一次
    std::unique_ptr<anti_cheat::HardwareFingerprint> m_fingerprint;
    std::unordered_set<std::wstring> m_legitimateModulePaths; // 使用哈希集合以实现O(1)复杂度的快速查找
    std::unordered_map<uintptr_t, std::chrono::steady_clock::time_point> m_reportedIllegalCallSources; // 用于记录已上报的非法调用来源，并实现5分钟上报冷却
    //  记录每个用户、每种作弊类型的最近上报时间，防止重复上报
    std::map<std::pair<uint32_t, anti_cheat::CheatCategory>, std::chrono::steady_clock::time_point> m_lastReported;

    // --- Input Automation Detection ---
    struct MouseMoveEvent {
        POINT pt;
        DWORD time;
    };
    struct MouseClickEvent {
        DWORD time;
    };

    HHOOK m_hMouseHook = NULL;
    std::mutex m_inputMutex;
    std::vector<MouseMoveEvent> m_mouseMoveEvents;
    std::vector<MouseClickEvent> m_mouseClickEvents;
    static Pimpl* s_pimpl_for_hooks; // Static pointer for hook procedures

    // Main loop and state management
    void MonitorLoop();
    void UploadReport();
    void InitializeAndBaseline();
    void ResetSessionState();
    void AddEvidence(anti_cheat::CheatCategory category, const std::string& description);
    void HardenProcessAndThreads(); //  进程与线程加固

    // --- Sensor Functions ---
    void Sensor_CheckApiHooks();
    void Sensor_CheckProcessHandles();
    void Sensor_ValidateParentProcess();
    void Sensor_ScanNewActivity();
    void Sensor_ScanMemory();
    void Sensor_VerifySystemModuleIntegrity();
    void Sensor_CheckEnvironment();
    void Sensor_DetectVirtualMachine();
    void Sensor_CollectHardwareFingerprint(); //  收集硬件指纹
    void Sensor_CheckSystemIntegrityState(); //  系统完整性状态检测
    void Sensor_CheckAdvancedAntiDebug(); //  高级反调试检测
    void Sensor_CheckIatHooks(); //  IAT Hook 检测
    void Sensor_CheckInputAutomation(); //  输入自动化检测
    void VerifyModuleIntegrity(const wchar_t* moduleName); //  通用模块验证辅助函数

    // VM detection helpers
    void DetectVmByCpuid();
    void DetectVmByRegistry();
    void DetectVmByMacAddress();

    void VerifyModuleSignature(HMODULE hModule);

    // --- Hook Procedures ---
    static LRESULT CALLBACK LowLevelMouseProc(int nCode, WPARAM wParam, LPARAM lParam);

    void CheckFunctionForHook(HMODULE moduleHandle, std::string_view functionName);
};

CheatMonitor::Pimpl* CheatMonitor::Pimpl::s_pimpl_for_hooks = nullptr;

CheatMonitor& CheatMonitor::GetInstance() { static CheatMonitor instance; return instance; }
CheatMonitor::CheatMonitor() { m_pimpl = new Pimpl(); }
CheatMonitor::~CheatMonitor() { 
    Shutdown(); 
}

void CheatMonitor::Initialize() {
    if (!m_pimpl) m_pimpl = new Pimpl();
    if (m_pimpl->m_isSystemActive.load()) return;
    m_pimpl->m_isSystemActive = true;
    // The hook procedure needs a static pointer to the Pimpl instance.
    Pimpl::s_pimpl_for_hooks = m_pimpl;
    // The hook must be set from a thread that has a message loop, but for system-wide LL hooks, it can be any thread.
    // 钩子回调函数需要一个指向Pimpl实例的静态指针。
    m_pimpl->m_hMouseHook = SetWindowsHookEx(WH_MOUSE_LL, Pimpl::LowLevelMouseProc, GetModuleHandle(NULL), 0);
    
    m_pimpl->m_monitorThread = std::thread(&Pimpl::MonitorLoop, m_pimpl);
}

void CheatMonitor::OnPlayerLogin(uint32_t user_id, const std::string& user_name, const std::string& client_version) {
    if (!m_pimpl || !m_pimpl->m_isSystemActive.load()) return;
    OnPlayerLogout();
    {
        std::lock_guard<std::mutex> lock(m_pimpl->m_sessionMutex);
        m_pimpl->m_currentUserId = user_id;
        m_pimpl->m_currentUserName = user_name;
        //  确保硬件指纹只在第一个会话开始时收集一次
        if (!m_pimpl->m_fingerprint) {
            m_pimpl->Sensor_CollectHardwareFingerprint();
        }
        m_pimpl->m_isSessionActive = true;
    }
    m_pimpl->m_cv.notify_one();
}

void CheatMonitor::OnPlayerLogout() {
    if (!m_pimpl || !m_pimpl->m_isSessionActive.load()) return;
    m_pimpl->UploadReport();
    {
        std::lock_guard<std::mutex> lock(m_pimpl->m_sessionMutex);
        m_pimpl->ResetSessionState();
        m_pimpl->m_isSessionActive = false;
    }
}

void CheatMonitor::Shutdown() {
    if (!m_pimpl || !m_pimpl->m_isSystemActive.load()) return;
    if (m_pimpl->m_isSessionActive.load()) OnPlayerLogout();
    m_pimpl->m_isSystemActive = false;
    m_pimpl->m_cv.notify_one();
    if (m_pimpl->m_hMouseHook) {
        UnhookWindowsHookEx(m_pimpl->m_hMouseHook);
        m_pimpl->m_hMouseHook = NULL;
    }
    Pimpl::s_pimpl_for_hooks = nullptr;
    if (m_pimpl->m_monitorThread.joinable()) m_pimpl->m_monitorThread.join();
    delete m_pimpl;
    m_pimpl = nullptr;
}

bool CheatMonitor::IsCallerLegitimate() {
    if (!m_pimpl) return true; // 如果系统未初始化，则不拦截

    // 1. 获取调用本函数的代码地址
    void* returnAddress = _ReturnAddress();
    HMODULE hModule = NULL;

    // 2. 检查该地址是否属于一个已加载的模块
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)returnAddress, &hModule) && hModule != NULL) {
        wchar_t modulePath[MAX_PATH];
        // 3. 获取该模块的完整路径
        if (GetModuleFileNameW(hModule, modulePath, MAX_PATH) > 0) {
            std::wstring lowerPath = modulePath;
            std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
            // 4. 使用哈希集合进行高效查找
            if (m_pimpl->m_legitimateModulePaths.count(lowerPath) > 0) {
                return true; // 调用者是白名单内的合法模块
            }
            // --- 非法调用处理 ---
            // 调用者来自一个已加载但不在白名单内的模块 (例如 cheat.dll)
            uintptr_t sourceId = std::hash<std::wstring>{}(lowerPath);
            std::string sourceDescription = "非法调用(未知模块): " + Utils::WideToString(modulePath);

            std::lock_guard<std::mutex> lock(m_pimpl->m_sessionMutex);
            auto now = std::chrono::steady_clock::now();
            auto it = m_pimpl->m_reportedIllegalCallSources.find(sourceId);

            if (it == m_pimpl->m_reportedIllegalCallSources.end() || 
                std::chrono::duration_cast<std::chrono::minutes>(now - it->second).count() >= 5) {
                // 如果是第一次发现，或者距离上次上报已超过5分钟，则上报并更新时间戳
                m_pimpl->m_reportedIllegalCallSources[sourceId] = now;
                m_pimpl->AddEvidence(anti_cheat::RUNTIME_ILLEGAL_FUNCTION_CALL, sourceDescription);
            }
            return false;
        }
    }

    // 调用者来自Shellcode或无法识别的内存区域
    uintptr_t sourceId = 0;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(returnAddress, &mbi, sizeof(mbi))) {
        sourceId = (uintptr_t)mbi.AllocationBase; // 使用内存区域的基地址作为唯一标识
    } else {
        sourceId = (uintptr_t)returnAddress; // 降级方案：使用返回地址本身
    }

    std::lock_guard<std::mutex> lock(m_pimpl->m_sessionMutex);
    auto now = std::chrono::steady_clock::now();
    auto it = m_pimpl->m_reportedIllegalCallSources.find(sourceId);

    if (it == m_pimpl->m_reportedIllegalCallSources.end() ||
        std::chrono::duration_cast<std::chrono::minutes>(now - it->second).count() >= 5) {
        m_pimpl->m_reportedIllegalCallSources[sourceId] = now;
        m_pimpl->AddEvidence(anti_cheat::RUNTIME_ILLEGAL_FUNCTION_CALL, "非法调用(Shellcode)");
    }
    return false;
}

void CheatMonitor::Pimpl::ResetSessionState() {
    m_evidences.clear();
    m_uniqueEvidence.clear();
    m_reportedIllegalCallSources.clear(); // 会话结束时清空“记忆”
    m_currentUserId = 0;
    m_currentUserName.clear();
}

void CheatMonitor::Pimpl::InitializeAndBaseline() {
    HardenProcessAndThreads(); // 在所有检测开始前，首先加固自身
    // 在会话开始时执行一次性检查
    Sensor_ValidateParentProcess(); // 使用新的、更安全的父进程验证
    Sensor_DetectVirtualMachine();
    // 检查游戏自身和反作弊模块的完整性
    Sensor_VerifySystemModuleIntegrity();

    HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te; te.dwSize = sizeof(te);
        if (Thread32First(hThreadSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == GetCurrentProcessId()) m_knownThreadIds.insert(te.th32ThreadID);
            } while (Thread32Next(hThreadSnapshot, &te));
        }
        CloseHandle(hThreadSnapshot);
    }

    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            // 将所有初始加载的模块视为基线的一部分
            m_knownModules.insert(hMods[i]);

            // 动态构建模块白名单：将所有初始加载的模块路径添加到白名单中
            wchar_t modPath[MAX_PATH];
            if (GetModuleFileNameW(hMods[i], modPath, MAX_PATH) > 0) {
                std::wstring lowerPath = modPath;
                std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
                m_legitimateModulePaths.insert(lowerPath);
            }
        }
    }
}

void CheatMonitor::Pimpl::HardenProcessAndThreads() {
    // 1. 设置进程缓解策略，阻止当前进程创建任何子进程。
    PROCESS_MITIGATION_CHILD_PROCESS_POLICY childPolicy = {};
    childPolicy.NoChildProcessCreation = 1;
    SetProcessMitigationPolicy(ProcessChildProcessPolicy, &childPolicy, sizeof(childPolicy));

#ifndef _DEBUG
    // 2. 为当前进程的所有线程设置“对调试器隐藏”属性
    // 这段代码只在Release版本中编译，以避免影响开发阶段的调试。
    if (!g_pNtSetInformationThread) {
        return;
    }

    HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnapshot == INVALID_HANDLE_VALUE) {
        return;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(hThreadSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == GetCurrentProcessId()) {
                HANDLE hThread = OpenThread(THREAD_SET_INFORMATION, FALSE, te.th32ThreadID);
                if (hThread) {
                    g_pNtSetInformationThread(hThread, (THREADINFOCLASS)0x11, NULL, 0); // 0x11 is ThreadHideFromDebugger
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hThreadSnapshot, &te));
    }
    CloseHandle(hThreadSnapshot);
#endif
}

void CheatMonitor::Pimpl::MonitorLoop() {
    InitializeAndBaseline();
    using namespace std::chrono;

    while (m_isSystemActive.load()) {
        {
            std::unique_lock<std::mutex> lock(m_cvMutex);
            m_cv.wait(lock, [this]{ return m_isSessionActive.load() || !m_isSystemActive.load(); });
        }
        if (!m_isSystemActive.load()) break;

        auto last_report_time = steady_clock::now();
        
        while (m_isSessionActive.load()) {
            auto scan_start_time = steady_clock::now();

            // --- 执行所有扫描 ---
            Sensor_CheckApiHooks();
            Sensor_CheckProcessHandles();
            Sensor_ScanNewActivity();
            Sensor_CheckEnvironment();
            Sensor_CheckAdvancedAntiDebug();
            Sensor_ScanMemory();
            Sensor_CheckSystemIntegrityState();
            Sensor_CheckIatHooks();
            Sensor_CheckInputAutomation();

            // --- 定期上报 ---
            if (duration_cast<minutes>(scan_start_time - last_report_time) >= minutes(5)) {
                UploadReport();
                last_report_time = scan_start_time;
            }

            // --- 动态休眠 ---
            // 保证两次扫描之间至少间隔10秒
            auto scan_end_time = steady_clock::now();
            // 计算本次扫描实际花费的时间。
            auto scan_duration = duration_cast<milliseconds>(scan_end_time - scan_start_time);
            // 从固定的10秒间隔中减去扫描耗时，得出需要休眠的时间。
            auto sleep_duration = seconds(10) - scan_duration;

            if (sleep_duration > milliseconds(0)) {
                std::unique_lock<std::mutex> lock(m_cvMutex);
                m_cv.wait_for(lock, sleep_duration, [this]{ return !m_isSessionActive.load() || !m_isSystemActive.load(); });
            }
        }
    }
}

void CheatMonitor::Pimpl::AddEvidence(anti_cheat::CheatCategory category, const std::string& description) {
    std::lock_guard<std::mutex> lock(m_sessionMutex);
    if (!m_isSessionActive) return;

    //  频率控制：半小时内只上报一次
    auto now = std::chrono::steady_clock::now();
    std::pair<uint32_t, anti_cheat::CheatCategory> key = {m_currentUserId, category};
    auto it = m_lastReported.find(key);

    if (it != m_lastReported.end()) {
        auto duration = std::chrono::duration_cast<std::chrono::minutes>(now - it->second);
        if (duration.count() < 30) {
            // 距离上次上报时间小于30分钟，取消本次上报
            return;
        }
    }

    // 如果是第一次发现，或者距离上次上报已超过30分钟，则更新时间戳
    m_lastReported[key] = now;



    // O(logN) 复杂度的去重检查
    if (m_uniqueEvidence.find({category, description}) != m_uniqueEvidence.end()) {
        return;
    }

    m_uniqueEvidence.insert({category, description});

    anti_cheat::Evidence evidence; // 在栈上创建对象
    evidence.set_client_timestamp_ms(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    evidence.set_category(category);
    evidence.set_description(description);
    m_evidences.push_back(evidence); // 拷贝到vector
}

void CheatMonitor::Pimpl::UploadReport() {
    std::lock_guard<std::mutex> lock(m_sessionMutex);
    if (m_evidences.empty()) return;

    anti_cheat::CheatReport report;
    report.set_report_id(Utils::GenerateUuid());
    report.set_report_timestamp_ms(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    
    //  如果硬件指纹已收集且尚未上报（m_fingerprint非空），则附加到报告中
    //  通过 release() 转移所有权，确保它只被上报一次。
    if (m_fingerprint) {
        report.set_allocated_fingerprint(m_fingerprint.release());
    }

    report.mutable_evidences()->CopyFrom({m_evidences.begin(), m_evidences.end()});

    std::cout << "\n--- [反作弊] 上报报告 (UserID: " << m_currentUserId << ") ---\n"
              << report.DebugString()
              << "-------------------- 报告结束 --------------------\n\n";
    
    m_evidences.clear();
    m_uniqueEvidence.clear();
}

void CheatMonitor::Pimpl::Sensor_CheckEnvironment() {
    if (IsDebuggerPresent()) {
        AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, "IsDebuggerPresent() API返回true");
    }

    // --- 性能优化: 解耦进程扫描与窗口扫描 ---
    // 1. 首先，一次性遍历所有窗口，构建一个 PID -> WindowTitles 的映射
    std::map<DWORD, std::vector<std::wstring>> windowTitlesByPid;
    auto enumProc = [](HWND hWnd, LPARAM lParam) -> BOOL {
        if (!IsWindowVisible(hWnd)) return TRUE;
        auto* pMap = reinterpret_cast<std::map<DWORD, std::vector<std::wstring>>*>(lParam);
        DWORD processId = 0;
        GetWindowThreadProcessId(hWnd, &processId);
        if (processId > 0) {
            wchar_t buffer[256];
            if (GetWindowTextW(hWnd, buffer, ARRAYSIZE(buffer)) > 0) {
                (*pMap)[processId].push_back(buffer);
            }
        }
        return TRUE;
    };
    EnumWindows(enumProc, reinterpret_cast<LPARAM>(&windowTitlesByPid));

    // 2. 然后，遍历进程列表，进行检查
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnapshot, &pe)) {
        do {
            std::wstring processName = pe.szExeFile;
            std::transform(processName.begin(), processName.end(), processName.begin(), ::towlower);
            
            // 检查进程名
            for (const auto& harmful : m_harmfulProcessNames) {
                if (processName.find(harmful) != std::wstring::npos) {
                    AddEvidence(anti_cheat::ENVIRONMENT_HARMFUL_PROCESS, "有害进程(文件名): " + Utils::WideToString(pe.szExeFile));
                    goto next_process; // 使用goto以跳出多层循环，继续检查下一个进程
                }
            }

            // 检查窗口标题 (从预先构建的map中查找)
            if (auto it = windowTitlesByPid.find(pe.th32ProcessID); it != windowTitlesByPid.end()) {
                for (const auto& title : it->second) {
                std::wstring lowerTitle = title;
                std::transform(lowerTitle.begin(), lowerTitle.end(), lowerTitle.begin(), ::towlower);
                for (const auto& keyword : m_harmfulKeywords) {
                    if (lowerTitle.find(keyword) != std::wstring::npos) {
                        AddEvidence(anti_cheat::ENVIRONMENT_HARMFUL_PROCESS, "有害进程(窗口标题): " + Utils::WideToString(title));
                        goto next_process;
                    }
                }
            }
            }
        next_process:;
        } while (Process32NextW(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
}

void CheatMonitor::Pimpl::VerifyModuleIntegrity(const wchar_t* moduleName) {
    // 定义句柄的智能指针类型，实现RAII，确保资源自动释放
    using UniqueFileHandle = std::unique_ptr<void, decltype(&::CloseHandle)>;
    using UniqueMappingHandle = std::unique_ptr<void, decltype(&::CloseHandle)>;

    HMODULE hModuleInMemory = GetModuleHandleW(moduleName);
    if (!hModuleInMemory) return;

    wchar_t modPathOnDisk[MAX_PATH];
    if (GetModuleFileNameW(hModuleInMemory, modPathOnDisk, MAX_PATH) == 0) return;

    UniqueFileHandle hFile(CreateFileW(modPathOnDisk, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL), &CloseHandle);
    if (hFile.get() == INVALID_HANDLE_VALUE) return;

    UniqueMappingHandle hMapping(CreateFileMappingW(hFile.get(), NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL), &CloseHandle);
    if (!hMapping.get()) return;

    LPVOID pMappedFileBase = MapViewOfFile(hMapping.get(), FILE_MAP_READ, 0, 0, 0);
    if (!pMappedFileBase) return;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModuleInMemory;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModuleInMemory + pDosHeader->e_lfanew);

    // 比较PE头
    if (memcmp(hModuleInMemory, pMappedFileBase, pNtHeaders->OptionalHeader.SizeOfHeaders) != 0) {
        AddEvidence(anti_cheat::INTEGRITY_MODULE_TAMPERED, "模块PE头被篡改: " + Utils::WideToString(moduleName));
    } else {
        // 遍历所有节，检查所有包含可执行代码的节
        PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
        for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++) {
            // 检查节属性是否为可执行代码
            if (pSectionHeader->Characteristics & IMAGE_SCN_CNT_CODE) {
                void* sectionInMemory = (BYTE*)hModuleInMemory + pSectionHeader->VirtualAddress;
                void* sectionOnDisk = (BYTE*)pMappedFileBase + pSectionHeader->PointerToRawData;
                if (memcmp(sectionInMemory, sectionOnDisk, pSectionHeader->Misc.VirtualSize) != 0) {
                    AddEvidence(anti_cheat::INTEGRITY_MODULE_TAMPERED, "代码节被篡改: " + Utils::WideToString(moduleName));
                    break; // 找到一个被篡改的就足够了
                }
            }
        }
    }
    UnmapViewOfFile(pMappedFileBase);
}

void CheatMonitor::Pimpl::Sensor_CheckSystemIntegrityState() {
    // 1. 检查测试签名模式是否开启
    SYSTEM_CODE_INTEGRITY_INFORMATION sci = { sizeof(sci), 0 };
    if (g_pNtQuerySystemInformation && NT_SUCCESS(g_pNtQuerySystemInformation(SystemCodeIntegrityInformation, &sci, sizeof(sci), nullptr))) {
        // CODEINTEGRITY_OPTION_TESTSIGN (0x02)
        if (sci.CodeIntegrityOptions & 0x02) {
            AddEvidence(anti_cheat::ENVIRONMENT_SUSPICIOUS_DRIVER, "系统开启了测试签名模式 (Test Signing Mode)");
        }
    }

    // 2. 检查安全启动状态 (更复杂的检查，未来可以添加)
    // ...
}

namespace { // 匿名命名空间，用于辅助函数
    // 将__try块移至此辅助函数中，以解决C2712错误。
    // 此函数不应使用任何需要堆栈展开的C++对象。
    void CheckCloseHandleException() {
        __try {
            // 使用 reinterpret_cast 和 uintptr_t 以避免C4312警告 (在64位上从int到更大的指针的转换)
            CloseHandle(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(0xDEADBEEF)));
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            // 如果调试器附加，它将捕获此异常，代码可能不会到达这里。
        }
    }
}
void CheatMonitor::Pimpl::Sensor_CheckAdvancedAntiDebug() {
    // 1. CheckRemoteDebuggerPresent - 另一个标准的API检查
    BOOL isDebuggerPresent = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent) && isDebuggerPresent) {
        AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, "CheckRemoteDebuggerPresent() API返回true");
    }

    // 2. PEB->BeingDebugged - 直接检查进程环境块中的标志
    // 这是 IsDebuggerPresent 内部使用的机制，直接检查可以绕过对API的Hook
#ifdef _WIN64
    auto pPeb = (PPEB)__readgsqword(0x60);
#else
    auto pPeb = (PPEB)__readfsdword(0x30);
#endif
    if (pPeb->BeingDebugged) {
        AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, "PEB->BeingDebugged 标志位为true");
    }

    // 3. CloseHandle 无效句柄技巧
    // 在没有调试器的情况下，调用会失败并返回。
    // 如果有调试器附加，它会捕获这个异常，导致执行流程改变。
    CheckCloseHandleException();

    // 4. 硬件断点检查 (DR0-DR7)
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
            AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, "检测到硬件断点 (Debug Registers)");
        }
    }

    // 5. 内核调试器检测 (通过 NtQuerySystemInformation)
    SYSTEM_KERNEL_DEBUGGER_INFORMATION info;
    if (g_pNtQuerySystemInformation && NT_SUCCESS(g_pNtQuerySystemInformation(SystemKernelDebuggerInformation, &info, sizeof(info), NULL))) {
        if (info.KernelDebuggerEnabled && !info.KernelDebuggerNotPresent) {
            AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, "检测到内核调试器 (NtQuerySystemInformation)");
        }
    }

    // 6. 内核调试器检测 (通过共享内存 _KUSER_SHARED_DATA)
    // 该结构体位于一个固定地址，其 KdDebuggerEnabled 字段是一个公开的标志。
#ifdef _WIN64
    const UCHAR* pSharedData = (const UCHAR*)0x7FFE0000;
#else
    const UCHAR* pSharedData = (const UCHAR*)0x7FFE0000; // x86 和 x64 地址相同
#endif
    const BOOLEAN kdDebuggerEnabled = *(pSharedData + 0x2D4);
    if (kdDebuggerEnabled) {
        AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, "检测到内核调试器 (KUSER_SHARED_DATA)");
    }
}

void CheatMonitor::Pimpl::Sensor_VerifySystemModuleIntegrity() {
    // 验证系统核心模块
    VerifyModuleIntegrity(L"ntdll.dll");
    VerifyModuleIntegrity(L"kernel32.dll");
    VerifyModuleIntegrity(L"user32.dll");

    // 验证游戏主程序 (NULL代表当前进程的.exe)
    VerifyModuleIntegrity(NULL);
}

void CheatMonitor::Pimpl::Sensor_ScanNewActivity() {
    HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te; te.dwSize = sizeof(te);
        if (Thread32First(hThreadSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == GetCurrentProcessId()) {                    
                    // std::set::insert 返回一个 pair，其第二个元素（bool）表示插入是否成功
                    if (m_knownThreadIds.insert(te.th32ThreadID).second) {
                        AddEvidence(anti_cheat::RUNTIME_THREAD_NEW_UNKNOWN, "检测到新线程 (TID: " + std::to_string(te.th32ThreadID) + ")");
                    }
                }
            } while (Thread32Next(hThreadSnapshot, &te));
        }
        CloseHandle(hThreadSnapshot);
    }

    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            if (m_knownModules.insert(hMods[i]).second) {
                // 当发现一个新模块时，立即进行处理
                wchar_t szModName[MAX_PATH];
                if (GetModuleFileNameW(hMods[i], szModName, MAX_PATH)) {
                    AddEvidence(anti_cheat::RUNTIME_MODULE_NEW_UNKNOWN, "加载了新模块: " + Utils::WideToString(szModName));
                    // 对新加载的模块进行签名验证
                    VerifyModuleSignature(hMods[i]);
                }
            }
        }
    }
}

void CheatMonitor::Pimpl::Sensor_ScanMemory() {
    unsigned char* pCurrentAddress = nullptr;
    MEMORY_BASIC_INFORMATION mbi;
    while (VirtualQuery(pCurrentAddress, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        const bool isCommitted = mbi.State == MEM_COMMIT;
        const bool isPrivate = mbi.Type == MEM_PRIVATE;
        const bool isExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));

        if (isCommitted && isPrivate && isExecutable) {
            HMODULE hModule = NULL;
            if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)mbi.BaseAddress, &hModule)) {
                std::ostringstream oss;
                oss << "发现可疑内存区域。地址: 0x" << std::hex << mbi.BaseAddress << ", 大小: " << std::dec << mbi.RegionSize;
                AddEvidence(anti_cheat::RUNTIME_MEMORY_EXEC_PRIVATE, oss.str());
            }
        }

        // 检查已加载模块的内存页是否被非法修改为可写+可执行
        // 这是一个非常可疑的迹象，通常意味着代码节被Patch以植入Hook
        if (mbi.Type == MEM_IMAGE && (mbi.Protect & PAGE_EXECUTE_READWRITE)) {
            HMODULE hModule = NULL;
            char moduleName[MAX_PATH] = {0};
            if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)mbi.BaseAddress, &hModule) && GetModuleFileNameA(hModule, moduleName, MAX_PATH)) {
                AddEvidence(anti_cheat::INTEGRITY_MEMORY_PATCH, "检测到可写的代码节: " + std::string(moduleName));
            }
        }
        pCurrentAddress += mbi.RegionSize;
    }
}

// 验证父进程，防止傀儡进程欺骗
void CheatMonitor::Pimpl::Sensor_ValidateParentProcess() {
    DWORD parentPid = 0;
    std::string parentName;
    if (!Utils::GetParentProcessInfo(parentPid, parentName)) {
        AddEvidence(anti_cheat::ENVIRONMENT_UNKNOWN, "无法获取父进程信息");
        return;
    }

    bool isLegitimate = false;
    for (const auto& legitimateName : m_legitimateParentProcesses) {
        if (_stricmp(parentName.c_str(), legitimateName.c_str()) == 0) {
            // 如果父进程是explorer.exe，需要进行额外验证，确保它是真正的桌面Shell进程，而不是伪造的同名进程。
            if (_stricmp(parentName.c_str(), "explorer.exe") == 0) {
                HWND hShellWnd = GetShellWindow();
                DWORD shellPid = 0;
                if (hShellWnd) {
                    GetWindowThreadProcessId(hShellWnd, &shellPid);
                    if (parentPid == shellPid) {
                        isLegitimate = true; // 验证通过，是合法的Shell进程
                    }
                }
                // 如果不是合法的Shell进程，isLegitimate将保持false
            } else {
                // 其他合法父进程（如启动器、IDE）直接信任
                isLegitimate = true;
            }
            break;
        }
    }

    if (!isLegitimate) {
        AddEvidence(anti_cheat::ENVIRONMENT_INVALID_PARENT_PROCESS, "由可疑或伪造的父进程启动: " + parentName + " (PID: " + std::to_string(parentPid) + ")");
    }
}

/**
 * @brief 通过CPUID指令检测虚拟机。
 * 1. 检查 Hypervisor-Present Bit。
 * 2. 检查 Hypervisor 厂商标识字符串。
 */
void CheatMonitor::Pimpl::DetectVmByCpuid() {
    // 使用 std::string_view 以避免不必要的字符串分配和拷贝
    static constexpr std::array<std::string_view, 6> vmVendorStrings = {
        "KVMKVMKVM",    // KVM
        "Microsoft Hv", // Microsoft Hyper-V
        "VMwareVMware", // VMware
        "XenVMMXenVMM", // Xen
        "VBoxVBoxVBox", // VirtualBox
        "prl hyperv"    // Parallels
    };

    int cpuInfo[4];

    // --- 1. 检查 Hypervisor Present Bit ---
    // CPUID EAX=1 后，ECX 寄存器的第31位是 Hypervisor Present Bit
    __cpuid(cpuInfo, 1);
    if ((cpuInfo[2] >> 31) & 1) {
        AddEvidence(anti_cheat::ENVIRONMENT_VIRTUAL_MACHINE, "CPUID: Hypervisor present bit is set.");
    }

    // --- 2. 检查 Hypervisor 厂商字符串 ---
    // Hypervisor 的 CPUID 功能叶从 0x40000000 开始
    __cpuid(cpuInfo, 0x40000000);

    char vendorId[13];
    memcpy(vendorId, &cpuInfo[1], 4);
    memcpy(vendorId + 4, &cpuInfo[2], 4);
    memcpy(vendorId + 8, &cpuInfo[3], 4);
    vendorId[12] = '\0';

    if (vendorId[0] != '\0') { // 仅在厂商字符串非空时进行比较
        for (const auto& vmVendor : vmVendorStrings) {
            if (vmVendor == vendorId) {
                AddEvidence(anti_cheat::ENVIRONMENT_VIRTUAL_MACHINE,
                            "CPUID: Found known hypervisor vendor string '" + std::string(vendorId) + "'.");
                break; // 找到匹配项后即可退出循环
            }
        }
    }
}

/**
 * @brief 通过检查特定的注册表项来检测虚拟机痕迹。
 * 虚拟机通常会留下特定的硬件或服务相关的注册表项。
 */
void CheatMonitor::Pimpl::DetectVmByRegistry() {
    // 策略1: 检查特定注册表项的存在。这些项的存在本身就是强证据。
    static constexpr std::array<const char*, 2> vmExistenceKeys = {
        R"(SOFTWARE\Oracle\VirtualBox Guest Additions)", // VirtualBox Guest Additions
        R"(SOFTWARE\VMware, Inc.\VMware Tools)"          // VMware Tools
    };

    for (const char* keyPath : vmExistenceKeys) {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            AddEvidence(anti_cheat::ENVIRONMENT_VIRTUAL_MACHINE,
                        "Registry: Found VM-related key: HKLM\\" + std::string(keyPath));
            RegCloseKey(hKey);
        }
    }

    // 策略2: 检查通用注册表项的值是否包含VM指纹。
    // Disk\Enum 的值通常包含 "VMware", "VBox", "QEMU" 等字符串。
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, R"(SYSTEM\CurrentControlSet\Services\Disk\Enum)", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        char valueName[256];
        DWORD valueNameSize = sizeof(valueName);
        BYTE data[1024];
        DWORD dataSize = sizeof(data);
        DWORD index = 0;
        
        // 枚举该键下的所有值
        while (RegEnumValueA(hKey, index++, valueName, &valueNameSize, NULL, NULL, data, &dataSize) == ERROR_SUCCESS) {
            // 将值数据转换为小写字符串以便不区分大小写地搜索
            std::string valueStr(reinterpret_cast<char*>(data), dataSize);
            std::transform(valueStr.begin(), valueStr.end(), valueStr.begin(), ::tolower);

            if (valueStr.find("vmware") != std::string::npos || valueStr.find("vbox") != std::string::npos || valueStr.find("qemu") != std::string::npos) {
                // 截断过长的原始数据以提高可读性
                std::string originalValue(reinterpret_cast<char*>(data), min(dataSize, 100));
                AddEvidence(anti_cheat::ENVIRONMENT_VIRTUAL_MACHINE, "Registry: Disk\\Enum contains VM identifier: " + originalValue);
                break; // 找到一个就足够了
            }
            // 为下一次迭代重置大小
            valueNameSize = sizeof(valueName);
            dataSize = sizeof(data);
        }
        RegCloseKey(hKey);
    }
}

/**
 * @brief 通过检查网卡MAC地址前缀（OUI）来检测虚拟机。
 */
void CheatMonitor::Pimpl::DetectVmByMacAddress() {
    // 定义已知虚拟机的MAC地址前缀 (Organizationally Unique Identifier)
    struct MacPrefix {
        std::array<BYTE, 3> oui;
        const char* vendor;
    };

    static const std::array<MacPrefix, 4> vmMacPrefixes = { {
        { {0x00, 0x05, 0x69}, "VMware" },
        { {0x00, 0x0C, 0x29}, "VMware" },
        { {0x08, 0x00, 0x27}, "VirtualBox" },
        { {0x00, 0x15, 0x5D}, "Microsoft Hyper-V" }
    } };

    ULONG bufferSize = 0;
    // 第一次调用以获取所需的缓冲区大小
    if (GetAdaptersInfo(nullptr, &bufferSize) != ERROR_BUFFER_OVERFLOW) {
        return; // 如果没有适配器或发生其他错误，则直接返回
    }

    std::vector<BYTE> buffer(bufferSize);
    auto adapterInfo = reinterpret_cast<IP_ADAPTER_INFO*>(buffer.data());

    // 第二次调用以获取适配器信息
    if (GetAdaptersInfo(adapterInfo, &bufferSize) != ERROR_SUCCESS) {
        return; // 获取信息失败
    }

    while (adapterInfo) {
        if (adapterInfo->AddressLength == 6) { // 确保是标准的6字节MAC地址
            for (const auto& prefix : vmMacPrefixes) {
                if (memcmp(adapterInfo->Address, prefix.oui.data(), 3) == 0) {
                    AddEvidence(anti_cheat::ENVIRONMENT_VIRTUAL_MACHINE,
                                "MAC: Found " + std::string(prefix.vendor) + " MAC address prefix.");
                    break; // 找到一个匹配项后，检查下一个适配器
                }
            }
        }
        adapterInfo = adapterInfo->Next;
    }
}

void CheatMonitor::Pimpl::Sensor_CollectHardwareFingerprint() {
    // 仅当指纹尚未收集时才执行
    if (m_fingerprint) return;

    m_fingerprint = std::make_unique<anti_cheat::HardwareFingerprint>();

    // 1. 获取C盘卷序列号
    DWORD serialNum = 0;
    if (GetVolumeInformationA("C:\\", NULL, 0, &serialNum, NULL, NULL, NULL, 0)) {
        m_fingerprint->set_disk_serial(std::to_string(serialNum));
    }

    // 2. 获取所有网络适配器的MAC地址
    ULONG bufferSize = 0;
    if (GetAdaptersInfo(nullptr, &bufferSize) == ERROR_BUFFER_OVERFLOW) {
        std::vector<BYTE> buffer(bufferSize);
        auto* adapterInfo = reinterpret_cast<IP_ADAPTER_INFO*>(buffer.data());
        if (GetAdaptersInfo(adapterInfo, &bufferSize) == ERROR_SUCCESS) {
            while (adapterInfo) {
                if (adapterInfo->AddressLength == 6) {
                    std::ostringstream oss;
                    oss << std::hex << std::uppercase << std::setfill('0');
                    for (int i = 0; i < 6; ++i) {
                        oss << std::setw(2) << static_cast<int>(adapterInfo->Address[i]) << (i < 5 ? "-" : "");
                    }
                    m_fingerprint->add_mac_addresses(oss.str());
                }
                adapterInfo = adapterInfo->Next;
            }
        }
    }

    // 3. 获取计算机名
    wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(computerName, &size)) {
        m_fingerprint->set_computer_name(Utils::WideToString(computerName));
    }

    // 4. 获取操作系统版本
    auto* pRtlGetVersion = (NTSTATUS(WINAPI*)(PRTL_OSVERSIONINFOW))GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
    if (pRtlGetVersion) {
        RTL_OSVERSIONINFOW osInfo = { sizeof(RTL_OSVERSIONINFOW) };
        if (pRtlGetVersion(&osInfo) == 0) { // 0 is STATUS_SUCCESS
            std::string osVersion = "OS:" + std::to_string(osInfo.dwMajorVersion) + "." + std::to_string(osInfo.dwMinorVersion) + "." + std::to_string(osInfo.dwBuildNumber);
            m_fingerprint->set_os_version(osVersion);
        }
    }

    // 5. 获取CPU信息
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    std::string cpuInfo = "CPU:Arch=" + std::to_string(sysInfo.wProcessorArchitecture) + ",Cores=" + std::to_string(sysInfo.dwNumberOfProcessors);
    m_fingerprint->set_cpu_info(cpuInfo);
}

namespace InputAnalysis {
    // 计算标准差，用于判断点击间隔的规律性
    double CalculateStdDev(const std::vector<double>& values) {
        if (values.size() < 2) return 0.0;
        double sum = std::accumulate(values.begin(), values.end(), 0.0);
        double mean = sum / values.size();
        double sq_sum = std::inner_product(values.begin(), values.end(), values.begin(), 0.0);
        double variance = sq_sum / values.size() - mean * mean;
        return variance > 0 ? std::sqrt(variance) : 0.0;
    }

    // 检查三点是否共线，用于判断鼠标轨迹是否为完美的直线
    bool ArePointsCollinear(POINT p1, POINT p2, POINT p3) {
        // 使用2D向量的叉积。如果叉积为0，则三点共线。
        // (p2.y - p1.y) * (p3.x - p2.x) - (p2.x - p1.x) * (p3.y - p2.y) == 0
        long long cross_product = static_cast<long long>(p2.y - p1.y) * (p3.x - p2.x) - static_cast<long long>(p2.x - p1.x) * (p3.y - p2.y);
        return cross_product == 0;
    }
}

void CheatMonitor::Pimpl::Sensor_CheckInputAutomation() {
    std::vector<MouseMoveEvent> mouseMoves;
    std::vector<MouseClickEvent> mouseClicks;

    {
        std::lock_guard<std::mutex> lock(m_inputMutex);
        // 为避免分析过于频繁或数据量过小，设置一个阈值
        if (m_mouseMoveEvents.size() > 200) {
            mouseMoves.swap(m_mouseMoveEvents);
        }
        if (m_mouseClickEvents.size() > 10) {
            mouseClicks.swap(m_mouseClickEvents);
        }
    }

    // --- 1. 分析点击规律性 ---
    if (mouseClicks.size() > 5) {
        std::vector<double> deltas;
        for (size_t i = 1; i < mouseClicks.size(); ++i) {
            deltas.push_back(static_cast<double>(mouseClicks[i].time - mouseClicks[i-1].time));
        }
        
        double stddev = InputAnalysis::CalculateStdDev(deltas);
        // 如果点击间隔的标准差小于5毫秒，这在人类操作中几乎不可能，极有可能是宏。
        if (stddev < 5.0 && stddev > 0) { // stddev > 0 to avoid single interval case
            AddEvidence(anti_cheat::INPUT_AUTOMATION_DETECTED, "检测到规律性鼠标点击 (StdDev: " + std::to_string(stddev) + "ms)");
        }
    }

    // --- 2. 分析鼠标移动轨迹 ---
    if (mouseMoves.size() > 10) {
        // a) 检查是否存在完美的直线移动
        int collinear_count = 0;
        for (size_t i = 2; i < mouseMoves.size(); ++i) {
            if (InputAnalysis::ArePointsCollinear(mouseMoves[i-2].pt, mouseMoves[i-1].pt, mouseMoves[i].pt)) {
                collinear_count++;
            } else {
                collinear_count = 0; // 如果不共线，则重置计数器
            }

            // 如果连续8个或更多点在一条完美的直线上，这对于人类来说是不自然的。
            // 这个阈值可能需要根据实际游戏数据进行调整。
            if (collinear_count >= 8) {
                AddEvidence(anti_cheat::INPUT_AUTOMATION_DETECTED, "检测到非自然直线鼠标移动");
                break; // 在这个数据批次中找到一个证据就足够了
            }
        }
    }
}

LRESULT CALLBACK CheatMonitor::Pimpl::LowLevelMouseProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && s_pimpl_for_hooks) {
        MSLLHOOKSTRUCT* pMouseStruct = (MSLLHOOKSTRUCT*)lParam;
        if (pMouseStruct) {
            std::lock_guard<std::mutex> lock(s_pimpl_for_hooks->m_inputMutex);
            if (wParam == WM_MOUSEMOVE) {
                s_pimpl_for_hooks->m_mouseMoveEvents.push_back({pMouseStruct->pt, pMouseStruct->time});
            } else if (wParam == WM_LBUTTONDOWN || wParam == WM_RBUTTONDOWN) {
                s_pimpl_for_hooks->m_mouseClickEvents.push_back({pMouseStruct->time});
            }
        }
    }
    // 务必调用 CallNextHookEx 将消息传递给钩子链中的下一个钩子
   return CallNextHookEx(s_pimpl_for_hooks->m_hMouseHook, nCode, wParam, lParam);
}

/**
 * @brief 检查单个函数是否存在已知的内联挂钩模式。
 * @param moduleHandle 模块句柄。
 * @param functionName 要检查的函数名。
 */
void CheatMonitor::Pimpl::CheckFunctionForHook(HMODULE moduleHandle, std::string_view functionName) {
    if (!moduleHandle) return;

    FARPROC pFunc = GetProcAddress(moduleHandle, functionName.data());
    if (!pFunc) {
        AddEvidence(anti_cheat::INTEGRITY_API_HOOK, "无法获取API地址: " + std::string(functionName));
        return;
    }

    // 检查常见的内联挂钩模式
    // 1. JMP rel32 (E9 xx xx xx xx)
    if (*reinterpret_cast<BYTE*>(pFunc) == 0xE9) {
        AddEvidence(anti_cheat::INTEGRITY_API_HOOK, "检测到 JMP Hook: " + std::string(functionName));
    }
    // 2. JMP [addr] (FF 25 xx xx xx xx)
    else if (*reinterpret_cast<WORD*>(pFunc) == 0x25FF) {
        AddEvidence(anti_cheat::INTEGRITY_API_HOOK, "检测到 JMP [addr] Hook: " + std::string(functionName));
    }
    // 3. PUSH addr; RET (68 xx xx xx xx C3) - 另一种常见的跳转方式
    else if (*reinterpret_cast<BYTE*>(pFunc) == 0x68 && *(reinterpret_cast<BYTE*>(reinterpret_cast<uintptr_t>(pFunc) + 5)) == 0xC3) {
        AddEvidence(anti_cheat::INTEGRITY_API_HOOK, "检测到 PUSH-RET Hook: " + std::string(functionName));
    }
}

void CheatMonitor::Pimpl::Sensor_CheckApiHooks() {
    // 此传感器通过检查关键函数的前几个字节来执行基本的内联API挂钩检测。
    // 这是一种快速但简单的检测方法，可以被更复杂的技术绕过。
    // 要进行更彻底的检查，请参阅 Sensor_VerifySystemModuleIntegrity。
    static constexpr std::array<std::string_view, 1> ntdll_funcs = { "NtQuerySystemInformation" };
    static constexpr std::array<std::string_view, 3> kernel32_funcs = { "CreateToolhelp32Snapshot", "GetProcAddress", "VirtualQueryEx" };
    static constexpr std::array<std::string_view, 1> psapi_funcs = { "EnumProcessModules" };

    // 缓存模块句柄以获得轻微的性能提升
    static const HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    static const HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    static const HMODULE hPsapi = GetModuleHandleA("psapi.dll");
    if (!hNtdll || !hKernel32 || !hPsapi) {
        AddEvidence(anti_cheat::INTEGRITY_API_HOOK, "无法获取核心模块句柄 (ntdll, kernel32, or psapi)");
        return;
    }

    for (const auto& func_name : ntdll_funcs)    CheckFunctionForHook(hNtdll, func_name);
    for (const auto& func_name : kernel32_funcs) CheckFunctionForHook(hKernel32, func_name);
    for (const auto& func_name : psapi_funcs)    CheckFunctionForHook(hPsapi, func_name);
}

void CheatMonitor::Pimpl::Sensor_CheckIatHooks() {
    // 主要检查我们自己的游戏进程模块，因为这是IAT Hook最常发生的地方。
    const HMODULE hSelf = GetModuleHandle(NULL);
    if (!hSelf) return;

    // 确保 hSelf 被视为指向常量字节数据的指针，以进行只读操作
    const BYTE* baseAddress = reinterpret_cast<const BYTE*>(hSelf);

    // 1. 对于 pDosHeader:
    //    将 baseAddress 转换为 const IMAGE_DOS_HEADER*
    const IMAGE_DOS_HEADER* pDosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(baseAddress);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return; // 或者抛出异常，或者返回错误码
    }

    // 2. 对于 pNtHeaders:
    //    将 (baseAddress + offset) 转换为 const IMAGE_NT_HEADERS*
    const IMAGE_NT_HEADERS* pNtHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(baseAddress + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return; // 或者抛出异常，或者返回错误码
    }

    // 找到导入表
    IMAGE_DATA_DIRECTORY importDirectory = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDirectory.VirtualAddress == 0) {
        return; // 没有导入表
    }

    // 3. 对于 pImportDesc:
    //    将 (baseAddress + offset) 转换为 const IMAGE_IMPORT_DESCRIPTOR*
    const IMAGE_IMPORT_DESCRIPTOR* pImportDesc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(baseAddress + importDirectory.VirtualAddress);

    // 遍历每个导入的DLL
    while (pImportDesc->Name) {
        const char* dllName = reinterpret_cast<const char*>(reinterpret_cast<const BYTE*>(hSelf) + pImportDesc->Name);
        HMODULE hImportedModule = GetModuleHandleA(dllName);
        if (!hImportedModule) {
            pImportDesc++;
            continue;
        }

        const IMAGE_THUNK_DATA* pThunk = reinterpret_cast<const IMAGE_THUNK_DATA*>(baseAddress + pImportDesc->FirstThunk);
        const IMAGE_THUNK_DATA* pOrigThunk = reinterpret_cast<const IMAGE_THUNK_DATA*>(baseAddress + pImportDesc->OriginalFirstThunk);

        // 遍历该DLL导入的每个函数
        while (pOrigThunk->u1.AddressOfData) {
            const IMAGE_IMPORT_BY_NAME* pImportByName = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(baseAddress + pOrigThunk->u1.AddressOfData);
            const char* functionName = pImportByName->Name;

            // 获取原始函数地址
            FARPROC originalAddress = GetProcAddress(hImportedModule, functionName);
            // 获取IAT中当前的函数地址
            // 注意：pThunk->u1.Function 通常是可写的，因为IAT会被修改。
            // 但是在这个检查的上下文中，我们只是读取它，所以 const 指针仍然是安全的。
            // 如果你需要修改它，则需要一个非 const 的 pThunk。
            // 但对于 hook 检测，我们只读取，所以当前 const 是没问题的。
            void* currentAddress = reinterpret_cast<void*>(pThunk->u1.Function);

            if (originalAddress && currentAddress != originalAddress) {
                // 假设 AddEvidence 是可访问的成员函数或友元函数
                AddEvidence(anti_cheat::INTEGRITY_API_HOOK, "检测到IAT Hook: " + std::string(dllName) + "!" + std::string(functionName));
            }

            pOrigThunk++; // 递增 const 指针是合法的，它不修改数据，只改变指针所指的位置
            pThunk++;     // 递增 const 指针是合法的
        }
    }
}

void CheatMonitor::Pimpl::Sensor_CheckProcessHandles() {
  // 模拟 UniqueHandle
  using UniqueHandle = std::unique_ptr<void, decltype(&::CloseHandle)>;

  // 缓存函数指针以提高性能，它在运行时不会改变
  static const auto pNtQuerySystemInformation = reinterpret_cast<PNtQuerySystemInformation>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"));
  if (!pNtQuerySystemInformation) {
    // 可以在此添加证据，但这种失败很罕见，可能表示更深层次的系统问题
    return;
  }

  constexpr ULONG initialBufferSize = 0x10000; // 64KB 初始缓冲区
  ULONG bufferSize = initialBufferSize;
  std::vector<BYTE> handleInfoBuffer(bufferSize);
  NTSTATUS status;

  // Retry loop for NtQuerySystemInformation
  do {
    status = pNtQuerySystemInformation(SystemHandleInformation, handleInfoBuffer.data(), bufferSize, nullptr);
    if (status == STATUS_INFO_LENGTH_MISMATCH) {
      bufferSize *= 2; // Double the buffer size
      handleInfoBuffer.resize(bufferSize);
    } else if (!NT_SUCCESS(status)) {
      // 此调用可能在系统高负载或其他原因下失败。
      // 静默返回通常比报告一个可能是误报的错误更安全。
      return;
    }
  } while (status == STATUS_INFO_LENGTH_MISMATCH);

  const DWORD ownPid = GetCurrentProcessId();
  const auto* pHandleInfo = reinterpret_cast<const SYSTEM_HANDLE_INFORMATION*>(handleInfoBuffer.data());

  for (ULONG i = 0; i < pHandleInfo->NumberOfHandles; ++i) {
    const auto& handle = pHandleInfo->Handles[i];

    // 1. 忽略自己进程的句柄
    if (handle.UniqueProcessId == ownPid) {
      continue;
    }

    // 2. 过滤掉不感兴趣的权限，只关注那些可以读取/写入/操作内存的句柄
    if (!(handle.GrantedAccess & (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_ALL_ACCESS))) {
      continue;
    }

    // 3. 打开句柄的持有者进程
    UniqueHandle hOwnerProcess(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE, FALSE, handle.UniqueProcessId), &CloseHandle);
    if (!hOwnerProcess) {
      continue; // 无法打开进程，可能是系统进程或已退出，直接跳过
    }

    // 4. 复制句柄以检查其目标
    HANDLE hDup = nullptr;
    if (DuplicateHandle(hOwnerProcess.get(), (HANDLE)handle.HandleValue, GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
      UniqueHandle hDupManaged(hDup, &CloseHandle);

      // 检查句柄是否指向我们自己的进程
      if (GetProcessId(hDupManaged.get()) == ownPid) {
        wchar_t ownerProcessName[MAX_PATH] = {0};
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(hOwnerProcess.get(), 0, ownerProcessName, &size)) {
          std::wstring ownerNameLower = std::filesystem::path(ownerProcessName).filename().wstring();
          std::transform(ownerNameLower.begin(), ownerNameLower.end(), ownerNameLower.begin(), ::towlower);

          // 5. 与更完整的有害进程列表进行比对
          bool isHarmful = false;
          for (const auto& harmfulName : m_harmfulProcessNames) {
            if (ownerNameLower.find(harmfulName) != std::wstring::npos) {
              isHarmful = true;
              break;
            }
          }

          if (isHarmful) {
            std::string evidenceDesc = "可疑进程持有我们进程的句柄: " + Utils::WideToString(ownerNameLower);
            AddEvidence(anti_cheat::INTEGRITY_SUSPICIOUS_HANDLE, evidenceDesc);
          }
        }
      }
    } else {
      // DuplicateHandle 失败有多种原因，不一定都是恶意行为。
      // 例如，如果句柄类型不支持复制，或者对方进程权限更高。
      // 谨慎上报，可以只记录日志或在特定错误码时上报。
      DWORD lastError = GetLastError();
      if (lastError == ERROR_ACCESS_DENIED) { // 权限问题比较可疑
        wchar_t ownerProcessName[MAX_PATH] = {0};
        DWORD size = MAX_PATH;
        if (QueryFullProcessImageNameW(hOwnerProcess.get(), 0, ownerProcessName, &size)) {
          std::string evidenceDesc = "无法复制句柄(拒绝访问)，疑似恶意保护: " + Utils::WideToString(std::filesystem::path(ownerProcessName).filename().wstring());
          AddEvidence(anti_cheat::INTEGRITY_SUSPICIOUS_HANDLE, evidenceDesc);
        }
      }
    }
  }
}

void CheatMonitor::Pimpl::VerifyModuleSignature(HMODULE hModule) {
    wchar_t modPath[MAX_PATH];
    if (GetModuleFileNameW(hModule, modPath, MAX_PATH) == 0) {
        return;
    }

    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = modPath;
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    GUID guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA winTrustData = {};
    winTrustData.cbStruct = sizeof(winTrustData);
    winTrustData.pPolicyCallbackData = NULL;
    winTrustData.pSIPClientData = NULL;
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileInfo;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

    // WinVerifyTrust 返回 0 表示成功
    if (WinVerifyTrust(NULL, &guid, &winTrustData) != ERROR_SUCCESS) {
        AddEvidence(anti_cheat::RUNTIME_MODULE_NEW_UNKNOWN, "加载了未签名的模块: " + Utils::WideToString(modPath));
    }
}
