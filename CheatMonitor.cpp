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
#include <unordered_map>
#include <random>

#include <Psapi.h>
#include <TlHelp32.h>
#include <Iphlpapi.h> // 为 GetAdaptersInfo 添加头文件
#include <wintrust.h> // 为 WinVerifyTrust 添加头文件
#include <Softpub.h>  // 为 WINTRUST_ACTION_GENERIC_VERIFY_V2 GUID 添加头文件
#include <ShlObj.h>   // CSIDL_PROGRAM_FILES, SHGetFolderPathW

#include <winternl.h> // 包含 NTSTATUS 等定义

#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Bcrypt.lib") // for BCryptGenRandom
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib") // 为注册表函数 (Reg*) 添加库链接
#pragma comment(lib, "iphlpapi.lib") // 为 GetAdaptersInfo 添加库链接
#pragma comment(lib, "wintrust.lib") // 为 WinVerifyTrust 添加库链接

// [修复] 为兼容旧版Windows SDK (pre-Win8)，手动定义缺失的类型
#if (NTDDI_VERSION < NTDDI_WIN8)
typedef enum _PROCESS_MITIGATION_POLICY
{
    ProcessDEPPolicy = 0,
    ProcessChildProcessPolicy = 8,
} PROCESS_MITIGATION_POLICY;

typedef struct _PROCESS_MITIGATION_CHILD_PROCESS_POLICY
{
    DWORD NoChildProcessCreation : 1;
    DWORD AuditNoChildProcessCreation : 1;
    DWORD AllowSecureProcessCreation : 1;
    DWORD ReservedFlags : 29;
} PROCESS_MITIGATION_CHILD_PROCESS_POLICY, *PPROCESS_MITIGATION_CHILD_PROCESS_POLICY;

typedef struct _PROCESS_MITIGATION_DEP_POLICY
{
    DWORD Enable : 1;
    DWORD DisableAtlThunkEmulation : 1;
    DWORD ReservedFlags : 30;
    BOOLEAN Permanent;
} PROCESS_MITIGATION_DEP_POLICY, *PPROCESS_MITIGATION_DEP_POLICY;
#endif // (NTDDI_VERSION < NTDDI_WIN8)

// --- 为 NtQuerySystemInformation 定义必要的结构体和类型 ---
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004L
#endif

// [修复] 为兼容旧版SDK，手动定义缺失的枚举值
// SystemCodeIntegrityInformation 在 Windows 8 SDK (NTDDI_WIN8) 中被定义为枚举。
// #ifndef 无法检测到枚举成员，因此我们必须使用SDK版本进行条件编译。
#if (NTDDI_VERSION < NTDDI_WIN8)
const int SystemCodeIntegrityInformation = 102;
#endif
const int SystemHandleInformation = 16;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS(WINAPI *PNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

// --- 为线程隐藏定义必要的结构体和类型 ---
typedef NTSTATUS(WINAPI *PNtSetInformationThread)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength);

typedef NTSTATUS(WINAPI *PNtQueryInformationThread)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength);

// 将函数指针定义为文件内静态变量，避免在多个函数中重复定义。
static const auto g_pNtQuerySystemInformation = reinterpret_cast<PNtQuerySystemInformation>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"));
static const auto g_pNtSetInformationThread = reinterpret_cast<PNtSetInformationThread>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationThread"));
static const auto g_pNtQueryInformationThread = reinterpret_cast<PNtQueryInformationThread>(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread"));

// --- 为系统完整性检测定义必要的结构体 ---
typedef struct _SYSTEM_CODE_INTEGRITY_INFORMATION
{
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SYSTEM_CODE_INTEGRITY_INFORMATION, *PSYSTEM_CODE_INTEGRITY_INFORMATION;

// --- 为VEH Hook检测定义未公开的结构体 ---
// 这些结构基于逆向工程，可能在不同Windows版本间有差异。
// __try/__except 块对于保证稳定性至关重要。

// PEB->VectoredExceptionHandlers 指向的结构体
typedef struct _VECTORED_HANDLER_LIST
{
    SRWLOCK Lock;
    LIST_ENTRY List;
} VECTORED_HANDLER_LIST, *PVECTORED_HANDLER_LIST;

// 链表中的节点结构
// 简化结构以提高跨版本兼容性，移除了不确定存在的 RefCount 成员。
// Handler 假定紧跟在 List 成员之后，这是更常见和稳定的布局。
typedef struct _VECTORED_HANDLER_ENTRY
{
    LIST_ENTRY List;
    PVOID Handler;
} VECTORED_HANDLER_ENTRY, *PVECTORED_HANDLER_ENTRY;

// --- 为内核调试器检测定义必要的结构体 ---
const int SystemKernelDebuggerInformation = 35;
typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

namespace Utils
{
    std::string WideToString(const std::wstring &wstr)
    {
        if (wstr.empty())
            return std::string();
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
        if (size_needed == 0)
        {
            std::cout << "WideCharToMultiByte failed to get size" << std::endl;
            return std::string();
        }
        std::string strTo(size_needed, 0);
        if (WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL) == 0)
        {
            std::cout << "WideCharToMultiByte failed to convert string" << std::endl;
            return std::string();
        }
        return strTo;
    }

    // [性能优化] 使用单次遍历和哈希表来查找父进程，避免双重循环。
    bool GetParentProcessInfo(DWORD &parentPid, std::string &parentName)
    {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        // 使用智能指针确保句柄总是被关闭
        auto snapshot_closer = [](HANDLE h)
        { CloseHandle(h); };
        std::unique_ptr<void, decltype(snapshot_closer)> snapshot_handle(hSnapshot, snapshot_closer);

        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(PROCESSENTRY32W);
        const DWORD currentPid = GetCurrentProcessId();
        DWORD ppid = 0;
        std::unordered_map<DWORD, std::wstring> processMap;

        if (Process32FirstW(hSnapshot, &pe))
        {
            do
            {
                processMap[pe.th32ProcessID] = pe.szExeFile;
                if (pe.th32ProcessID == currentPid)
                {
                    ppid = pe.th32ParentProcessID;
                }
            } while (Process32NextW(hSnapshot, &pe));
        }
        else
        {
            return false; // 遍历失败
        }

        if (ppid > 0)
        {
            auto it = processMap.find(ppid);
            if (it != processMap.end())
            {
                parentPid = ppid;
                parentName = WideToString(it->second);
                return true;
            }
        }

        return false; // 未找到父进程
    }

    std::string GenerateUuid()
    {
        GUID guid;
        if (CoCreateGuid(&guid) == S_OK)
        {
            wchar_t uuid_w[40] = {0};
            StringFromGUID2(guid, uuid_w, 40);
            return WideToString(uuid_w);
        }
        else
        {
            std::cout << "[AntiCheat] GenerateUuid Error: CoCreateGuid failed." << std::endl;
        }
        return "";
    }

    std::wstring StringToWide(const std::string &str)
    {
        if (str.empty())
            return std::wstring();
        int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
        std::wstring wstrTo(size_needed, 0);
        MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
        return wstrTo;
    }

    // 为兼容旧版Windows（Vista之前），提供一个QueryFullProcessImageNameW的安全替代方案。
    std::wstring GetProcessFullName(HANDLE hProcess)
    {
        wchar_t processName[MAX_PATH] = {0};

        // 优先使用 QueryFullProcessImageNameW (Vista+)
        typedef BOOL(WINAPI * PQueryFullProcessImageNameW)(HANDLE, DWORD, LPWSTR, PDWORD);
        static PQueryFullProcessImageNameW pQueryFullProcessImageNameW =
            (PQueryFullProcessImageNameW)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "QueryFullProcessImageNameW");

        if (pQueryFullProcessImageNameW)
        {
            DWORD size = MAX_PATH;
            if (pQueryFullProcessImageNameW(hProcess, 0, processName, &size))
            {
                return processName;
            }
            // 如果失败，不记录日志，因为我们会尝试降级方案
        }

        // 降级方案：使用 GetModuleFileNameExW (XP+)
        if (GetModuleFileNameExW(hProcess, NULL, processName, MAX_PATH))
        {
            return processName;
        }

        // 如果所有方法都失败了，才记录错误
        // 注意：这里不能调用AddEvidence，因为它是一个通用工具函数。
        // 调用者需要负责处理空字符串的返回值。
        return L""; // 获取失败
    }

    // 通用的文件签名验证辅助函数
    bool VerifyFileSignature(const std::wstring &filePath)
    {
        WINTRUST_FILE_INFO fileInfo = {};
        fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
        fileInfo.pcwszFilePath = filePath.c_str();
        fileInfo.hFile = NULL;
        fileInfo.pgKnownSubject = NULL;

        GUID guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        WINTRUST_DATA winTrustData = {};
        winTrustData.cbStruct = sizeof(winTrustData);
        winTrustData.dwUIChoice = WTD_UI_NONE;
        winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
        winTrustData.pFile = &fileInfo;
        winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

        LONG result = WinVerifyTrust(NULL, &guid, &winTrustData);

        // 无论成功与否，都必须调用CLOSE来释放资源
        winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &guid, &winTrustData);

        return (result == ERROR_SUCCESS);
    }

}

namespace
{ // 匿名命名空间，用于辅助函数

    // [新增] 指针验证函数（需根据环境实现）
    bool IsValidPointer(const void *ptr, size_t size)
    {
        if (!ptr)
            return false;

        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0)
            return false;

        // 检查内存是否已提交且可读
        if (mbi.State != MEM_COMMIT || !(mbi.Protect & (PAGE_READONLY | PAGE_READWRITE)))
            return false;

        // 确保请求的内存范围在同一内存页面内
        return ((uintptr_t)ptr + size) <= ((uintptr_t)mbi.BaseAddress + mbi.RegionSize);
    }

    // 获取模块路径的占位符（替换为实际实现）
    bool GetModulePathForAddress(PVOID address, wchar_t *buffer, size_t bufferSize)
    {
        HMODULE hModule = nullptr;
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCWSTR)address, &hModule) && hModule)
        {
            return GetModuleFileNameW(hModule, buffer, static_cast<DWORD>(bufferSize)) != 0;
        }
        return false;
    }

    // 用于动态查找VEH链表偏移量的“诱饵”处理函数。
    // 它什么也不做，只是作为一个可被识别的指针存在。
    LONG WINAPI DecoyVehHandler(PEXCEPTION_POINTERS ExceptionInfo)
    {
        UNREFERENCED_PARAMETER(ExceptionInfo);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // 此函数不应使用任何需要堆栈展开的C++对象。
    // [修复] 使用 __try/__except 块来安全地执行此反调试检查。
    // 如果没有调试器，会触发一个异常并被捕获。如果附加了调试器，它可能会“吞掉”这个异常，
    // 从而改变程序的执行路径，但这本身不是一个可靠的证据来源，更多是用于增加逆向分析的难度。
    void CheckCloseHandleException()
    {
        __try
        {
            // 使用 reinterpret_cast 和 uintptr_t 以避免C4312警告 (在64位上从int到更大的指针的转换)
            CloseHandle(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(0xDEADBEEF)));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            // 异常被捕获，这是没有调试器时的预期行为。什么也不做。
        }
    }

    // [新增] 辅助函数：通过KUSER_SHARED_DATA检测内核调试器
    // 此函数不应使用任何需要堆栈展开的C++对象。
    bool IsKernelDebuggerPresent_KUserSharedData()
    {
        __try
        {
            // KUSER_SHARED_DATA is a well-known, fixed address in user-mode.
            const UCHAR *pSharedData = (const UCHAR *)0x7FFE0000;
            // The KdDebuggerEnabled flag is at offset 0x2D4.
            const BOOLEAN kdDebuggerEnabled = *(pSharedData + 0x2D4);
            return kdDebuggerEnabled;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            // Accessing the address failed. This can happen in some sandboxed
            // environments or future Windows versions. Treat as not present.
            return false;
        }
    }
    // 辅助函数：获取模块的代码节信息 (.text)
    bool GetCodeSectionInfo(HMODULE hModule, PVOID &outBase, DWORD &outSize)
    {
        if (!hModule)
            return false;
        const BYTE *baseAddress = reinterpret_cast<const BYTE *>(hModule);
        __try
        {
            const auto *pDosHeader = reinterpret_cast<const IMAGE_DOS_HEADER *>(baseAddress);
            if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
                return false;

            const auto *pNtHeaders = reinterpret_cast<const IMAGE_NT_HEADERS *>(baseAddress + pDosHeader->e_lfanew);
            if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
                return false;

            PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
            for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++)
            {
                // 寻找第一个可执行代码节 (通常是 .text)
                if (pSectionHeader->Characteristics & IMAGE_SCN_CNT_CODE)
                {
                    outBase = (PVOID)(baseAddress + pSectionHeader->VirtualAddress);
                    outSize = pSectionHeader->Misc.VirtualSize;
                    return true;
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            // 访问模块内存失败，可能模块已被卸载或内存损坏
            return false;
        }
        return false;
    }
#pragma warning(pop)

    // 辅助函数：计算内存块的哈希值 (使用FNV-1a算法)
    // 注意：FNV-1a 是一种快速非密码学哈希。对于高安全要求，应考虑使用密码学安全哈希（如SHA-256）。
    std::vector<uint8_t> CalculateHash(const BYTE *data, size_t size)
    {
        uint64_t hash = 14695981039346656037ULL;     // FNV_OFFSET_BASIS_64
        const uint64_t fnv_prime = 1099511628211ULL; // FNV_PRIME_64

        for (size_t i = 0; i < size; ++i)
        {
            hash ^= data[i];
            hash *= fnv_prime;
        }
        std::vector<uint8_t> result(sizeof(hash));
        memcpy(result.data(), &hash, sizeof(hash));
        return result;
    }

#pragma warning(pop) // [修复] 与上面的push配对

}



// --- [重构] 核心架构组件 ---

class ScanContext;

// ISensor: 所有检测传感器的抽象基类接口 (策略模式)
class ISensor
{
public:
    virtual ~ISensor() = default;
    virtual const char *GetName() const = 0; // 用于日志和调试
    virtual void Execute(ScanContext &context) = 0;
};

struct CheatMonitor::Pimpl
{
    std::atomic<bool> m_isSystemActive = false;
    std::atomic<bool> m_isSessionActive = false;
    std::thread m_monitorThread;
    std::condition_variable m_cv;
    std::mutex m_cvMutex;
    std::mutex m_modulePathsMutex; // [修复] 保护 m_legitimateModulePaths 的并发访问

    std::mutex m_sessionMutex;
    uint32_t m_currentUserId = 0;
    std::string m_currentUserName;

    std::set<std::pair<anti_cheat::CheatCategory, std::string>> m_uniqueEvidence;
    std::vector<anti_cheat::Evidence> m_evidences;

    // [新增] 用于控制会话基线重建的标志
    std::atomic<bool> m_newSessionNeedsBaseline = false;

    // [性能优化] 使用哈希集合进行O(1)复杂度的父进程白名单检查
    const std::unordered_set<std::string> m_legitimateParentProcesses = {
        "yourlauncher.exe", // 必须包含官方启动器! 请替换为真实名称 (小写)。
        "explorer.exe",     // Windows Shell
        "devenv.exe",       // Visual Studio
        "cmd.exe",          // 命令提示符
        "powershell.exe",   // PowerShell
        "code.exe"          // Visual Studio Code
    };
    const std::vector<std::wstring> m_harmfulProcessNames = {
        // 内存修改器 & 调试器
        L"cheatengine", L"ollydbg", L"x64dbg", L"x32dbg", L"ida64", L"ida", L"windbg",
        L"processhacker", L"artmoney", L"ghidra", L"reclass", L"reclass.net",
        // 网络抓包
        L"fiddler", L"wireshark", L"charles",
        // 自动化 & 宏
        L"autohotkey"};
    const std::vector<std::wstring> m_harmfulKeywords = {
        // 中文
        L"外挂", L"辅助", L"脚本", L"注入", L"透视", L"自瞄", L"内存修改", L"调试", L"反汇编", L"吾爱破解",
        // 英文
        L"cheat engine", L"hack", L"trainer", L"bot", L"aimbot", L"wallhack", L"speedhack",
        L"memory editor", L"debugger", L"disassembler", L"injector", L"packet editor"};
    // 使用 std::set 以获得更快的查找速度 (O(logN)) 并自动处理重复项
    std::set<DWORD> m_knownThreadIds;
    std::set<HMODULE> m_knownModules;
    //  硬件指纹信息，只在首次登录时收集一次
    std::unique_ptr<anti_cheat::HardwareFingerprint> m_fingerprint;
    std::unordered_set<std::wstring> m_legitimateModulePaths;                                          // 使用哈希集合以实现O(1)复杂度的快速查找
    std::unordered_map<uintptr_t, std::chrono::steady_clock::time_point> m_reportedIllegalCallSources; // 用于记录已上报的非法调用来源，并实现5分钟上报冷却
    //  记录每个用户、每种作弊类型的最近上报时间，防止重复上报
    std::map<std::pair<uint32_t, anti_cheat::CheatCategory>, std::chrono::steady_clock::time_point> m_lastReported;

    static constexpr auto kReportCooldownMinutes = std::chrono::minutes(30);

    // --- Input Automation Detection ---
    struct MouseMoveEvent
    {
        POINT pt;
        DWORD time;
    };
    struct MouseClickEvent
    {
        DWORD time;
    };

    HHOOK m_hMouseHook = NULL;
    std::mutex m_inputMutex;
    std::vector<MouseMoveEvent> m_mouseMoveEvents;
    std::vector<MouseClickEvent> m_mouseClickEvents;
    static Pimpl *s_pimpl_for_hooks; // Static pointer for hook procedures

    static constexpr size_t kMaxMouseMoveEvents = 5000; // 最大存储5000个鼠标移动事件
    static constexpr size_t kMaxMouseClickEvents = 500; // 最大存储500个鼠标点击事件

    std::mt19937 m_rng;      // 随机数生成器
    std::random_device m_rd; // 随机数种子

    // [新增] 白名单列表
    std::unordered_set<std::wstring> m_whitelistedProcessPaths;   // 白名单进程完整路径 (小写)
    std::unordered_set<std::wstring> m_whitelistedWindowKeywords; // 白名单窗口标题关键词 (小写)

    // [新增] IAT Hook 白名单
    std::unordered_set<std::string> m_whitelistedIATHooks; // 存储 "DLL!Function" 格式的白名单

    // [新增] VEH Hook 白名单
    std::unordered_set<std::wstring> m_whitelistedVEHModules; // 存储白名单VEH处理函数所属的模块路径 (小写)

    // 模块签名验证缓存
    enum class SignatureVerdict
    {
        UNKNOWN,
        SIGNED_AND_TRUSTED,
        UNSIGNED_OR_UNTRUSTED,
        VERIFICATION_FAILED
    };
    std::unordered_map<std::wstring, std::pair<SignatureVerdict, std::chrono::steady_clock::time_point>> m_moduleSignatureCache;
    // [新增] 进程句柄检测缓存
    enum class ProcessVerdict
    {
        UNKNOWN,
        SIGNED_AND_TRUSTED,
        UNSIGNED_OR_UNTRUSTED
    };
    std::unordered_map<DWORD, std::pair<ProcessVerdict, std::chrono::steady_clock::time_point>> m_processVerdictCache;
    static constexpr auto kProcessCacheDuration = std::chrono::minutes(15); // 进程可信度缓存15分钟

    static constexpr auto kSignatureCacheDuration = std::chrono::minutes(60); // 缓存60分钟

    // 存储关键模块代码节的基线哈希值
    std::unordered_map<std::wstring, std::vector<uint8_t>> m_moduleBaselineHashes;

    // [重构] IAT Hook检测基线：为每个导入的DLL存储一个独立的哈希值
    std::unordered_map<std::string, std::vector<uint8_t>> m_iatBaselineHashes;
    uintptr_t m_vehListOffset = 0; // [新增] 存储VEH链表在PEB中的偏移量

    // [新增] 传感器集合
    std::vector<std::unique_ptr<ISensor>> m_lightweight_sensors;
    std::vector<std::unique_ptr<ISensor>> m_heavyweight_sensors;

    // Main loop and state management
    void MonitorLoop();
    void UploadReport();
    void InitializeSystem();
    void InitializeGlobalState();
    void InitializeSessionBaseline();
    void ResetSessionState();
    void AddEvidence(anti_cheat::CheatCategory category, const std::string &description);
    void HardenProcessAndThreads(); //  进程与线程加固

    // --- Sensor Functions ---
    void Sensor_CheckProcessHandles();
    bool Sensor_ValidateParentProcess();
    void Sensor_ScanNewActivity();
    void Sensor_ScanMemory();

    void Sensor_CheckEnvironment();
    void Sensor_DetectVirtualMachine();
    std::vector<std::string> CollectHardwareFingerprintErrors(); //  收集硬件指纹并返回错误
    void Sensor_CheckSystemIntegrityState();  //  系统完整性状态检测
    void Sensor_CheckAdvancedAntiDebug();     //  高级反调试检测
    void Sensor_CheckIatHooks();              //  IAT Hook 检测
    void Sensor_CheckVehHooks();
    void Sensor_CheckInputAutomation(); //  输入自动化检测

    void DoCheckIatHooks(ScanContext &context, const BYTE *baseAddress, const IMAGE_IMPORT_DESCRIPTOR *pImportDesc);
    void VerifyModuleIntegrity(const wchar_t *moduleName); //  通用模块验证辅助函数
    void VerifyModuleSignature(HMODULE hModule);

    // Helper to check if an address belongs to a whitelisted module
    bool IsAddressInLegitimateModule(PVOID address, std::wstring &outModulePath);
    // 动态查找VEH链表在PEB中的偏移量
    uintptr_t FindVehListOffset();

    // VM detection helpers
    void DetectVmByCpuid();
    void DetectVmByRegistry();
    void DetectVmByMacAddress();

    // --- Hook Procedures ---
    static LRESULT CALLBACK LowLevelMouseProc(int nCode, WPARAM wParam, LPARAM lParam);
    static LPVOID WINAPI DetourVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

    // Shellcode检测：安装和卸载API钩子
    void InstallVirtualAllocHook();
    void UninstallVirtualAllocHook();

    // [新增] VirtualAlloc Hook状态管理
    bool m_isVirtualAllocHooked = false;
    BYTE m_originalVirtualAllocBytes[5] = {0}; // 假设JMP指令长度为5

    std::mutex m_hookMutex; // 用于保护 hook 安装/卸载的互斥锁
};

// ScanContext: 为传感器提供所需依赖的上下文对象
// 这是“依赖倒置”原则的体现，传感器不直接依赖Pimpl，而是依赖这个抽象的上下文
class ScanContext
{
private:
    CheatMonitor::Pimpl *m_pimpl; //  持有对Pimpl的指针

public:
    explicit ScanContext(CheatMonitor::Pimpl *p) : m_pimpl(p) {}

    // --- 提供给传感器的服务 ---
    void AddEvidence(anti_cheat::CheatCategory category, const std::string &description)
    {
        m_pimpl->AddEvidence(category, description);
    }

    // --- 提供对配置的只读访问 ---
    const std::vector<std::wstring> &GetHarmfulProcessNames() const { return m_pimpl->m_harmfulProcessNames; }
    const std::vector<std::wstring> &GetHarmfulKeywords() const { return m_pimpl->m_harmfulKeywords; }
    const std::unordered_set<std::wstring> &GetWhitelistedProcessPaths() const { return m_pimpl->m_whitelistedProcessPaths; }
    const std::unordered_set<std::wstring> &GetWhitelistedWindowKeywords() const { return m_pimpl->m_whitelistedWindowKeywords; }
    const std::unordered_map<std::string, std::vector<uint8_t>> &GetIatBaselineHashes() const { return m_pimpl->m_iatBaselineHashes; }
    const std::unordered_map<std::wstring, std::vector<uint8_t>> &GetModuleBaselineHashes() const { return m_pimpl->m_moduleBaselineHashes; }
    uintptr_t GetVehListOffset() const { return m_pimpl->m_vehListOffset; }
    const std::unordered_set<std::wstring> &GetWhitelistedVEHModules() const { return m_pimpl->m_whitelistedVEHModules; }
    bool IsAddressInLegitimateModule(PVOID address, std::wstring &outModulePath) { return m_pimpl->IsAddressInLegitimateModule(address, outModulePath); }

    // --- 提供对缓存的访问 ---
    std::unordered_map<DWORD, std::pair<CheatMonitor::Pimpl::ProcessVerdict, std::chrono::steady_clock::time_point>> &GetProcessVerdictCache() { return m_pimpl->m_processVerdictCache; }

    // --- 提供对输入数据的访问 ---
    std::vector<CheatMonitor::Pimpl::MouseMoveEvent> &GetMouseMoveEvents() { return m_pimpl->m_mouseMoveEvents; }
    std::vector<CheatMonitor::Pimpl::MouseClickEvent> &GetMouseClickEvents() { return m_pimpl->m_mouseClickEvents; }
    std::mutex &GetInputMutex() { return m_pimpl->m_inputMutex; }

    // --- 提供对已知状态的访问 ---
    std::set<DWORD> &GetKnownThreadIds() { return m_pimpl->m_knownThreadIds; }
    std::set<HMODULE> &GetKnownModules() { return m_pimpl->m_knownModules; }
    void VerifyModuleSignature(HMODULE hModule) { m_pimpl->VerifyModuleSignature(hModule); }
};

namespace InputAnalysis
{
    // 计算标准差，用于判断点击间隔的规律性
    double CalculateStdDev(const std::vector<double> &values)
    {
        if (values.size() < 2)
            return 0.0;
        double sum = std::accumulate(values.begin(), values.end(), 0.0);
        double mean = sum / values.size();
        double sq_sum = std::inner_product(values.begin(), values.end(), values.begin(), 0.0);
        double variance = sq_sum / values.size() - mean * mean;
        return variance > 0 ? std::sqrt(variance) : 0.0;
    }

    // 检查三点是否共线，用于判断鼠标轨迹是否为完美的直线
    bool ArePointsCollinear(POINT p1, POINT p2, POINT p3)
    {
        // 使用2D向量的叉积。如果叉积为0，则三点共线。
        // (p2.y - p1.y) * (p3.x - p2.x) - (p2.x - p1.x) * (p3.y - p2.y) == 0
        long long cross_product = static_cast<long long>(p2.y - p1.y) * (p3.x - p2.x) - static_cast<long long>(p2.x - p1.x) * (p3.y - p2.y);
        return cross_product == 0;
    }
}
// --- [重构] 将所有传感器实现移入独立的类中 ---
namespace Sensors
{

    // --- 轻量级传感器 ---

    class AdvancedAntiDebugSensor : public ISensor
    {
    public:
        const char *GetName() const override { return "AdvancedAntiDebugSensor"; }
        void Execute(ScanContext &context) override
        {
            // 该传感器的逻辑直接从原 Sensor_CheckAdvancedAntiDebug 函数迁移而来
            std::array<std::function<void()>, 6> checks = {
                [&]()
                {
                    BOOL isDebuggerPresent = FALSE;
                    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent) && isDebuggerPresent)
                    {
                        context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, "CheckRemoteDebuggerPresent() API返回true");
                    }
                },
                [&]()
                {
#ifdef _WIN64
                    auto pPeb = (PPEB)__readgsqword(0x60);
#else
                    auto pPeb = (PPEB)__readfsdword(0x30);
#endif
                    if (pPeb && pPeb->BeingDebugged)
                    {
                        context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, "PEB->BeingDebugged 标志位为true");
                    }
                },
                []()
                { CheckCloseHandleException(); },
                [&]()
                {
                    CONTEXT ctx = {};
                    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                    if (GetThreadContext(GetCurrentThread(), &ctx))
                    {
                        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0)
                        {
                            context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, "检测到硬件断点 (Debug Registers)");
                        }
                    }
                },
                [&]()
                {
                    SYSTEM_KERNEL_DEBUGGER_INFORMATION info;
                    if (g_pNtQuerySystemInformation && NT_SUCCESS(g_pNtQuerySystemInformation(SystemKernelDebuggerInformation, &info, sizeof(info), NULL)))
                    {
                        if (info.KernelDebuggerEnabled && !info.KernelDebuggerNotPresent)
                        {
                            context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, "检测到内核调试器 (NtQuerySystemInformation)");
                        }
                    }
                },
                [&]()
                {
                    if (IsKernelDebuggerPresent_KUserSharedData())
                    {
                        context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, "检测到内核调试器 (KUSER_SHARED_DATA)");
                    }
                }};
            for (const auto &check : checks)
            {
                check();
            }
        }
    };

    class MemoryScanSensor : public ISensor
    {
    public:
        const char *GetName() const override { return "MemoryScanSensor"; }
        void Execute(ScanContext &context) override
        {
            for (const auto &[modulePath, baselineHash] : context.GetModuleBaselineHashes())
            {
                HMODULE hModule = GetModuleHandleW(modulePath.c_str());
                if (!hModule)
                    continue;

                PVOID codeBase = nullptr;
                DWORD codeSize = 0;
                if (GetCodeSectionInfo(hModule, codeBase, codeSize))
                {
                    std::vector<uint8_t> currentHash = CalculateHash(static_cast<BYTE *>(codeBase), codeSize);
                    if (currentHash != baselineHash)
                    {
                        context.AddEvidence(anti_cheat::INTEGRITY_MEMORY_PATCH, "检测到内存代码节被篡改: " + Utils::WideToString(modulePath));
                    }
                }
            }
        }
    };

    class SystemIntegritySensor : public ISensor
    {
    public:
        const char *GetName() const override { return "SystemIntegritySensor"; }
        void Execute(ScanContext &context) override
        {
            SYSTEM_CODE_INTEGRITY_INFORMATION sci = {sizeof(sci), 0};
            if (g_pNtQuerySystemInformation && NT_SUCCESS(g_pNtQuerySystemInformation(SystemCodeIntegrityInformation, &sci, sizeof(sci), nullptr)))
            {
                if (sci.CodeIntegrityOptions & 0x02)
                {
                    context.AddEvidence(anti_cheat::ENVIRONMENT_SUSPICIOUS_DRIVER, "系统开启了测试签名模式 (Test Signing Mode)");
                }
                if (sci.CodeIntegrityOptions & 0x01)
                {
                    context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, "系统开启了内核调试模式 (Kernel Debugging Enabled)");
                }
            }
        }
    };

// 辅助函数，安全地执行 IAT 钩子检查，避免 SEH 和 C2712 错误
static void CheckIatHooksSafe(ScanContext &context, const BYTE *baseAddress)
{
    // 验证 baseAddress 是否有效
    if (!baseAddress || !IsValidPointer(baseAddress, sizeof(IMAGE_DOS_HEADER)))
    {
        context.AddEvidence(anti_cheat::RUNTIME_ERROR, "IAT Hook检测失败：无效的基地址或不可读内存。");
        return;
    }

    const IMAGE_DOS_HEADER *pDosHeader = reinterpret_cast<const IMAGE_DOS_HEADER *>(baseAddress);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        context.AddEvidence(anti_cheat::RUNTIME_ERROR, "IAT Hook检测失败：无效的 DOS 签名。");
        return;
    }

    // 计算 NT 头地址并验证
    const BYTE *ntHeaderAddress = baseAddress + pDosHeader->e_lfanew;
    if (!IsValidPointer(ntHeaderAddress, sizeof(IMAGE_NT_HEADERS)))
    {
        context.AddEvidence(anti_cheat::RUNTIME_ERROR, "IAT Hook检测失败：NT 头地址无效或不可读。");
        return;
    }

    const IMAGE_NT_HEADERS *pNtHeaders = reinterpret_cast<const IMAGE_NT_HEADERS *>(ntHeaderAddress);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        context.AddEvidence(anti_cheat::RUNTIME_ERROR, "IAT Hook检测失败：无效的 NT 签名。");
        return;
    }

    // 检查导入表目录
    IMAGE_DATA_DIRECTORY importDirectory = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDirectory.VirtualAddress == 0 || importDirectory.Size == 0)
    {
        return; // 没有导入表，正常情况，直接返回
    }

    // 计算导入表描述符地址并验证
    const BYTE *importDescAddress = baseAddress + importDirectory.VirtualAddress;
    if (!IsValidPointer(importDescAddress, sizeof(IMAGE_IMPORT_DESCRIPTOR)))
    {
        context.AddEvidence(anti_cheat::RUNTIME_ERROR, "IAT Hook检测失败：导入表地址无效或不可读。");
        return;
    }

    const IMAGE_IMPORT_DESCRIPTOR *pImportDesc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR *>(importDescAddress);
    CheatMonitor::Pimpl::s_pimpl_for_hooks->DoCheckIatHooks(context, baseAddress, pImportDesc);
}

    class IatHookSensor : public ISensor
    {
    public:
        const char *GetName() const override { return "IatHookSensor"; }
        void Execute(ScanContext &context) override
        {
            const HMODULE hSelf = GetModuleHandle(NULL);
            if (!hSelf)
                return;

            CheckIatHooksSafe(context, reinterpret_cast<const BYTE *>(hSelf));
        }
    };

    class VehHookSensor : public ISensor
    {
    public:
        const char *GetName() const override { return "VehHookSensor"; }
        void Execute(ScanContext &context) override
        {
#ifdef _WIN64
            const auto pPeb = reinterpret_cast<const BYTE *>(__readgsqword(0x60));
#else
            const auto pPeb = reinterpret_cast<const BYTE *>(__readfsdword(0x30));
#endif
            if (!pPeb || context.GetVehListOffset() == 0)
                return;

            const auto *pVehList = *reinterpret_cast<const VECTORED_HANDLER_LIST *const *>(pPeb + context.GetVehListOffset());
            if (!pVehList)
                return;

            const LIST_ENTRY *pListHead = &pVehList->List;
            const LIST_ENTRY *pCurrentEntry = pListHead->Flink;
            int handlerIndex = 0;
            constexpr int maxHandlersToScan = 32;

            // 辅助函数处理每个处理程序，避免在关键部分使用 C++ 对象展开
            auto ProcessHandler = [&](const VECTORED_HANDLER_ENTRY *pHandlerEntry, int index) -> bool
            {
                const PVOID handlerAddress = pHandlerEntry->Handler;
                std::wstring modulePath;

                // IsAddressInLegitimateModule 会填充 modulePath 并检查其是否在主白名单中
                if (context.IsAddressInLegitimateModule(handlerAddress, modulePath))
                {
                    // 处理程序位于白名单模块中，无需操作
                    return true;
                }

                bool hasModule = !modulePath.empty();
                if (hasModule)
                {
                    // 将模块路径转换为小写以进行比较
                    std::wstring lowerModulePath = modulePath;
                    std::transform(lowerModulePath.begin(), lowerModulePath.end(), lowerModulePath.begin(), ::towlower);
                    if (context.GetWhitelistedVEHModules().count(lowerModulePath) == 0)
                    {
                        std::wostringstream woss;
                        woss << L"检测到可疑的VEH Hook (Handler #" << index << L").来源: " << modulePath << L", 地址: 0x" << std::hex << handlerAddress;
                        context.AddEvidence(anti_cheat::INTEGRITY_API_HOOK, Utils::WideToString(woss.str()));
                    }
                }
                else
                {
                    // 处理程序不在任何模块中，可能是 Shellcode
                    std::wostringstream woss;
                    woss << L"检测到来自Shellcode的VEH Hook (Handler #" << index << L").地址: 0x" << std::hex << handlerAddress;
                    context.AddEvidence(anti_cheat::INTEGRITY_API_HOOK, Utils::WideToString(woss.str()));
                }
                return true;
            };

            // 遍历 VEH 链表，使用指针检查避免异常
            while (pCurrentEntry && pCurrentEntry != pListHead && handlerIndex < maxHandlersToScan)
            {
                // 在解引用前验证指针有效性
                if (!IsValidPointer(pCurrentEntry, sizeof(*pCurrentEntry))) // 替换为实际的指针验证
                {
                    context.AddEvidence(anti_cheat::INTEGRITY_API_HOOK, "遍历VEH链表时检测到无效指针，链表可能已损坏。");
                    break;
                }

                const auto *pHandlerEntry = CONTAINING_RECORD(pCurrentEntry, VECTORED_HANDLER_ENTRY, List);

                if (!ProcessHandler(pHandlerEntry, handlerIndex))
                {
                    context.AddEvidence(anti_cheat::INTEGRITY_API_HOOK, "处理VEH处理程序时发生错误，链表可能已损坏。");
                    break;
                }

                pCurrentEntry = pCurrentEntry->Flink;
                handlerIndex++;
            }
        }
    };

    class InputAutomationSensor : public ISensor
    {
    public:
        const char *GetName() const override { return "InputAutomationSensor"; }
        void Execute(ScanContext &context) override
        {
            std::vector<CheatMonitor::Pimpl::MouseMoveEvent> local_moves;
            std::vector<CheatMonitor::Pimpl::MouseClickEvent> local_clicks;
            {
                std::lock_guard<std::mutex> lock(context.GetInputMutex());
                if (context.GetMouseMoveEvents().size() > 200)
                {
                    local_moves.swap(context.GetMouseMoveEvents());
                }
                if (context.GetMouseClickEvents().size() > 10)
                {
                    local_clicks.swap(context.GetMouseClickEvents());
                }
            }

            if (local_clicks.size() > 5)
            {
                std::vector<double> deltas;
                for (size_t i = 1; i < local_clicks.size(); ++i)
                {
                    deltas.push_back(static_cast<double>(local_clicks[i].time - local_clicks[i - 1].time));
                }
                double stddev = InputAnalysis::CalculateStdDev(deltas);
                if (stddev < 5.0 && stddev > 0)
                {
                    context.AddEvidence(anti_cheat::INPUT_AUTOMATION_DETECTED, "检测到规律性鼠标点击 (StdDev: " + std::to_string(stddev) + "ms)");
                }
            }

            if (local_moves.size() > 10)
            {
                int collinear_count = 0;
                for (size_t i = 2; i < local_moves.size(); ++i)
                {
                    if (InputAnalysis::ArePointsCollinear(local_moves[i - 2].pt, local_moves[i - 1].pt, local_moves[i].pt))
                    {
                        collinear_count++;
                    }
                    else
                    {
                        collinear_count = 0;
                    }
                    if (collinear_count >= 8)
                    {
                        context.AddEvidence(anti_cheat::INPUT_AUTOMATION_DETECTED, "检测到非自然直线鼠标移动");
                        break;
                    }
                }
            }
        }
    };

    // --- 重量级传感器 ---

    class ProcessHandleSensor : public ISensor
    {
    public:
        const char *GetName() const override { return "ProcessHandleSensor"; }
        void Execute(ScanContext &context) override
        {
            if (!g_pNtQuerySystemInformation)
                return;

            ULONG bufferSize = 0x10000;
            std::vector<BYTE> handleInfoBuffer(bufferSize);
            NTSTATUS status;

            do
            {
                status = g_pNtQuerySystemInformation(SystemHandleInformation, handleInfoBuffer.data(), bufferSize, nullptr);
                if (status == STATUS_INFO_LENGTH_MISMATCH)
                {
                    bufferSize *= 2;
                    if (bufferSize > 0x4000000)
                        return;
                    handleInfoBuffer.resize(bufferSize);
                }
            } while (status == STATUS_INFO_LENGTH_MISMATCH);

            if (!NT_SUCCESS(status))
                return;

            const DWORD ownPid = GetCurrentProcessId();
            const auto *pHandleInfo = reinterpret_cast<const SYSTEM_HANDLE_INFORMATION *>(handleInfoBuffer.data());
            const auto now = std::chrono::steady_clock::now();

            for (ULONG i = 0; i < pHandleInfo->NumberOfHandles; ++i)
            {
                const auto &handle = pHandleInfo->Handles[i];
                if (handle.UniqueProcessId == ownPid || !(handle.GrantedAccess & (PROCESS_VM_READ | PROCESS_VM_WRITE)))
                    continue;

                auto &cache = context.GetProcessVerdictCache();
                auto cacheIt = cache.find(handle.UniqueProcessId);
                if (cacheIt != cache.end())
                {
                    if (now < cacheIt->second.second + CheatMonitor::Pimpl::kProcessCacheDuration)
                    {
                        if (cacheIt->second.first == CheatMonitor::Pimpl::ProcessVerdict::SIGNED_AND_TRUSTED)
                            continue;
                    }
                    else
                    {
                        cache.erase(cacheIt);
                    }
                }

                using UniqueHandle = std::unique_ptr<void, decltype(&::CloseHandle)>;
                UniqueHandle hOwnerProcess(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE, FALSE, handle.UniqueProcessId), &::CloseHandle);
                if (!hOwnerProcess.get())
                    continue;

                HANDLE hDup = nullptr;
                if (DuplicateHandle(hOwnerProcess.get(), (HANDLE)handle.HandleValue, GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS))
                {
                    UniqueHandle hDupManaged(hDup, &::CloseHandle);
                    if (GetProcessId(hDupManaged.get()) == ownPid)
                    {
                        CheatMonitor::Pimpl::ProcessVerdict currentVerdict = CheatMonitor::Pimpl::ProcessVerdict::UNSIGNED_OR_UNTRUSTED;
                        std::wstring ownerProcessPath = Utils::GetProcessFullName(hOwnerProcess.get());
                        if (!ownerProcessPath.empty())
                        {
                            if (Utils::VerifyFileSignature(ownerProcessPath))
                            {
                                currentVerdict = CheatMonitor::Pimpl::ProcessVerdict::SIGNED_AND_TRUSTED;
                            }
                        }
                        cache[handle.UniqueProcessId] = {currentVerdict, now};
                        if (currentVerdict == CheatMonitor::Pimpl::ProcessVerdict::UNSIGNED_OR_UNTRUSTED)
                        {
                            std::wstring filename = ownerProcessPath.empty() ? L"Unknown" : std::filesystem::path(ownerProcessPath).filename().wstring();
                            context.AddEvidence(anti_cheat::INTEGRITY_SUSPICIOUS_HANDLE, "未签名的可疑进程持有我们进程的句柄: " + Utils::WideToString(filename) + " (PID: " + std::to_string(handle.UniqueProcessId) + ")");
                        }
                    }
                }
            }
        }
    };

    class NewActivitySensor : public ISensor
    {
    public:
        const char *GetName() const override { return "NewActivitySensor"; }
        void Execute(ScanContext &context) override
        {
            // Scan for new threads
            HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (hThreadSnapshot != INVALID_HANDLE_VALUE)
            {
                THREADENTRY32 te;
                te.dwSize = sizeof(te);
                if (Thread32First(hThreadSnapshot, &te))
                {
                    do
                    {
                        if (te.th32OwnerProcessID == GetCurrentProcessId())
                        {
                            if (context.GetKnownThreadIds().insert(te.th32ThreadID).second)
                            {
                                context.AddEvidence(anti_cheat::RUNTIME_THREAD_NEW_UNKNOWN, "检测到新线程 (TID: " + std::to_string(te.th32ThreadID) + ")");
                            }
                        }
                    } while (Thread32Next(hThreadSnapshot, &te));
                }
                CloseHandle(hThreadSnapshot);
            }

            // Scan for new modules
            std::vector<HMODULE> hModsVec(1024);
            DWORD cbNeeded;
            if (EnumProcessModules(GetCurrentProcess(), hModsVec.data(), hModsVec.size() * sizeof(HMODULE), &cbNeeded))
            {
                if (hModsVec.size() * sizeof(HMODULE) < cbNeeded)
                {
                    hModsVec.resize(cbNeeded / sizeof(HMODULE));
                    EnumProcessModules(GetCurrentProcess(), hModsVec.data(), hModsVec.size() * sizeof(HMODULE), &cbNeeded);
                }
                for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
                {
                    if (context.GetKnownModules().insert(hModsVec[i]).second)
                    {
                        wchar_t szModName[MAX_PATH];
                        if (GetModuleFileNameW(hModsVec[i], szModName, MAX_PATH))
                        {
                            context.AddEvidence(anti_cheat::RUNTIME_MODULE_NEW_UNKNOWN, "加载了新模块: " + Utils::WideToString(szModName));
                            context.VerifyModuleSignature(hModsVec[i]);
                        }
                    }
                }
            }
        }
    };

    class EnvironmentSensor : public ISensor
    {
    public:
        const char *GetName() const override { return "EnvironmentSensor"; }
        void Execute(ScanContext &context) override
        {
            // 1. 首先，一次性遍历所有窗口，构建一个 PID -> WindowTitles 的映射
            std::unordered_map<DWORD, std::vector<std::wstring>> windowTitlesByPid;
            auto enumProc = [](HWND hWnd, LPARAM lParam) -> BOOL
            {
                if (!IsWindowVisible(hWnd))
                    return TRUE;
                auto *pMap = reinterpret_cast<std::unordered_map<DWORD, std::vector<std::wstring>> *>(lParam);
                DWORD processId = 0;
                GetWindowThreadProcessId(hWnd, &processId);
                if (processId > 0)
                {
                    wchar_t buffer[256];
                    if (GetWindowTextLengthW(hWnd) > 0 && GetWindowTextW(hWnd, buffer, ARRAYSIZE(buffer)) > 0)
                    {
                        (*pMap)[processId].push_back(buffer);
                    }
                }
                return TRUE;
            };
            EnumWindows(enumProc, reinterpret_cast<LPARAM>(&windowTitlesByPid));

            // 2. 然后，遍历进程列表，进行检查
            using UniqueSnapshotHandle = std::unique_ptr<void, decltype(&::CloseHandle)>;
            UniqueSnapshotHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), &::CloseHandle);
            if (hSnapshot.get() == INVALID_HANDLE_VALUE)
                return;

            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(pe);
            if (Process32FirstW(hSnapshot.get(), &pe))
            {
                do
                {
                    std::wstring processName = pe.szExeFile;
                    std::transform(processName.begin(), processName.end(), processName.begin(), ::towlower);

                    // 检查点 1: 廉价的进程名黑名单检查
                    for (const auto &harmful : context.GetHarmfulProcessNames())
                    {
                        if (processName.find(harmful) != std::wstring::npos)
                        {
                            context.AddEvidence(anti_cheat::ENVIRONMENT_HARMFUL_PROCESS, "有害进程(文件名): " + Utils::WideToString(pe.szExeFile));
                            continue; // 继续检查下一个进程
                        }
                    }

                    // 检查点 2: 昂贵的进程路径白名单检查 (仅在需要时执行)
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                    if (hProcess)
                    {
                        std::wstring fullProcessPath = Utils::GetProcessFullName(hProcess);
                        CloseHandle(hProcess);
                        if (!fullProcessPath.empty())
                        {
                            std::transform(fullProcessPath.begin(), fullProcessPath.end(), fullProcessPath.begin(), ::towlower);
                            if (context.GetWhitelistedProcessPaths().count(fullProcessPath) > 0)
                            {
                                continue; // 进程在白名单中，安全，继续检查下一个进程
                            }
                        }
                    }

                    // 检查点 3: 窗口标题黑名单检查
                    if (auto it = windowTitlesByPid.find(pe.th32ProcessID); it != windowTitlesByPid.end())
                    {
                        for (const auto &title : it->second)
                        {
                            std::wstring lowerTitle = title;
                            std::transform(lowerTitle.begin(), lowerTitle.end(), lowerTitle.begin(), ::towlower);

                            // 检查窗口标题是否在白名单中
                            bool isWhitelistedWindow = false;
                            for (const auto &whitelistedKeyword : context.GetWhitelistedWindowKeywords())
                            {
                                if (lowerTitle.find(whitelistedKeyword) != std::wstring::npos)
                                {
                                    isWhitelistedWindow = true;
                                    break;
                                }
                            }
                            if (isWhitelistedWindow)
                            {
                                continue; // 窗口标题在白名单中，检查下一个窗口标题
                            }

                            // 检查窗口标题是否包含有害关键词
                            for (const auto &keyword : context.GetHarmfulKeywords())
                            {
                                if (lowerTitle.find(keyword) != std::wstring::npos)
                                {
                                    context.AddEvidence(anti_cheat::ENVIRONMENT_HARMFUL_PROCESS, "有害进程(窗口标题): " + Utils::WideToString(title));
                                    goto next_process_loop; // 跳出内外两层循环，检查下一个进程
                                }
                            }
                        }
                    }

                next_process_loop:;
                } while (Process32NextW(hSnapshot.get(), &pe));
            }
        }
    };

} // namespace Sensors

// --- VirtualAlloc Hooking ---
// 定义原始VirtualAlloc函数指针的类型
typedef LPVOID(WINAPI *VirtualAlloc_t)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
// 指向原始VirtualAlloc函数的“跳板”
static VirtualAlloc_t pTrampolineVirtualAlloc = nullptr;

CheatMonitor::Pimpl *CheatMonitor::Pimpl::s_pimpl_for_hooks = nullptr;

CheatMonitor &CheatMonitor::GetInstance()
{
    static CheatMonitor instance;
    return instance;
}
CheatMonitor::CheatMonitor() : m_pimpl(std::make_unique<Pimpl>()) {}
CheatMonitor::~CheatMonitor()
{
    Shutdown();
}

bool CheatMonitor::Initialize()
{

    std::lock_guard<std::mutex> lock(m_initMutex); // 增加互斥锁保护
    if (!m_pimpl)
        m_pimpl = std::make_unique<Pimpl>();
    if (m_pimpl->m_isSystemActive.load())
        return true; // 已经初始化成功，直接返回true

    // The hook procedure needs a static pointer to the Pimpl instance.
    Pimpl::s_pimpl_for_hooks = m_pimpl.get();

    // The hook must be set from a thread that has a message loop, but for system-wide LL hooks, it can be any thread.
    // 钩子回调函数需要一个指向Pimpl实例的静态指针。
    m_pimpl->m_hMouseHook = SetWindowsHookEx(WH_MOUSE_LL, Pimpl::LowLevelMouseProc, GetModuleHandle(NULL), 0);
    if (!m_pimpl->m_hMouseHook)
    {
        // 注意：此时AddEvidence可能无法上报，因为监控线程还未启动。

        // 最好能有一个初始化的日志系统来记录这种严重错误。
        std::cout << "[AntiCheat] Initialize Error: Failed to set mouse hook. Error code: " << GetLastError() << std::endl;
        return false;
    }

    // VirtualAlloc 钩子将在监控线程的 InitializeSystem 中被安装，此处不再调用。

    try
    {
        m_pimpl->m_monitorThread = std::thread(&Pimpl::MonitorLoop, m_pimpl.get());
    }
    catch (const std::system_error &e)
    {
        std::cout << "[AntiCheat] Initialize Error: Failed to create monitor thread. Error: " << e.what() << std::endl;
        if (m_pimpl->m_hMouseHook)
        {
            UnhookWindowsHookEx(m_pimpl->m_hMouseHook);
            m_pimpl->m_hMouseHook = NULL;
        }
        // 此处无需卸载VirtualAlloc钩子，因为它还未被安装。
        return false;
    }

    m_pimpl->m_isSystemActive = true;
    return true;
}

void CheatMonitor::OnPlayerLogin(uint32_t user_id, const std::string &user_name)
{
    if (!m_pimpl || !m_pimpl->m_isSystemActive.load())
        return;
    // [重构] 先登出上一个玩家，这会处理上一个会话的报告上传和状态清理
    OnPlayerLogout();
    {
        std::lock_guard<std::mutex> lock(m_pimpl->m_sessionMutex);
        m_pimpl->m_currentUserId = user_id;
        m_pimpl->m_currentUserName = user_name;
        //  确保硬件指纹只在第一个会话开始时收集一次
        if (!m_pimpl->m_fingerprint)
        {
            // [修复] 将指纹收集与证据添加解耦，以避免重入锁。
            // 1. 调用一个不直接添加证据，而是返回错误列表的函数。
            std::vector<std::string> errors = m_pimpl->CollectHardwareFingerprintErrors();
            // 2. 在同一个锁保护的上下文中，安全地添加证据。
            for (const auto& error : errors)
            {
                m_pimpl->AddEvidence(anti_cheat::RUNTIME_ERROR, error);
            }
        }
        m_pimpl->m_isSessionActive = true;
        m_pimpl->m_newSessionNeedsBaseline = true; // [新增] 标记新会话需要建立基线
    }
    m_pimpl->m_cv.notify_one();
}

void CheatMonitor::OnPlayerLogout()
{

    if (!m_pimpl || !m_pimpl->m_isSessionActive.load())
        return;

    // [修复] 核心逻辑修复：先原子地标记会话结束，以阻止监控线程继续添加证据。
    {
        std::lock_guard<std::mutex> lock(m_pimpl->m_sessionMutex);
        if (!m_pimpl->m_isSessionActive)
            return; // 在锁内再次检查
        m_pimpl->m_isSessionActive = false;
    }
    m_pimpl->m_cv.notify_one(); // 唤醒监控线程，使其能快速感知到状态变化并退出内部循环

    // 现在会话已被标记为不活跃，监控线程不会再添加新的证据。
    // 此时可以安全地上传该会话期间收集到的所有证据。
    m_pimpl->UploadReport();

    // 上传完成后，清理会话相关的状态，为下一个可能的会话做准备。
    {
        std::lock_guard<std::mutex> lock(m_pimpl->m_sessionMutex);

        m_pimpl->ResetSessionState();
    }
}

void CheatMonitor::Shutdown()
{
    std::lock_guard<std::mutex> lock(m_initMutex); // [修复] 增加互斥锁保护
    if (!m_pimpl || !m_pimpl->m_isSystemActive.load())
        return;

    if (m_pimpl->m_isSessionActive.load())
        OnPlayerLogout();
    m_pimpl->m_isSystemActive = false;
    m_pimpl->m_cv.notify_one();

    // [修复] 先原子性地切断钩子回调函数访问Pimpl实例的路径，再卸载钩子，防止use-after-free
    Pimpl::s_pimpl_for_hooks = nullptr;
    if (m_pimpl->m_hMouseHook)
    {
        if (!UnhookWindowsHookEx(m_pimpl->m_hMouseHook))
        {
            std::cout << "[AntiCheat] Shutdown Error: Failed to unhook mouse hook. Error code: " << GetLastError() << std::endl;
        }
        m_pimpl->m_hMouseHook = NULL;
    }

    if (m_pimpl->m_monitorThread.joinable())
        m_pimpl->m_monitorThread.join();
    m_pimpl->UninstallVirtualAllocHook(); // [新增] 卸载钩子，恢复原始函数
                                          // UninstallVirtualAllocHook 内部已添加日志，此处不重复判断。
    m_pimpl.reset();
}

bool CheatMonitor::IsCallerLegitimate()
{
    if (!m_pimpl)
        return true; // 如果系统未初始化，则不拦截

    // 1. 获取调用本函数的代码地址
    void *returnAddress = _ReturnAddress();
    HMODULE hModule = NULL;

    // 2. 检查该地址是否属于一个已加载的模块
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)returnAddress, &hModule) && hModule != NULL)
    {
        wchar_t modulePath[MAX_PATH];

        // 3. 获取该模块的完整路径
        if (GetModuleFileNameW(hModule, modulePath, MAX_PATH) > 0)
        {
            std::wstring lowerPath = modulePath;
            std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
            // 4. 使用哈希集合进行高效查找
            {
                std::lock_guard<std::mutex> lock(m_pimpl->m_modulePathsMutex); // [修复] 加锁保护读取
                if (m_pimpl->m_legitimateModulePaths.count(lowerPath) > 0)
                {
                    return true; // 调用者是白名单内的合法模块
                }
            }
            // --- 非法调用处理 ---
            // 调用者来自一个已加载但不在白名单内的模块 (例如 cheat.dll)
            uintptr_t sourceId = std::hash<std::wstring>{}(lowerPath);
            std::string sourceDescription = "非法调用(未知模块): " + Utils::WideToString(modulePath);

            std::lock_guard<std::mutex> lock(m_pimpl->m_sessionMutex);
            auto now = std::chrono::steady_clock::now();
            auto it = m_pimpl->m_reportedIllegalCallSources.find(sourceId);

            if (it == m_pimpl->m_reportedIllegalCallSources.end() ||
                std::chrono::duration_cast<std::chrono::minutes>(now - it->second).count() >= 5)
            {
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
    if (VirtualQuery(returnAddress, &mbi, sizeof(mbi)))
    {
        sourceId = (uintptr_t)mbi.AllocationBase; // 使用内存区域的基地址作为唯一标识
    }
    else
    {
        sourceId = (uintptr_t)returnAddress; // 降级方案：使用返回地址本身
    }

    std::lock_guard<std::mutex> lock(m_pimpl->m_sessionMutex);
    auto now = std::chrono::steady_clock::now();
    auto it = m_pimpl->m_reportedIllegalCallSources.find(sourceId);

    if (it == m_pimpl->m_reportedIllegalCallSources.end() ||
        std::chrono::duration_cast<std::chrono::minutes>(now - it->second).count() >= 5)
    {
        m_pimpl->m_reportedIllegalCallSources[sourceId] = now;
        m_pimpl->AddEvidence(anti_cheat::RUNTIME_ILLEGAL_FUNCTION_CALL, "非法调用(Shellcode)");
    }
    return false;
}

void CheatMonitor::Pimpl::ResetSessionState()
{
    m_evidences.clear();
    m_uniqueEvidence.clear();
    m_reportedIllegalCallSources.clear(); // 会话结束时清空“记忆”
    // m_moduleSignatureCache.clear(); // 模块签名缓存通常不需要在会话结束时清空，因为它与进程无关
    m_currentUserId = 0;

    // [重构] 初始化传感器列表，包括轻量级和重量级传感器
    m_lightweight_sensors.clear();
    m_heavyweight_sensors.clear();

    m_lightweight_sensors.push_back(std::make_unique<Sensors::AdvancedAntiDebugSensor>());
    m_lightweight_sensors.push_back(std::make_unique<Sensors::SystemIntegritySensor>());
    m_lightweight_sensors.push_back(std::make_unique<Sensors::IatHookSensor>());
    m_lightweight_sensors.push_back(std::make_unique<Sensors::VehHookSensor>());
    m_lightweight_sensors.push_back(std::make_unique<Sensors::InputAutomationSensor>());

    m_heavyweight_sensors.push_back(std::make_unique<Sensors::ProcessHandleSensor>());
    m_heavyweight_sensors.push_back(std::make_unique<Sensors::NewActivitySensor>());
    m_heavyweight_sensors.push_back(std::make_unique<Sensors::MemoryScanSensor>());

    m_currentUserName.clear();
    // [修复] 移除对未定义成员的调用
}

void CheatMonitor::Pimpl::InitializeSessionBaseline()
{
    m_rng.seed(m_rd()); // 为每个会话重置随机数种子，增加随机性

    // [新增] 初始化白名单 (重要：实际应从配置文件或服务器加载，避免硬编码)
    // 这里的路径示例将尝试使用更通用的方法，避免硬编码盘符。
    wchar_t systemDir[MAX_PATH];
    if (GetSystemDirectoryW(systemDir, MAX_PATH) > 0)
    {
        std::wstring wsSystemDir = systemDir;
        std::transform(wsSystemDir.begin(), wsSystemDir.end(), wsSystemDir.begin(), ::towlower);

        // Windows系统目录下的常见合法进程
        m_whitelistedProcessPaths.insert(wsSystemDir + L"\\explorer.exe");
        m_whitelistedProcessPaths.insert(wsSystemDir + L"\\cmd.exe");
        m_whitelistedProcessPaths.insert(wsSystemDir + L"\\powershell.exe");
    }
    else
    {
        AddEvidence(anti_cheat::RUNTIME_ERROR, "会话基线初始化失败: 无法获取系统目录。");
        return;
    }

    // 尝试获取Program Files目录 (x86和x64)
    wchar_t programFiles[MAX_PATH];
    if (SHGetFolderPathW(NULL, CSIDL_PROGRAM_FILES, NULL, 0, programFiles) == S_OK)
    {
        std::wstring wsProgramFiles = programFiles;
        // 示例：Visual Studio (假设安装在Program Files)
        m_whitelistedProcessPaths.insert(wsProgramFiles + L"\\microsoft visual studio\\2022\\community\\common7\\ide\\devenv.exe");
    }
    else
    {
        AddEvidence(anti_cheat::RUNTIME_ERROR, "会话基线初始化失败: 无法获取Program Files目录。");
        return;
    }

    wchar_t programFilesX86[MAX_PATH];
    if (SHGetFolderPathW(NULL, CSIDL_PROGRAM_FILESX86, NULL, 0, programFilesX86) == S_OK)
    {
        std::wstring wsProgramFilesX86 = programFilesX86;
        // 示例：Visual Studio Code (假设安装在Program Files (x86) 或 Local AppData)
        // 对于VS Code，更常见的是在AppData，这里仅作示例
        // m_whitelistedProcessPaths.insert(wsProgramFilesX86 + L"\\microsoft vs code\\code.exe");
    }
    else
    {
        AddEvidence(anti_cheat::RUNTIME_ERROR, "会话基线初始化失败: 无法获取Program Files (x86)目录。");
        return;
    }

    // 对于用户特定的应用（如VS Code），通常在AppData，需要动态获取用户目录
    wchar_t appDataLocal[MAX_PATH];
    if (SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appDataLocal) == S_OK)
    {
        std::wstring wsAppDataLocal = appDataLocal;
        m_whitelistedProcessPaths.insert(wsAppDataLocal + L"\\programs\\microsoft vs code\\code.exe");
    }
    else
    {
        AddEvidence(anti_cheat::RUNTIME_ERROR, "会话基线初始化失败: 无法获取Local AppData目录。");
        return;
    }

    // 窗口标题关键词
    m_whitelistedWindowKeywords.insert(L"visual studio");
    m_whitelistedWindowKeywords.insert(L"command prompt");
    m_whitelistedWindowKeywords.insert(L"powershell");
    m_whitelistedWindowKeywords.insert(L"visual studio code");

    // [新增] 初始化IAT Hook白名单 (重要：实际应从配置文件或服务器加载，避免硬编码)
    // 示例：允许来自特定DLL的特定函数被钩子（例如，某些安全软件或驱动）
    // m_whitelistedIATHooks.insert("ntdll.dll!NtCreateFile");
    // m_whitelistedIATHooks.insert("kernel32.dll!CreateFileW");

    // [新增] 初始化VEH Hook白名单 (示例，实际应从配置文件或服务器加载)
    // 示例：允许来自某些安全软件或系统组件的VEH处理函数
    // m_whitelistedVEHModules.insert(L"c:\\windows\\system32\\drivers\\some_security_driver.sys");
    // m_whitelistedVEHModules.insert(L"c:\\program files\\your_security_software\\security.dll");

    // 在会话开始时执行一次性检查
    Sensor_ValidateParentProcess(); // 使用新的、更安全的父进程验证
    Sensor_DetectVirtualMachine();

    // 在初始化时执行一次性的、彻底的模块完整性校验
    // 第1层：验证模块的数字签名，确保磁盘上的文件是可信的。
    // VerifyModuleSignature 内部已添加日志。
    VerifyModuleSignature(GetModuleHandleW(L"ntdll.dll"));
    VerifyModuleSignature(GetModuleHandleW(L"kernel32.dll"));
    VerifyModuleSignature(GetModuleHandleW(L"user32.dll"));
    VerifyModuleSignature(GetModuleHandle(NULL)); // 验证游戏主程序

    // 第2层：将内存中的模块与磁盘上的可信版本进行比较，以检测启动时的篡改。
    // VerifyModuleIntegrity 内部已添加日志。
    VerifyModuleIntegrity(L"ntdll.dll");
    VerifyModuleIntegrity(L"kernel32.dll");
    VerifyModuleIntegrity(L"user32.dll");
    VerifyModuleIntegrity(NULL); // 验证游戏主程序

    HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnapshot != INVALID_HANDLE_VALUE)
    {
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        if (Thread32First(hThreadSnapshot, &te))
        {
            do
            {
                if (te.th32OwnerProcessID == GetCurrentProcessId())
                    m_knownThreadIds.insert(te.th32ThreadID);
            } while (Thread32Next(hThreadSnapshot, &te));
        }
        CloseHandle(hThreadSnapshot);
    }
    else
    {
        AddEvidence(anti_cheat::RUNTIME_ERROR, "会话基线初始化失败: 无法创建线程快照。");
    }

    // 动态构建模块白名单：将所有初始加载的模块路径添加到白名单中
    // 采用动态缓冲区，确保能够获取所有模块
    std::vector<HMODULE> hModsVec;
    DWORD cbNeeded;
    DWORD bufferSize = 1024 * sizeof(HMODULE); // 初始缓冲区大小
    hModsVec.resize(bufferSize / sizeof(HMODULE));

    while (EnumProcessModules(GetCurrentProcess(), hModsVec.data(), bufferSize, &cbNeeded))
    {
        if (cbNeeded <= bufferSize)
        {
            hModsVec.resize(cbNeeded / sizeof(HMODULE));
            break;
        }
        else
        {
            bufferSize = cbNeeded; // 缓冲区不足，扩大并重试
            hModsVec.resize(bufferSize / sizeof(HMODULE));
        }
    }

    if (cbNeeded > 0)
    {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            // 将所有初始加载的模块视为基线的一部分
            m_knownModules.insert(hModsVec[i]);

            wchar_t modPath[MAX_PATH];
            if (GetModuleFileNameW(hModsVec[i], modPath, MAX_PATH) > 0)
            {
                // 对于Windows文件系统，路径比较通常不区分大小写，直接存储原始路径或使用不区分大小写的比较器
                // 这里为了兼容性，仍然转换为小写，但更推荐使用_wcsicmp进行比较或PathCchCanonicalizeEx
                std::wstring lowerPath = modPath;
                std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower); // 依赖locale，但对于路径通常安全
                {
                    std::lock_guard<std::mutex> lock(m_modulePathsMutex); // [修复] 加锁保护写入
                    m_legitimateModulePaths.insert(lowerPath);
                }
            }
            else
            {
                AddEvidence(anti_cheat::RUNTIME_ERROR, "会话基线初始化失败: 无法获取模块路径 (句柄: " + std::to_string((uintptr_t)hModsVec[i]) + ").");
            }
        }
    }
    else
    {
        AddEvidence(anti_cheat::RUNTIME_ERROR, "会话基线初始化失败: 无法枚举进程模块。");
    }

    // 为关键模块建立代码节哈希基线
    const std::vector<const wchar_t *> modulesToBaseline = {L"ntdll.dll", L"kernel32.dll", L"user32.dll", NULL}; // NULL代表主程序
    for (const auto *moduleName : modulesToBaseline)
    {
        HMODULE hModule = GetModuleHandleW(moduleName);
        if (hModule)
        {
            PVOID codeBase = nullptr;
            DWORD codeSize = 0;
            if (GetCodeSectionInfo(hModule, codeBase, codeSize))
            {
                wchar_t modulePath[MAX_PATH];
                if (GetModuleFileNameW(hModule, modulePath, MAX_PATH) > 0)
                {
                    m_moduleBaselineHashes[modulePath] = CalculateHash(static_cast<BYTE *>(codeBase), codeSize);
                }
                else
                {
                    std::cout << "[AntiCheat] Baseline Error: GetModuleFileNameW failed for hModule 0x" << std::hex << hModule << " during baseline hash." << std::endl;
                }
            }
            else
            {
                std::cout << "[AntiCheat] Baseline Error: GetCodeSectionInfo failed for module: " << Utils::WideToString(moduleName ? moduleName : L"主程序") << std::endl;
            }
        }
        else
        {
            AddEvidence(anti_cheat::RUNTIME_ERROR, "会话基线初始化失败: 无法获取基线模块句柄: " + Utils::WideToString(moduleName ? moduleName : L"主程序"));
        }
    }

    // [重构] 为主模块的每个导入DLL建立独立的IAT哈希基线
    const HMODULE hSelf = GetModuleHandle(NULL);
    if (hSelf)
    {
        const BYTE *baseAddress = reinterpret_cast<const BYTE *>(hSelf);

        const IMAGE_DOS_HEADER *pDosHeader = reinterpret_cast<const IMAGE_DOS_HEADER *>(baseAddress);
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
            AddEvidence(anti_cheat::RUNTIME_ERROR, "会话基线初始化失败: 主程序DOS头无效。");
            return;
        }

        const IMAGE_NT_HEADERS *pNtHeaders = reinterpret_cast<const IMAGE_NT_HEADERS *>(baseAddress + pDosHeader->e_lfanew);
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
        {
            AddEvidence(anti_cheat::RUNTIME_ERROR, "会话基线初始化失败: 主程序NT头无效。");
            return;
        }

        IMAGE_DATA_DIRECTORY importDirectory = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDirectory.VirtualAddress == 0)
        {
            return; // No import table, which is valid.
        }

        const IMAGE_IMPORT_DESCRIPTOR *pImportDesc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR *>(baseAddress + importDirectory.VirtualAddress);

        while (pImportDesc->Name)
        {
            const char *dllName = reinterpret_cast<const char *>(baseAddress + pImportDesc->Name);
            const IMAGE_THUNK_DATA *pThunk = reinterpret_cast<const IMAGE_THUNK_DATA *>(baseAddress + pImportDesc->FirstThunk);

            size_t entryCount = 0;
            const IMAGE_THUNK_DATA *pCurrentThunk = pThunk;
            while (pCurrentThunk->u1.AddressOfData)
            {
                entryCount++;
                pCurrentThunk++;
            }

            if (entryCount > 0)
            {
                size_t iatBlockSize = entryCount * sizeof(IMAGE_THUNK_DATA);
                m_iatBaselineHashes[dllName] = CalculateHash(reinterpret_cast<const BYTE *>(pThunk), iatBlockSize);
            }
            pImportDesc++;
        }
    }
    else
    {
        AddEvidence(anti_cheat::RUNTIME_ERROR, "会话基线初始化失败: 无法获取主程序模块句柄。");
    }

    AddEvidence(anti_cheat::SYSTEM_INITIALIZED, "反作弊系统初始化成功并建立基线。");
}

void CheatMonitor::Pimpl::InitializeSystem()
{
    m_rng.seed(m_rd()); // 初始化随机数生成器

    // --- 执行一次性的系统级初始化 ---

    // 1. 加固进程，防止被轻易篡改。
    HardenProcessAndThreads();

    // 2. 动态查找VEH链表偏移量，为后续的VEH Hook检测做准备。
    m_vehListOffset = FindVehListOffset();
    if (m_vehListOffset == 0)
    {
        // 这是一个关键功能的失败，必须记录。
        AddEvidence(anti_cheat::RUNTIME_ERROR, "系统初始化失败: 无法动态查找VEH链表偏移量。");
    }

    // 3. 安装API钩子以监控可疑的内存分配行为。
    InstallVirtualAllocHook();
}

void CheatMonitor::Pimpl::HardenProcessAndThreads()
{
    // SetProcessMitigationPolicy 在 Windows 8 / Server 2012 R2 及以上版本可用。
    // 为兼容旧版系统，我们动态加载此函数。
    typedef BOOL(WINAPI * PSetProcessMitigationPolicy)(PROCESS_MITIGATION_POLICY, PVOID, SIZE_T);
    PSetProcessMitigationPolicy pSetProcessMitigationPolicy = (PSetProcessMitigationPolicy)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "SetProcessMitigationPolicy");

    if (pSetProcessMitigationPolicy)
    {
        // 1. 设置进程缓解策略，阻止当前进程创建任何子进程。
        PROCESS_MITIGATION_CHILD_PROCESS_POLICY childPolicy = {};
        childPolicy.NoChildProcessCreation = 1;
        if (!pSetProcessMitigationPolicy(ProcessChildProcessPolicy, &childPolicy, sizeof(childPolicy)))
        {
            AddEvidence(anti_cheat::ENVIRONMENT_PROCESS_HARDENING_FAILED, "进程加固失败: 无法设置禁止子进程创建策略。");
        }

        // 2. DEP (Data Execution Prevention)
        PROCESS_MITIGATION_DEP_POLICY depPolicy = {};
        depPolicy.Enable = 1;    // 启用 DEP
        depPolicy.Permanent = 1; // 永久启用，不能被禁用
        if (!pSetProcessMitigationPolicy(ProcessDEPPolicy, &depPolicy, sizeof(depPolicy)))
        {
            AddEvidence(anti_cheat::ENVIRONMENT_PROCESS_HARDENING_FAILED, "进程加固失败: 无法设置DEP策略。");
        }

        // 3. [增强] 禁止动态代码生成。这是一个非常强的缓解措施，但需谨慎测试。
        // 如果游戏引擎或第三方库使用了JIT等技术，可能会导致冲突。
        // 注意：此策略可能导致兼容性问题，在生产环境中使用前务必进行全面测试。
        // PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamicCodePolicy = {};
        // dynamicCodePolicy.ProhibitDynamicCode = 1;
        // if (!pSetProcessMitigationPolicy(ProcessDynamicCodePolicy, &dynamicCodePolicy, sizeof(dynamicCodePolicy))) {
        //     std::cout << "[AntiCheat] Hardening Warning: Failed to set ProcessDynamicCodePolicy." << std::endl;
        // }
    }

#ifndef _DEBUG
    // 3. 为当前进程的所有线程设置“对调试器隐藏”属性
    // 这段代码只在Release版本中编译，以避免影响开发阶段的调试。
    if (!g_pNtSetInformationThread)
    {
        return;
    }
    HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnapshot == INVALID_HANDLE_VALUE)
    {
        return;
    }
    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(hThreadSnapshot, &te))
    {
        do
        {
            if (te.th32OwnerProcessID == GetCurrentProcessId())
            {
                HANDLE hThread = OpenThread(THREAD_SET_INFORMATION, FALSE, te.th32ThreadID);
                if (hThread)
                {
                    NTSTATUS status = g_pNtSetInformationThread(hThread, (THREADINFOCLASS)0x11, NULL, 0); // 0x11 is ThreadHideFromDebugger
                    if (!NT_SUCCESS(status))
                    {
                        AddEvidence(anti_cheat::ENVIRONMENT_PROCESS_HARDENING_FAILED, "线程加固失败: 无法隐藏线程 (TID: " + std::to_string(te.th32ThreadID) + ").");
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hThreadSnapshot, &te));
    }
    CloseHandle(hThreadSnapshot);

#endif
}

void CheatMonitor::Pimpl::MonitorLoop()
{
    // [性能优化] 将监控线程的优先级设置为低于正常，以确保它不会与游戏主渲染/逻辑线程争抢CPU资源，
    // 从而避免引入卡顿。这是一个在反作弊开发中至关重要的实践。
    HANDLE hCurrentThread = GetCurrentThread();
    if (!SetThreadPriority(hCurrentThread, THREAD_PRIORITY_BELOW_NORMAL))
    {
        // 记录一个非致命的错误。即使设置失败，监控也应继续。
        std::cout << "[AntiCheat] Performance Warning: Failed to set monitor thread priority. Error: " << GetLastError() << std::endl;
    }

    // [重构] 系统级初始化，只执行一次
    InitializeSystem();
    using namespace std::chrono;

    ScanContext context(this);

    while (m_isSystemActive.load())
    {
        {
            std::unique_lock<std::mutex> lock(m_cvMutex);
            m_cv.wait(lock, [this]
                      { return m_isSessionActive.load() || !m_isSystemActive.load(); });
        }
        if (!m_isSystemActive.load())
            break;

        // [重构] 会话级初始化，每次新会话开始时执行
        if (m_newSessionNeedsBaseline.exchange(false))
        {
            InitializeSessionBaseline();
        }

        auto last_report_time = steady_clock::now();
        // [性能重构] 为重量级扫描引入独立的、更长的计时器
        auto last_heavy_scan_time = steady_clock::now();

        while (m_isSessionActive.load())
        {
            auto scan_start_time = steady_clock::now();

            // --- [重构] Tier 1: 执行轻量级、高频扫描 ---
            std::shuffle(m_lightweight_sensors.begin(), m_lightweight_sensors.end(), m_rng);
            for (const auto &sensor : m_lightweight_sensors)
            {
                if (!m_isSessionActive.load())
                    break;
                try
                {
                    sensor->Execute(context);
                }

                catch (const std::exception &e)
                {
                    std::cout << "[AntiCheat] Sensor Exception: " << sensor->GetName() << ", " << e.what() << std::endl;
                }
                catch (...)
                {
                    std::cout << "[AntiCheat] Sensor Exception: Unknown in " << sensor->GetName() << std::endl;
                }
            }

            // --- [重构] Tier 2: 执行重量级、低频扫描 ---
            if (duration_cast<minutes>(scan_start_time - last_heavy_scan_time) >= minutes(15))
            {
                std::shuffle(m_heavyweight_sensors.begin(), m_heavyweight_sensors.end(), m_rng);
                for (const auto &sensor : m_heavyweight_sensors)
                {
                    if (!m_isSessionActive.load())
                        break;
                    try
                    {
                        sensor->Execute(context);
                    }
                    catch (const std::exception &e)
                    {
                        std::cout << "[AntiCheat] Heavy Sensor Exception: " << sensor->GetName() << ", " << e.what() << std::endl;
                    }
                    catch (...)
                    {
                        std::cout << "[AntiCheat] Heavy Sensor Exception: Unknown in " << sensor->GetName() << std::endl;
                    }
                }
                last_heavy_scan_time = steady_clock::now();
            }

            // --- 定期上报 ---
            if (duration_cast<minutes>(scan_start_time - last_report_time) >= minutes(5))
            {
                UploadReport();
                last_report_time = steady_clock::now();
            }

            // [改进] 为扫描间隔引入随机抖动，使其更难被预测。
            auto scan_end_time = steady_clock::now();
            auto scan_duration = duration_cast<milliseconds>(scan_end_time - scan_start_time);

            // 目标间隔为8-12秒。先计算基础休眠时间。
            auto base_sleep_duration = seconds(8) - scan_duration;
            // 再增加一个0-4秒的随机抖动。
            auto jitter = milliseconds(m_rng() % 4000); // 使用成员随机数生成器
            auto sleep_duration = base_sleep_duration + jitter;

            if (sleep_duration > milliseconds(0))
            {
                std::unique_lock<std::mutex> lock(m_cvMutex);
                m_cv.wait_for(lock, sleep_duration, [this]
                              { return !m_isSessionActive.load() || !m_isSystemActive.load(); });
            }
        }
    }
}

void CheatMonitor::Pimpl::AddEvidence(anti_cheat::CheatCategory category, const std::string &description)
{
    std::lock_guard<std::mutex> lock(m_sessionMutex);
    if (!m_isSessionActive)
        return;

    // O(logN) 复杂度的去重检查
    if (m_uniqueEvidence.find({category, description}) != m_uniqueEvidence.end())
    {
        return;
    }

    m_uniqueEvidence.insert({category, description});

    anti_cheat::Evidence evidence; // 在栈上创建对象
    evidence.set_client_timestamp_ms(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    evidence.set_category(category);
    evidence.set_description(description);
    m_evidences.push_back(evidence); // 拷贝到vector
}

void CheatMonitor::Pimpl::UploadReport()
{
    std::lock_guard<std::mutex> lock(m_sessionMutex);
    if (m_evidences.empty() && !m_fingerprint)
    {
        return;
    }

    auto now = std::chrono::steady_clock::now();

    // 1. 筛选出本次需要上报的证据
    std::vector<anti_cheat::Evidence> evidences_to_report;
    std::set<anti_cheat::CheatCategory> categories_in_report;

    for (const auto &evidence : m_evidences)
    {
        std::pair<uint32_t, anti_cheat::CheatCategory> key = {m_currentUserId, evidence.category()};
        auto it = m_lastReported.find(key);

        // 如果该类别是第一次发现，或距离上次上报已超过冷却时间
        if (it == m_lastReported.end() ||
            std::chrono::duration_cast<std::chrono::minutes>(now - it->second) >= kReportCooldownMinutes)
        {
            evidences_to_report.push_back(evidence);
            categories_in_report.insert(evidence.category());
        }
    }

    // 如果筛选后没有可上报的证据，并且没有指纹要上报，则直接清理并返回
    if (evidences_to_report.empty() && !m_fingerprint)
    {
        m_evidences.clear();
        m_uniqueEvidence.clear();
        return;
    }

    anti_cheat::CheatReport report;
    report.set_report_id(Utils::GenerateUuid());
    report.set_report_timestamp_ms(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());

    // 将所有权转移给 report 对象
    if (m_fingerprint)
    {
        report.set_allocated_fingerprint(m_fingerprint.release());
    }

    report.mutable_evidences()->CopyFrom({evidences_to_report.begin(), evidences_to_report.end()});

    // --- 实际的网络上报逻辑应在此处实现 ---
    // bool upload_successful = YourNetworkClient::Send(report.SerializeAsString());
    bool upload_successful = true; // 此处为占位符，模拟上报成功

    if (upload_successful)
    {
        // 上报成功后，为所有已上报的类别更新冷却时间戳
        for (const auto &category : categories_in_report)
        {
            m_lastReported[{m_currentUserId, category}] = now;
        }
        // 清理所有已处理的证据
        m_evidences.clear();
        m_uniqueEvidence.clear();
    }
    else
    {
        // 上报失败，将指纹的所有权还给 Pimpl，以便下次重试。
        // 证据保留在 m_evidences 中，等待下次上报时重试。
        if (report.has_fingerprint())
        {
            m_fingerprint.reset(report.release_fingerprint());
        }
    }
}

void CheatMonitor::Pimpl::Sensor_CheckEnvironment()
{
    // [修复] 移除冗余的IsDebuggerPresent()检查，因为它与Sensor_CheckAdvancedAntiDebug中的PEB检查重复。

    // --- 性能优化: 解耦进程扫描与窗口扫描 ---
    // 1. 首先，一次性遍历所有窗口，构建一个 PID -> WindowTitles 的映射
    std::unordered_map<DWORD, std::vector<std::wstring>> windowTitlesByPid;
    auto enumProc = [](HWND hWnd, LPARAM lParam) -> BOOL
    {
        if (!IsWindowVisible(hWnd))
            return TRUE;
        auto *pMap = reinterpret_cast<std::unordered_map<DWORD, std::vector<std::wstring>> *>(lParam);
        DWORD processId = 0;
        GetWindowThreadProcessId(hWnd, &processId);
        if (processId > 0)
        {
            wchar_t buffer[256];
            // 先检查标题长度，确保我们只处理有标题的窗口，并使API调用更健壮
            if (GetWindowTextLengthW(hWnd) > 0 && GetWindowTextW(hWnd, buffer, ARRAYSIZE(buffer)) > 0)
            {
                (*pMap)[processId].push_back(buffer);
            }
        }
        return TRUE;
    };
    EnumWindows(enumProc, reinterpret_cast<LPARAM>(&windowTitlesByPid));

    // 2. 然后，遍历进程列表，进行检查
    // 使用智能指针和自定义删除器来自动管理句柄生命周期 (RAII)
    using UniqueSnapshotHandle = std::unique_ptr<void, decltype(&::CloseHandle)>;
    UniqueSnapshotHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), &CloseHandle);
    if (hSnapshot.get() == INVALID_HANDLE_VALUE)
        return;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnapshot.get(), &pe))
    {
        do
        {
            // [性能优化] 将廉价的检查前置，避免对每个进程都执行昂贵的API调用。
            [&]
            {
                std::wstring processName = pe.szExeFile;
                std::transform(processName.begin(), processName.end(), processName.begin(), ::towlower);

                // 1. 首先执行最廉价的检查：进程名是否在黑名单中。
                for (const auto &harmful : m_harmfulProcessNames)
                {
                    if (processName.find(harmful) != std::wstring::npos)
                    {
                        AddEvidence(anti_cheat::ENVIRONMENT_HARMFUL_PROCESS, "有害进程(文件名): " + Utils::WideToString(pe.szExeFile));
                        return; // 发现即上报并返回，无需后续昂贵检查。
                    }
                }

                // 2. 如果进程名不在黑名单中，再执行昂贵的检查：获取完整路径以核对白名单。
                //    这个OpenProcess调用现在只对不在黑名单中的进程执行，大大减少了系统调用次数。
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                if (hProcess)
                {
                    std::wstring fullProcessPath = Utils::GetProcessFullName(hProcess);
                    CloseHandle(hProcess); // 确保立即关闭句柄

                    if (!fullProcessPath.empty())
                    {
                        std::transform(fullProcessPath.begin(), fullProcessPath.end(), fullProcessPath.begin(), ::towlower);
                        if (m_whitelistedProcessPaths.count(fullProcessPath) > 0)
                        {
                            return; // 进程在路径白名单中，跳过后续检查。
                        }
                    }
                }

                // 3. 最后，检查窗口标题。
                if (auto it = windowTitlesByPid.find(pe.th32ProcessID); it != windowTitlesByPid.end())
                {
                    for (const auto &title : it->second)
                    {
                        std::wstring lowerTitle = title;
                        std::transform(lowerTitle.begin(), lowerTitle.end(), lowerTitle.begin(), ::towlower);

                        // 检查窗口标题是否在白名单中
                        bool isWhitelistedWindow = false;
                        for (const auto &whitelistedKeyword : m_whitelistedWindowKeywords)
                        {
                            if (lowerTitle.find(whitelistedKeyword) != std::wstring::npos)
                            {
                                isWhitelistedWindow = true;
                                break;
                            }
                        }
                        if (isWhitelistedWindow)
                        {
                            continue; // 窗口在白名单中，跳过此窗口的有害关键词检查。
                        }

                        // 检查窗口标题是否包含有害关键词
                        for (const auto &keyword : m_harmfulKeywords)
                        {
                            if (lowerTitle.find(keyword) != std::wstring::npos)
                            {
                                AddEvidence(anti_cheat::ENVIRONMENT_HARMFUL_PROCESS, "有害进程(窗口标题): " + Utils::WideToString(title));
                                return; // 发现一个即可返回。
                            }
                        }
                    }
                }
            }(); // 立即执行lambda
        } while (Process32NextW(hSnapshot.get(), &pe));
    }
}

// [新增] 模块完整性校验的辅助函数，将不安全的内存访问隔离在SEH块中
struct IntegrityCheckResult
{
    enum class Status { Success, DosHeaderInvalid, NtHeaderInvalid, PeHeaderTampered, SectionTampered, Exception };
    Status status;
    char sectionName[9];
    char modPathStr[512];
};

void PerformLowLevelCheck(IntegrityCheckResult &result, HMODULE hModuleInMemory, LPVOID pMappedFileBase, const wchar_t *modPathOnDisk)
{
    WideCharToMultiByte(CP_UTF8, 0, modPathOnDisk, -1, result.modPathStr, sizeof(result.modPathStr), nullptr, nullptr);
    result.status = IntegrityCheckResult::Status::Success;
    result.sectionName[0] = '\0';

    __try
    {
        const auto *pDosHeader = reinterpret_cast<const IMAGE_DOS_HEADER *>(hModuleInMemory);
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
            result.status = IntegrityCheckResult::Status::DosHeaderInvalid;
            return;
        }

        const auto *pNtHeaders = reinterpret_cast<const IMAGE_NT_HEADERS *>(reinterpret_cast<const BYTE *>(hModuleInMemory) + pDosHeader->e_lfanew);
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
        {
            result.status = IntegrityCheckResult::Status::NtHeaderInvalid;
            return;
        }

        if (memcmp(hModuleInMemory, pMappedFileBase, pNtHeaders->OptionalHeader.SizeOfHeaders) != 0)
        {
            result.status = IntegrityCheckResult::Status::PeHeaderTampered;
        }
        else
        {
            const IMAGE_SECTION_HEADER *pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
            for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++)
            {
                if (pSectionHeader->Characteristics & IMAGE_SCN_CNT_CODE && pSectionHeader->Misc.VirtualSize > 0 && pSectionHeader->SizeOfRawData > 0)
                {
                    const void *sectionInMemory = reinterpret_cast<const BYTE *>(hModuleInMemory) + pSectionHeader->VirtualAddress;
                    const void *sectionOnDisk = reinterpret_cast<const BYTE *>(pMappedFileBase) + pSectionHeader->PointerToRawData;
                    size_t sizeToCompare = min(pSectionHeader->Misc.VirtualSize, pSectionHeader->SizeOfRawData);
                    if (memcmp(sectionInMemory, sectionOnDisk, sizeToCompare) != 0)
                    {
                        memcpy(result.sectionName, pSectionHeader->Name, 8);
                        result.sectionName[8] = '\0';
                        result.status = IntegrityCheckResult::Status::SectionTampered;
                        break;
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        result.status = IntegrityCheckResult::Status::Exception;
    }
}

void CheckModuleIntegrity(CheatMonitor::Pimpl *pimpl, HMODULE hModuleInMemory, LPVOID pMappedFileBase, const wchar_t *modPathOnDisk)
{
    IntegrityCheckResult result;
    PerformLowLevelCheck(result, hModuleInMemory, pMappedFileBase, modPathOnDisk);

    if (result.status != IntegrityCheckResult::Status::Success)
    {
        char errorMsg[1024];
        switch (result.status)
        {
        case IntegrityCheckResult::Status::DosHeaderInvalid:
            snprintf(errorMsg, sizeof(errorMsg), "模块DOS头无效: %s", result.modPathStr);
            pimpl->AddEvidence(anti_cheat::INTEGRITY_MODULE_TAMPERED, errorMsg);
            break;
        case IntegrityCheckResult::Status::NtHeaderInvalid:
            snprintf(errorMsg, sizeof(errorMsg), "模块NT头无效: %s", result.modPathStr);
            pimpl->AddEvidence(anti_cheat::INTEGRITY_MODULE_TAMPERED, errorMsg);
            break;
        case IntegrityCheckResult::Status::PeHeaderTampered:
            snprintf(errorMsg, sizeof(errorMsg), "模块PE头被篡改: %s (内存与磁盘不匹配)", result.modPathStr);
            pimpl->AddEvidence(anti_cheat::INTEGRITY_MODULE_TAMPERED, errorMsg);
            break;
        case IntegrityCheckResult::Status::SectionTampered:
            snprintf(errorMsg, sizeof(errorMsg), "代码节被篡改: %s (节名: %s)", result.modPathStr, result.sectionName);
            pimpl->AddEvidence(anti_cheat::INTEGRITY_MODULE_TAMPERED, errorMsg);
            break;
        case IntegrityCheckResult::Status::Exception:
            snprintf(errorMsg, sizeof(errorMsg), "模块完整性校验时发生异常: %s，内存可能已损坏。", result.modPathStr);
            pimpl->AddEvidence(anti_cheat::RUNTIME_ERROR, errorMsg);
            break;
        default:
            break;
        }
    }
}

void PerformIntegrityCheck(CheatMonitor::Pimpl *pimpl, HMODULE hModuleInMemory, LPVOID pMappedFileBase, const std::wstring &modPathOnDisk)
{
    CheckModuleIntegrity(pimpl, hModuleInMemory, pMappedFileBase, modPathOnDisk.c_str());
}

void CheatMonitor::Pimpl::VerifyModuleIntegrity(const wchar_t *moduleName)
{
    // 定义句柄的智能指针类型，实现RAII，确保资源自动释放
    using UniqueFileHandle = std::unique_ptr<void, decltype(&::CloseHandle)>;
    using UniqueMappingHandle = std::unique_ptr<void, decltype(&::CloseHandle)>;

    HMODULE hModuleInMemory = GetModuleHandleW(moduleName);
    if (!hModuleInMemory)
    {
        AddEvidence(anti_cheat::RUNTIME_ERROR, "模块完整性校验失败: 无法获取模块句柄: " + Utils::WideToString(moduleName ? moduleName : L"主程序"));
        return;
    }

    wchar_t modPathOnDisk[MAX_PATH];
    if (GetModuleFileNameW(hModuleInMemory, modPathOnDisk, MAX_PATH) == 0)
    {
        AddEvidence(anti_cheat::RUNTIME_ERROR, "模块完整性校验失败: 无法获取模块路径 (句柄: " + std::to_string((uintptr_t)hModuleInMemory) + ")");
        return;
    }

    UniqueFileHandle hFile(CreateFileW(modPathOnDisk, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL), &CloseHandle);
    if (hFile.get() == INVALID_HANDLE_VALUE)
    {
        AddEvidence(anti_cheat::RUNTIME_ERROR, "模块完整性校验失败: 无法打开模块文件: " + Utils::WideToString(modPathOnDisk));
        return;
    }

    UniqueMappingHandle hMapping(CreateFileMappingW(hFile.get(), NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL), &CloseHandle);
    if (!hMapping.get())
    {
        AddEvidence(anti_cheat::RUNTIME_ERROR, "模块完整性校验失败: 无法创建文件映射: " + Utils::WideToString(modPathOnDisk));
        return;
    }

    LPVOID pMappedFileBase = MapViewOfFile(hMapping.get(), FILE_MAP_READ, 0, 0, 0);
    if (!pMappedFileBase)
    {
        AddEvidence(anti_cheat::RUNTIME_ERROR, "模块完整性校验失败: 无法映射文件视图: " + Utils::WideToString(modPathOnDisk));
        return;
    }

    PerformIntegrityCheck(this, hModuleInMemory, pMappedFileBase, modPathOnDisk);

    UnmapViewOfFile(pMappedFileBase);
}

void CheatMonitor::Pimpl::Sensor_CheckSystemIntegrityState()
{
    // 1. 检查测试签名模式是否开启
    SYSTEM_CODE_INTEGRITY_INFORMATION sci = {sizeof(sci), 0};
    if (!g_pNtQuerySystemInformation)
    {
        AddEvidence(anti_cheat::RUNTIME_ERROR, "系统完整性检测失败: 无法获取NtQuerySystemInformation函数地址。");
        return;
    }

    NTSTATUS status = g_pNtQuerySystemInformation(SystemCodeIntegrityInformation, &sci, sizeof(sci), nullptr);
    if (NT_SUCCESS(status))
    {
        // CODEINTEGRITY_OPTION_TESTSIGN (0x02) - 允许加载测试签名的驱动
        if (sci.CodeIntegrityOptions & 0x02)
        {
            AddEvidence(anti_cheat::ENVIRONMENT_SUSPICIOUS_DRIVER, "系统开启了测试签名模式 (Test Signing Mode)");
        }

        // [增强] 检查内核调试模式是否通过 BCD 启动选项开启
        // CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED (0x01)
        if (sci.CodeIntegrityOptions & 0x01)
        {
            AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, "系统开启了内核调试模式 (Kernel Debugging Enabled)");
        }
    }
    else
    {
        AddEvidence(anti_cheat::RUNTIME_ERROR, "系统完整性检测失败: NtQuerySystemInformation调用失败，状态码: " + std::to_string(status));
    }

    // 2. 检查安全启动状态 (Secure Boot) 是一个更复杂的检查，未来可以添加。
    // 这通常需要调用 GetFirmwareEnvironmentVariable 来查询 UEFI 变量。
}

void CheatMonitor::Pimpl::Sensor_CheckAdvancedAntiDebug()
{
    // [改进] 随机化检测顺序，增加破解难度
    std::array<std::function<void()>, 6> checks = {
        // 1. CheckRemoteDebuggerPresent
        [&]()
        {
            BOOL isDebuggerPresent = FALSE;
            if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent) && isDebuggerPresent)
            {
                AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, "CheckRemoteDebuggerPresent() API返回true");
            }
        },
        // 2. PEB->BeingDebugged
        [&]()
        {
#ifdef _WIN64
            auto pPeb = (PPEB)__readgsqword(0x60);
#else
            auto pPeb = (PPEB)__readfsdword(0x30);
#endif
            if (pPeb && pPeb->BeingDebugged)
            {
                AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, "PEB->BeingDebugged 标志位为true");
            }
        },
        // 3. CloseHandle 无效句柄技巧
        []() // [修复] 改为非捕获lambda，避免C2712错误
        { CheckCloseHandleException(); },
        // 4. 硬件断点检查
        [&]()
        {
            CONTEXT ctx = {};
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(GetCurrentThread(), &ctx))
            {
                if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0)
                {
                    AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, "检测到硬件断点 (Debug Registers)");
                }
            }
            else
            {
                AddEvidence(anti_cheat::RUNTIME_ERROR, "反调试检测失败: GetThreadContext 失败。");
            }
        },
        // 5. 内核调试器检测 (NtQuerySystemInformation)
        [&]()
        {
            SYSTEM_KERNEL_DEBUGGER_INFORMATION info;
            if (!g_pNtQuerySystemInformation)
            {
                AddEvidence(anti_cheat::RUNTIME_ERROR, "反调试检测失败: 无法获取NtQuerySystemInformation地址。");
                return;
            }
            if (NT_SUCCESS(g_pNtQuerySystemInformation(SystemKernelDebuggerInformation, &info, sizeof(info), NULL)))
            {
                if (info.KernelDebuggerEnabled && !info.KernelDebuggerNotPresent)
                {
                    AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, "检测到内核调试器 (NtQuerySystemInformation)");
                }
            }
            else
            {
                AddEvidence(anti_cheat::RUNTIME_ERROR, "反调试检测失败: NtQuerySystemInformation(KernelDebugger) 调用失败。");
            }
        },
        // 6. 内核调试器检测 (KUSER_SHARED_DATA)
        [&]()
        {
            const UCHAR *pSharedData = (const UCHAR *)0x7FFE0000;
            if (IsValidPointer(pSharedData, sizeof(UCHAR))) // 检查指针有效性
            {
                const BOOLEAN kdDebuggerEnabled = *(pSharedData + 0x2D4);
                if (kdDebuggerEnabled)
                {
                    AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, "检测到内核调试器 (KUSER_SHARED_DATA)");
                }
            }
        }};

    // 使用密码学安全的随机数生成器来打乱顺序
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(checks.begin(), checks.end(), g);

    // 按随机顺序执行所有检查
    for (const auto &check : checks)
    {
        check();
    }
}

void CheatMonitor::Pimpl::Sensor_ScanNewActivity()
{
    HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnapshot == INVALID_HANDLE_VALUE)
    {
        AddEvidence(anti_cheat::RUNTIME_ERROR, "新活动扫描失败: 无法创建线程快照。");
    }
    else
    {
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        if (Thread32First(hThreadSnapshot, &te))
        {
            do
            {
                if (te.th32OwnerProcessID == GetCurrentProcessId())
                {
                    if (m_knownThreadIds.insert(te.th32ThreadID).second)
                    {
                        std::string evidenceDesc = "检测到新线程 (TID: " + std::to_string(te.th32ThreadID);
                        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                        if (hThread)
                        {
                            PVOID startAddress = nullptr;
                            const int ThreadQuerySetWin32StartAddress = 9;
                            if (g_pNtQueryInformationThread && NT_SUCCESS(g_pNtQueryInformationThread(hThread, (THREADINFOCLASS)ThreadQuerySetWin32StartAddress, &startAddress, sizeof(startAddress), NULL)))
                            {
                                HMODULE hModule = NULL;
                                wchar_t modulePath[MAX_PATH] = {0};
                                if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)startAddress, &hModule) && hModule != NULL)
                                {
                                    if (GetModuleFileNameW(hModule, modulePath, MAX_PATH) > 0)
                                    {
                                        evidenceDesc += ", 位于模块: " + Utils::WideToString(modulePath);
                                    }
                                }
                                else
                                {
                                    evidenceDesc += ", 位于未知内存区域"; // 极有可能是Shellcode
                                }
                            }
                            CloseHandle(hThread);
                        }
                        AddEvidence(anti_cheat::RUNTIME_THREAD_NEW_UNKNOWN, evidenceDesc + ")");
                    }
                }
            } while (Thread32Next(hThreadSnapshot, &te));
        }
        else
        {
            AddEvidence(anti_cheat::RUNTIME_ERROR, "新活动扫描失败: 遍历线程快照失败。");
        }
        CloseHandle(hThreadSnapshot);
    }

    std::vector<HMODULE> hModsVec(1024); // Start with a reasonable size
    DWORD cbNeeded;
    if (EnumProcessModules(GetCurrentProcess(), hModsVec.data(), hModsVec.size() * sizeof(HMODULE), &cbNeeded))
    {
        if (hModsVec.size() * sizeof(HMODULE) < cbNeeded)
        {
            hModsVec.resize(cbNeeded / sizeof(HMODULE));
            if (!EnumProcessModules(GetCurrentProcess(), hModsVec.data(), hModsVec.size() * sizeof(HMODULE), &cbNeeded))
            {
                AddEvidence(anti_cheat::RUNTIME_ERROR, "新活动扫描失败: 无法重新枚举进程模块。");
                return;
            }
        }

        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            if (m_knownModules.insert(hModsVec[i]).second)
            {
                wchar_t szModName[MAX_PATH];
                if (GetModuleFileNameW(hModsVec[i], szModName, MAX_PATH))
                {
                    AddEvidence(anti_cheat::RUNTIME_MODULE_NEW_UNKNOWN, "加载了新模块: " + Utils::WideToString(szModName));
                    VerifyModuleSignature(hModsVec[i]);
                }
                else
                {
                    AddEvidence(anti_cheat::RUNTIME_ERROR, "新活动扫描失败: 无法获取新模块的文件名。");
                }
            }
        }
    }
    else
    {
        AddEvidence(anti_cheat::RUNTIME_ERROR, "新活动扫描失败: 无法枚举进程模块。");
    }
}

void CheatMonitor::Pimpl::Sensor_ScanMemory()
{
    // [重构] 通过定期校验关键模块代码节的哈希值来检测内存Patch。
    // 这个方法比遍历整个进程内存空间的VirtualQuery性能高出几个数量级。

    for (const auto &[modulePath, baselineHash] : m_moduleBaselineHashes)
    {
        HMODULE hModule = GetModuleHandleW(modulePath.c_str());
        if (!hModule)
        {
            std::cout << "[AntiCheat] ScanMemory Warning: Baslined module not found in memory: " << Utils::WideToString(modulePath) << std::endl;
            continue;
        }

        PVOID codeBase = nullptr;
        DWORD codeSize = 0;
        if (GetCodeSectionInfo(hModule, codeBase, codeSize))
        {
            std::vector<uint8_t> currentHash = CalculateHash(static_cast<BYTE *>(codeBase), codeSize);
            if (currentHash != baselineHash)
            {
                AddEvidence(anti_cheat::INTEGRITY_MEMORY_PATCH, "检测到内存代码节被篡改: " + Utils::WideToString(modulePath));
                // [可选] 一旦发现被篡改，可以更新基线为当前哈希，以避免重复上报。
                // 或者，也可以在AddEvidence中实现更复杂的上报冷却逻辑。
                m_moduleBaselineHashes[modulePath] = currentHash;
            }
        }
        else
        {
            std::cout << "[AntiCheat] ScanMemory Error: GetCodeSectionInfo failed for module: " << Utils::WideToString(modulePath) << std::endl;
        }
    }
}

// 验证父进程，防止傀儡进程欺骗
bool CheatMonitor::Pimpl::Sensor_ValidateParentProcess()
{
    DWORD parentPid = 0;
    std::string parentName;
    if (!Utils::GetParentProcessInfo(parentPid, parentName))
    {
        AddEvidence(anti_cheat::ENVIRONMENT_UNKNOWN, "无法获取父进程信息");
        return false;
    }

    // 1. 首先，检查父进程名是否在我们的白名单中。
    std::string lowerParentName = parentName;
    std::transform(lowerParentName.begin(), lowerParentName.end(), lowerParentName.begin(), ::tolower);
    if (m_legitimateParentProcesses.count(lowerParentName) == 0)
    {
        AddEvidence(anti_cheat::ENVIRONMENT_INVALID_PARENT_PROCESS, "由一个不在白名单的父进程启动: " + parentName + " (PID: " + std::to_string(parentPid) + ")");
        return false;
    }

    // 2. [核心重构] 对所有白名单内的父进程，强制执行数字签名验证。
    bool isSignatureValid = false;
    HANDLE hParent = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parentPid);
    if (hParent)
    {
        std::wstring parentPath = Utils::GetProcessFullName(hParent);
        if (!parentPath.empty())
        {
            isSignatureValid = Utils::VerifyFileSignature(parentPath);
        }
        CloseHandle(hParent);
    }

    if (!isSignatureValid)
    {
        AddEvidence(anti_cheat::ENVIRONMENT_INVALID_PARENT_PROCESS, "父进程名称合法 (" + parentName + ")，但其文件未签名或签名无效。");
        return false;
    }

    // 3. [加固] 如果父进程是explorer.exe，执行额外的PID校验。
    //    此时我们已经确认了它是一个微软签名的explorer.exe，现在要确认它是不是当前的桌面Shell实例。
    if (_stricmp(parentName.c_str(), "explorer.exe") == 0)
    {
        HWND hShellWnd = GetShellWindow();
        DWORD shellPid = 0;
        if (hShellWnd)
        {
            GetWindowThreadProcessId(hShellWnd, &shellPid);
        }
        if (!hShellWnd || (DWORD)parentPid != (DWORD)shellPid)
        {
            AddEvidence(anti_cheat::ENVIRONMENT_INVALID_PARENT_PROCESS, "父进程是一个已签名但非激活Shell的explorer.exe实例。");
            return false;
        }
    }

    // 4. 所有检查通过，父进程被确认为合法。
    return true;
}

/**
 * @brief 通过CPUID指令检测虚拟机。
 * 1. 检查 Hypervisor-Present Bit。
 * 2. 检查 Hypervisor 厂商标识字符串。
 */
void CheatMonitor::Pimpl::DetectVmByCpuid()
{
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
    if ((cpuInfo[2] >> 31) & 1)
    {
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

    if (vendorId[0] != '\0')
    { // 仅在厂商字符串非空时进行比较
        for (const auto &vmVendor : vmVendorStrings)
        {
            if (vmVendor == vendorId)
            {
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
void CheatMonitor::Pimpl::DetectVmByRegistry()
{
    // 策略1: 检查特定注册表项的存在。这些项的存在本身就是强证据。
    static constexpr std::array<const char *, 2> vmExistenceKeys = {
        R"(SOFTWARE\Oracle\VirtualBox Guest Additions)", // VirtualBox Guest Additions
        R"(SOFTWARE\VMware, Inc.\VMware Tools)"          // VMware Tools
    };

    for (const char *keyPath : vmExistenceKeys)
    {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
        {
            AddEvidence(anti_cheat::ENVIRONMENT_VIRTUAL_MACHINE,
                        "Registry: Found VM-related key: HKLM\\" + std::string(keyPath));
            RegCloseKey(hKey);
        }
    }

    // 策略2: 检查通用注册表项的值是否包含VM指纹。
    // Disk\Enum 的值通常包含 "VMware", "VBox", "QEMU" 等字符串。
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, R"(SYSTEM\CurrentControlSet\Services\Disk\Enum)", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        char valueName[256];
        DWORD valueNameSize = sizeof(valueName);
        BYTE data[1024];
        DWORD dataSize = sizeof(data);
        DWORD index = 0;

        // 枚举该键下的所有值
        while (RegEnumValueA(hKey, index++, valueName, &valueNameSize, NULL, NULL, data, &dataSize) == ERROR_SUCCESS)
        {
            // 将值数据转换为小写字符串以便不区分大小写地搜索
            std::string valueStr(reinterpret_cast<char *>(data), dataSize);
            std::transform(valueStr.begin(), valueStr.end(), valueStr.begin(), ::tolower);

            if (valueStr.find("vmware") != std::string::npos || valueStr.find("vbox") != std::string::npos || valueStr.find("qemu") != std::string::npos)
            {
                // 截断过长的原始数据以提高可读性
                std::string originalValue(reinterpret_cast<char *>(data), min(dataSize, 100));
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
void CheatMonitor::Pimpl::DetectVmByMacAddress()
{
    // 定义已知虚拟机的MAC地址前缀 (Organizationally Unique Identifier)
    struct MacPrefix
    {
        std::array<BYTE, 3> oui;
        const char *vendor;
    };

    static const std::array<MacPrefix, 4> vmMacPrefixes = {{{{0x00, 0x05, 0x69}, "VMware"},
                                                            {{0x00, 0x0C, 0x29}, "VMware"},
                                                            {{0x08, 0x00, 0x27}, "VirtualBox"},
                                                            {{0x00, 0x15, 0x5D}, "Microsoft Hyper-V"}}};

    ULONG bufferSize = 0;
    // 第一次调用以获取所需的缓冲区大小
    if (GetAdaptersInfo(nullptr, &bufferSize) == ERROR_BUFFER_OVERFLOW)
    {
        return; // 如果没有适配器或发生其他错误，则直接返回
    }

    std::vector<BYTE> buffer(bufferSize);
    auto adapterInfo = reinterpret_cast<IP_ADAPTER_INFO *>(buffer.data());

    // 第二次调用以获取适配器信息
    if (GetAdaptersInfo(adapterInfo, &bufferSize) == ERROR_SUCCESS)
    {
        return; // 获取信息失败
    }

    while (adapterInfo)
    {
        if (adapterInfo->AddressLength == 6)
        { // 确保是标准的6字节MAC地址
            for (const auto &prefix : vmMacPrefixes)
            {
                if (memcmp(adapterInfo->Address, prefix.oui.data(), 3) == 0)
                {
                    AddEvidence(anti_cheat::ENVIRONMENT_VIRTUAL_MACHINE,
                                "MAC: Found " + std::string(prefix.vendor) + " MAC address prefix.");
                    break; // 找到一个匹配项后，检查下一个适配器
                }
            }
        }
        adapterInfo = adapterInfo->Next;
    }
}

std::vector<std::string> CheatMonitor::Pimpl::CollectHardwareFingerprintErrors()
{
    std::vector<std::string> errors;

    // 仅当指纹尚未收集时才执行
    if (m_fingerprint)
        return errors;

    m_fingerprint = std::make_unique<anti_cheat::HardwareFingerprint>();

    // 1. 获取C盘卷序列号
    DWORD serialNum = 0;
    wchar_t systemPath[MAX_PATH];
    if (GetSystemDirectoryW(systemPath, MAX_PATH) > 0)
    {
        // 提取盘符，例如 "C:\\"
        wchar_t drive[] = {systemPath[0], L':', L'\\', L'\\0'};
        if (GetVolumeInformationW(drive, NULL, 0, &serialNum, NULL, NULL, NULL, 0))
        {
            m_fingerprint->set_disk_serial(std::to_string(serialNum));
        }
        else
        {
            errors.emplace_back("硬件指纹收集失败: 无法获取C盘卷序列号。");
        }
    }
    else
    {
        errors.emplace_back("硬件指纹收集失败: 无法获取系统目录。");
    }

    // 2. 获取所有网络适配器的MAC地址
    ULONG bufferSize = 0;
    if (GetAdaptersInfo(nullptr, &bufferSize) == ERROR_BUFFER_OVERFLOW)
    {
        std::vector<BYTE> buffer(bufferSize);
        auto *adapterInfo = reinterpret_cast<IP_ADAPTER_INFO *>(buffer.data());
        if (GetAdaptersInfo(adapterInfo, &bufferSize) == ERROR_SUCCESS)
        {
            while (adapterInfo)
            {
                if (adapterInfo->AddressLength == 6)
                {
                    std::ostringstream oss;
                    oss << std::hex << std::uppercase << std::setfill('0');
                    for (int i = 0; i < 6; ++i)
                    {
                        oss << std::setw(2) << static_cast<int>(adapterInfo->Address[i]) << (i < 5 ? "-" : "");
                    }
                    m_fingerprint->add_mac_addresses(oss.str());
                }
                adapterInfo = adapterInfo->Next;
            }
        }
        else
        {
            errors.emplace_back("硬件指纹收集失败: 无法获取网络适配器信息。");
        }
    }
    else if (bufferSize == 0)
    {
        errors.emplace_back("硬件指纹收集失败: 未找到网络适配器。");
    }
    else
    {
        errors.emplace_back("硬件指纹收集失败: GetAdaptersInfo第一次调用失败。");
    }

    // 3. 获取计算机名
    wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(computerName, &size))
    {
        m_fingerprint->set_computer_name(Utils::WideToString(computerName));
    }
    else
    {
        errors.emplace_back("硬件指纹收集失败: 无法获取计算机名。");
    }

    // 4. 获取操作系统版本
    auto *pRtlGetVersion = (NTSTATUS(WINAPI *)(PRTL_OSVERSIONINFOW))GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlGetVersion");
    if (pRtlGetVersion)
    {
        RTL_OSVERSIONINFOW osInfo = {sizeof(RTL_OSVERSIONINFOW)};
        if (pRtlGetVersion(&osInfo) == 0)
        { // 0 is STATUS_SUCCESS

            std::string osVersion = "OS:" + std::to_string(osInfo.dwMajorVersion) + "." + std::to_string(osInfo.dwMinorVersion) + "." + std::to_string(osInfo.dwBuildNumber);
            m_fingerprint->set_os_version(osVersion);
        }
        else
        {
            errors.emplace_back("硬件指纹收集失败: RtlGetVersion调用失败。");
        }
    }
    else
    {
        errors.emplace_back("硬件指纹收集失败: 无法获取RtlGetVersion函数地址。");
    }

    // 5. 获取CPU信息
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    // GetSystemInfo 总是成功，无需检查返回值。
    std::string cpuInfo = "CPU:Arch=" + std::to_string(sysInfo.wProcessorArchitecture) + ",Cores=" + std::to_string(sysInfo.dwNumberOfProcessors);
    m_fingerprint->set_cpu_info(cpuInfo);

    return errors;
}

void CheatMonitor::Pimpl::Sensor_CheckInputAutomation()
{
    // [修复] 增加锁并优化逻辑，防止数据竞争并减少锁的持有时间。

    // 1. 将共享数据快速复制到局部变量，然后立即释放锁。
    std::vector<MouseMoveEvent> local_moves;
    std::vector<MouseClickEvent> local_clicks;
    {
        std::lock_guard<std::mutex> lock(m_inputMutex);
        // 为避免分析过于频繁或数据量过小，设置一个阈值
        if (m_mouseMoveEvents.size() > 200)
        {
            local_moves.swap(m_mouseMoveEvents); // 使用swap是O(1)操作，比复制更高效
        }
        if (m_mouseClickEvents.size() > 10)
        {
            local_clicks.swap(m_mouseClickEvents);
        }
    }

    // 2. 在局部数据上执行分析，此时已无锁。
    // 分析点击规律性
    if (local_clicks.size() > 5)
    {
        std::vector<double> deltas;
        for (size_t i = 1; i < local_clicks.size(); ++i)
        {
            deltas.push_back(static_cast<double>(local_clicks[i].time - local_clicks[i - 1].time));
        }

        double stddev = InputAnalysis::CalculateStdDev(deltas);
        // 如果点击间隔的标准差小于5毫秒，这在人类操作中几乎不可能，极有可能是宏。
        if (stddev < 5.0 && stddev > 0) // stddev > 0 to avoid single interval case
        {
            AddEvidence(anti_cheat::INPUT_AUTOMATION_DETECTED, "检测到规律性鼠标点击 (StdDev: " + std::to_string(stddev) + "ms)");
        }
    }

    // 3. 分析鼠标移动轨迹
    if (local_moves.size() > 10)
    {
        // a) 检查是否存在完美的直线移动
        int collinear_count = 0;
        for (size_t i = 2; i < local_moves.size(); ++i)
        {
            if (InputAnalysis::ArePointsCollinear(local_moves[i - 2].pt, local_moves[i - 1].pt, local_moves[i].pt))
            {
                collinear_count++;
            }
            else
            {
                collinear_count = 0; // 如果不共线，则重置计数器
            }

            // 如果连续8个或更多点在一条完美的直线上，这对于人类来说是不自然的。
            // 这个阈值可能需要根据实际游戏数据进行调整。
            if (collinear_count >= 8)
            {
                AddEvidence(anti_cheat::INPUT_AUTOMATION_DETECTED, "检测到非自然直线鼠标移动");
                break; // 在这个数据批次中找到一个证据就足够了
            }
        }
    }
}

LRESULT CALLBACK CheatMonitor::Pimpl::LowLevelMouseProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode == HC_ACTION && s_pimpl_for_hooks)
    {

        MSLLHOOKSTRUCT *pMouseStruct = (MSLLHOOKSTRUCT *)lParam;
        if (!pMouseStruct)
        {
            s_pimpl_for_hooks->AddEvidence(anti_cheat::RUNTIME_ERROR, "鼠标钩子回调中lParam为空。");
            return CallNextHookEx(s_pimpl_for_hooks->m_hMouseHook, nCode, wParam, lParam);
        }

        if (pMouseStruct->flags & LLMHF_INJECTED)
        {
            s_pimpl_for_hooks->AddEvidence(anti_cheat::INPUT_AUTOMATION_DETECTED, "检测到注入的鼠标事件 (LLMHF_INJECTED flag)");
        }

        {
            std::lock_guard<std::mutex> lock(s_pimpl_for_hooks->m_inputMutex); // [修复] 加锁保护并发写入
            if (wParam == WM_LBUTTONDOWN || wParam == WM_RBUTTONDOWN)
            {
                if (s_pimpl_for_hooks->m_mouseClickEvents.size() < kMaxMouseClickEvents)
                {
                    s_pimpl_for_hooks->m_mouseClickEvents.push_back({pMouseStruct->time});
                }
            }
            else if (wParam == WM_MOUSEMOVE)
            {
                if (s_pimpl_for_hooks->m_mouseMoveEvents.size() < kMaxMouseMoveEvents)
                {
                    s_pimpl_for_hooks->m_mouseMoveEvents.push_back({pMouseStruct->pt, pMouseStruct->time});
                }
            }
        }
    }
    // 务必调用 CallNextHookEx 将消息传递给钩子链中的下一个钩子
    return CallNextHookEx(s_pimpl_for_hooks->m_hMouseHook, nCode, wParam, lParam);
}

void CheatMonitor::Pimpl::Sensor_CheckVehHooks()
{
#ifdef _WIN64
    const auto pPeb = reinterpret_cast<const BYTE *>(__readgsqword(0x60));
#else
    const auto pPeb = reinterpret_cast<const BYTE *>(__readfsdword(0x30));
#endif

    if (!pPeb)
    {
        AddEvidence(anti_cheat::RUNTIME_ERROR, "VEH Hook检测失败: 无法获取PEB地址。");
        return;
    }
    if (m_vehListOffset == 0)
    {
        // 在InitializeSystem中已记录错误，此处不再重复记录以避免日志泛滥
        return;
    }

    const auto *pVehList = *reinterpret_cast<const VECTORED_HANDLER_LIST *const *>(pPeb + m_vehListOffset);
    if (!pVehList)
    {
        // VEH链表指针为空是正常的，例如未注册任何处理程序时
        return;
    }

    const LIST_ENTRY *pListHead = &pVehList->List;
    const LIST_ENTRY *pCurrentEntry = pListHead->Flink;
    int handlerIndex = 0;
    constexpr int maxHandlersToScan = 32; // 设置上限以防止链表损坏导致的无限循环攻击

    // 辅助函数处理每个处理程序，避免在关键部分使用 C++ 对象展开
    auto ProcessHandler = [&](const VECTORED_HANDLER_ENTRY *pHandlerEntry, int index) -> bool
    {
        const PVOID handlerAddress = pHandlerEntry->Handler;
        std::wstring modulePath;

        // IsAddressInLegitimateModule 会填充 modulePath 并检查其是否在主白名单中
        if (IsAddressInLegitimateModule(handlerAddress, modulePath))
        {
            // 处理程序位于白名单模块中，无需操作
            return true;
        }

        bool hasModule = !modulePath.empty();
        if (hasModule)
        {
            // 将模块路径转换为小写以进行比较
            std::wstring lowerModulePath = modulePath;
            std::transform(lowerModulePath.begin(), lowerModulePath.end(), lowerModulePath.begin(), ::towlower);
            if (m_whitelistedVEHModules.count(lowerModulePath) == 0)
            {
                std::wostringstream woss;
                woss << L"检测到可疑的VEH Hook (Handler #" << index << L").来源: " << modulePath << L", 地址: 0x" << std::hex << handlerAddress;
                AddEvidence(anti_cheat::INTEGRITY_API_HOOK, Utils::WideToString(woss.str()));
            }
        }
        else
        {
            // 处理程序不在任何模块中，可能是 Shellcode
            std::wostringstream woss;
            woss << L"检测到来自Shellcode的VEH Hook (Handler #" << index << L").地址: 0x" << std::hex << handlerAddress;
            AddEvidence(anti_cheat::INTEGRITY_API_HOOK, Utils::WideToString(woss.str()));
        }
        return true;
    };

    // 遍历 VEH 链表，使用指针检查避免异常
    while (pCurrentEntry && pCurrentEntry != pListHead && handlerIndex < maxHandlersToScan)
    {
        // 在解引用前验证指针有效性
        if (!IsValidPointer(pCurrentEntry, sizeof(*pCurrentEntry))) // 替换为实际的指针验证
        {
            AddEvidence(anti_cheat::INTEGRITY_API_HOOK, "遍历VEH链表时检测到无效指针，链表可能已损坏。");
            break;
        }

        const auto *pHandlerEntry = CONTAINING_RECORD(pCurrentEntry, VECTORED_HANDLER_ENTRY, List);

        if (!ProcessHandler(pHandlerEntry, handlerIndex))
        {
            AddEvidence(anti_cheat::INTEGRITY_API_HOOK, "处理VEH处理程序时发生错误，链表可能已损坏。");
            break;
        }

        pCurrentEntry = pCurrentEntry->Flink;
        handlerIndex++;
    }

    if (handlerIndex >= maxHandlersToScan)
    {
        AddEvidence(anti_cheat::INTEGRITY_API_HOOK, "VEH处理程序数量超过上限，链表可能已损坏。");
    }
}

bool CheatMonitor::Pimpl::IsAddressInLegitimateModule(PVOID address, std::wstring &outModulePath)
{
    outModulePath.clear();
    HMODULE hModule = NULL;

    // Attempt to get a handle to the module containing the address
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)address, &hModule) && hModule != NULL)
    {
        wchar_t modulePathBuffer[MAX_PATH] = {0};
        // Get the full path of the module
        if (GetModuleFileNameW(hModule, modulePathBuffer, MAX_PATH) > 0)
        {
            outModulePath = modulePathBuffer;
            std::wstring lowerPath = outModulePath;
            std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
            // [修复] 增加锁来保护对共享集合的并发读取，防止与InitializeSessionBaseline中的写入操作冲突
            {
                std::lock_guard<std::mutex> lock(m_modulePathsMutex);
                return m_legitimateModulePaths.count(lowerPath) > 0;
            }
        }
        else
        {
            std::cout << "[AntiCheat] IsAddressInLegitimateModule Error: GetModuleFileNameW failed for hModule 0x" << std::hex << hModule << std::endl;
        }
    }
    else
    {
        // This can happen if the address is in non-module memory (e.g., JIT code, shellcode), which is a valid case.
        // No need to log an error here.
    }
    // Address is not in any module, or we failed to get the module path
    return false;
}

void CheatMonitor::Pimpl::Sensor_CheckProcessHandles()
{
    using UniqueHandle = std::unique_ptr<void, decltype(&::CloseHandle)>;

    if (!g_pNtQuerySystemInformation)
    {
        AddEvidence(anti_cheat::RUNTIME_ERROR, "进程句柄检测失败: 无法获取NtQuerySystemInformation函数地址。");
        return;
    }

    ULONG bufferSize = 0x10000; // 从64KB开始
    std::vector<BYTE> handleInfoBuffer(bufferSize);
    NTSTATUS status;

    do
    {
        status = g_pNtQuerySystemInformation(SystemHandleInformation, handleInfoBuffer.data(), bufferSize, nullptr);
        if (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            bufferSize *= 2;
            if (bufferSize > 0x4000000)
            { // 设置一个上限（如64MB）以防止无限增长
                AddEvidence(anti_cheat::RUNTIME_ERROR, "进程句柄检测失败: 句柄信息缓冲区增长超出上限。");
                return;
            }
            handleInfoBuffer.resize(bufferSize);
        }
        else if (!NT_SUCCESS(status))
        {
            AddEvidence(anti_cheat::RUNTIME_ERROR, "进程句柄检测失败: NtQuerySystemInformation调用失败，状态码: " + std::to_string(status));
            return;
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    const DWORD ownPid = GetCurrentProcessId();
    const auto *pHandleInfo = reinterpret_cast<const SYSTEM_HANDLE_INFORMATION *>(handleInfoBuffer.data());
    const auto now = std::chrono::steady_clock::now();

    for (ULONG i = 0; i < pHandleInfo->NumberOfHandles; ++i)
    {
        const auto &handle = pHandleInfo->Handles[i];

        if (handle.UniqueProcessId == ownPid ||
            !(handle.GrantedAccess & (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_ALL_ACCESS)))
        {
            continue;
        }

        // 1. [核心性能优化] 检查长期缓存
        auto cacheIt = m_processVerdictCache.find(handle.UniqueProcessId);
        if (cacheIt != m_processVerdictCache.end())
        {
            auto &[verdict, timestamp] = cacheIt->second;
            // 如果缓存未过期，并且是可信的，则直接跳过，这是最高频的路径
            if (now < timestamp + kProcessCacheDuration)
            {
                if (verdict == ProcessVerdict::SIGNED_AND_TRUSTED)
                {
                    continue;
                }
            }
            else
            {
                // 缓存过期，移除它，以便重新验证
                m_processVerdictCache.erase(cacheIt);
            }
        }

        UniqueHandle hOwnerProcess(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE, FALSE, handle.UniqueProcessId), &CloseHandle);
        if (!hOwnerProcess.get())
        {
            continue; // 无法打开进程，可能已退出，跳过
        }

        HANDLE hDup = nullptr;
        if (DuplicateHandle(hOwnerProcess.get(), (HANDLE)handle.HandleValue, GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS))
        {
            UniqueHandle hDupManaged(hDup, &CloseHandle);

            if (GetProcessId(hDupManaged.get()) == ownPid)
            {
                // 只有在确认句柄指向我们后，才进行昂贵的签名验证
                ProcessVerdict currentVerdict = ProcessVerdict::UNSIGNED_OR_UNTRUSTED;
                std::wstring ownerProcessPath = Utils::GetProcessFullName(hOwnerProcess.get());

                if (!ownerProcessPath.empty())
                {
                    // [新增] 检查进程路径是否在白名单中
                    std::wstring lowerOwnerProcessPath = ownerProcessPath;
                    std::transform(lowerOwnerProcessPath.begin(), lowerOwnerProcessPath.end(), lowerOwnerProcessPath.begin(), ::towlower);
                    if (m_whitelistedProcessPaths.count(lowerOwnerProcessPath) > 0)
                    {
                        currentVerdict = ProcessVerdict::SIGNED_AND_TRUSTED; // 白名单进程，视为可信
                    }
                    else if (Utils::VerifyFileSignature(ownerProcessPath))
                    {
                        currentVerdict = ProcessVerdict::SIGNED_AND_TRUSTED;
                    }
                }

                // 2. 更新缓存
                m_processVerdictCache[handle.UniqueProcessId] = {currentVerdict, now};

                // 3. 如果验证结果是不可信，则上报
                if (currentVerdict == ProcessVerdict::UNSIGNED_OR_UNTRUSTED)
                {
                    std::wstring filename = ownerProcessPath.empty() ? L"Unknown" : std::filesystem::path(ownerProcessPath).filename().wstring();
                    std::string evidenceDesc = "未签名的可疑进程持有我们进程的句柄: " + Utils::WideToString(filename) + " (PID: " + std::to_string(handle.UniqueProcessId) + ")";
                    AddEvidence(anti_cheat::INTEGRITY_SUSPICIOUS_HANDLE, evidenceDesc);
                }
            }
        } // DuplicateHandle失败，可能句柄已失效，静默处理
    }
}

void CheatMonitor::Pimpl::VerifyModuleSignature(HMODULE hModule)
{
    wchar_t modPath[MAX_PATH];
    if (GetModuleFileNameW(hModule, modPath, MAX_PATH) == 0)
    {
        std::cout << "[AntiCheat] VerifyModuleSignature Error: GetModuleFileNameW failed for hModule 0x" << std::hex << hModule << std::endl;
        return;
    }

    std::wstring modulePathStr = modPath;
    auto now = std::chrono::steady_clock::now();

    // 1. 检查缓存
    auto it = m_moduleSignatureCache.find(modulePathStr);
    if (it != m_moduleSignatureCache.end())
    {
        auto &[verdict, timestamp] = it->second;
        if (now < timestamp + kSignatureCacheDuration)
        {
            // 缓存未过期，直接使用缓存结果
            if (verdict == SignatureVerdict::UNSIGNED_OR_UNTRUSTED || verdict == SignatureVerdict::VERIFICATION_FAILED)
            {
                // 如果缓存结果是未签名或验证失败，则再次上报（如果需要，可以增加冷却）
                AddEvidence(anti_cheat::RUNTIME_MODULE_NEW_UNKNOWN, "加载了未签名或签名无效的模块 (缓存): " + Utils::WideToString(modulePathStr));
            }
            return; // 缓存命中，直接返回
        }
        else
        {
            // 缓存过期，移除它以便重新验证
            m_moduleSignatureCache.erase(it);
        }
    }

    // 2. 调用通用的签名验证函数
    SignatureVerdict currentVerdict;
    if (Utils::VerifyFileSignature(modulePathStr))
    {
        currentVerdict = SignatureVerdict::SIGNED_AND_TRUSTED;
        std::cout << "[AntiCheat] Info: Module signature verified for " << Utils::WideToString(modulePathStr) << std::endl;
    }
    else
    {
        currentVerdict = SignatureVerdict::UNSIGNED_OR_UNTRUSTED;
        AddEvidence(anti_cheat::RUNTIME_MODULE_NEW_UNKNOWN, "加载了未签名或签名无效的模块: " + Utils::WideToString(modulePathStr));
    }

    // 3. 更新缓存
    m_moduleSignatureCache[modulePathStr] = {currentVerdict, now};
}

// --- Shellcode检测实现 ---

/**
 * @brief 我们的诱饵函数，它将取代原始的VirtualAlloc。
 *        这是实时Shellcode检测的核心。
 * @note  此函数必须是静态的，因为它被用作API钩子的目标。
 *        它通过 s_pimpl_for_hooks 静态指针访问 Pimpl 实例。
 */
LPVOID WINAPI CheatMonitor::Pimpl::DetourVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    // 如果反作弊系统尚未完全初始化，则直接调用原始函数
    if (!s_pimpl_for_hooks)
    {
        return pTrampolineVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
    }

    // 1. 首先，检查请求的内存是否具有执行权限。
    const bool isExecutable = (flProtect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));

    // 2. 如果请求的不是可执行内存，则直接调用原始函数，不进行任何分析。
    //    这是最高频的路径，可以最小化性能开销。
    if (!isExecutable)
    {
        return pTrampolineVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
    }

    // 3. 如果请求了可执行内存，我们需要分析调用者是谁。
    void *callerAddress = _ReturnAddress();
    // 注意：_ReturnAddress() 在某些编译器优化或反调试技术下可能不可靠。
    // 对于更高级的检测，可能需要栈回溯。

    std::wstring modulePath;

    // 4. 检查调用者是否来自一个已知的、合法的模块。
    //    IsAddressInLegitimateModule 内部使用了我们之前建立的白名单 m_legitimateModulePaths。
    if (s_pimpl_for_hooks->IsAddressInLegitimateModule(callerAddress, modulePath))
    {
        // 调用者是合法的（例如，游戏引擎的JIT编译器），直接放行。
    }
    else
    {
        // 5. 调用者来自未知模块或Shellcode，这是一个强烈的可疑信号。
        std::wostringstream woss;
        if (!modulePath.empty())
        {
            // 调用者来自一个已加载但不在白名单的模块
            woss << L"可疑的内存分配请求：一个未知的模块 [" << modulePath << L"] 正在申请可执行内存。";
        }
        else
        {
            // 调用者不属于任何模块，极有可能是Shellcode
            woss << L"可疑的内存分配请求：一段Shellcode正在申请可执行内存。调用者地址: 0x" << std::hex << callerAddress;
        }
        // 上报证据。注意：这里我们只上报，不阻止分配，以避免破坏游戏正常逻辑。
        // AddEvidence内部有冷却机制，但对于高频触发的Shellcode，可能需要更短的局部冷却。
        s_pimpl_for_hooks->AddEvidence(anti_cheat::RUNTIME_MEMORY_EXEC_PRIVATE, Utils::WideToString(woss.str()));
    }

    // 6. 无论如何，都调用原始函数，确保内存分配请求被正确处理。
    return pTrampolineVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}

/**
 * @brief 安装对VirtualAlloc的内联钩子。
 */
void CheatMonitor::Pimpl::InstallVirtualAllocHook()
{
    if (m_isVirtualAllocHooked)
        return;

    std::lock_guard<std::mutex> hookLock(m_hookMutex);
    if (m_isVirtualAllocHooked)
        return; // Double-check after lock

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32)
    {
        AddEvidence(anti_cheat::RUNTIME_ERROR, "Hook安装失败: 无法获取kernel32.dll句柄。");
        return;
    }

    FARPROC pOriginalVirtualAlloc = GetProcAddress(hKernel32, "VirtualAlloc");
    if (!pOriginalVirtualAlloc)
    {
        AddEvidence(anti_cheat::RUNTIME_ERROR, "Hook安装失败: 无法获取VirtualAlloc函数地址。");
        return;
    }

    // For simplicity, we assume a 5-byte JMP. A real implementation
    // would use a disassembler engine like Capstone or Zydis.
    constexpr size_t instructionLength = 5;

    pTrampolineVirtualAlloc = (VirtualAlloc_t)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pTrampolineVirtualAlloc)
    {
        AddEvidence(anti_cheat::RUNTIME_ERROR, "Hook安装失败: 无法为跳板分配内存。");
        return;
    }

    // 1. Build the JMP instruction to our detour function.
    BYTE jmpInstruction[5] = {0xE9, 0x00, 0x00, 0x00, 0x00};
    DWORD_PTR relativeOffset = (DWORD_PTR)CheatMonitor::Pimpl::DetourVirtualAlloc - (DWORD_PTR)pOriginalVirtualAlloc - sizeof(jmpInstruction);
    memcpy(jmpInstruction + 1, &relativeOffset, sizeof(DWORD));

    // 2. Save the original function bytes and copy them to our trampoline.
    memcpy(m_originalVirtualAllocBytes, pOriginalVirtualAlloc, instructionLength);
    memcpy(pTrampolineVirtualAlloc, m_originalVirtualAllocBytes, instructionLength);

    // 3. Add a JMP from the trampoline back to the original function, after the overwritten bytes.
    BYTE *trampolineEnd = (BYTE *)pTrampolineVirtualAlloc + instructionLength;
    BYTE jmpToOriginal[5] = {0xE9, 0x00, 0x00, 0x00, 0x00};
    relativeOffset = ((DWORD_PTR)pOriginalVirtualAlloc + instructionLength) - (DWORD_PTR)trampolineEnd - sizeof(jmpToOriginal);
    memcpy(jmpToOriginal + 1, &relativeOffset, sizeof(DWORD));
    memcpy(trampolineEnd, jmpToOriginal, sizeof(jmpToOriginal));

    // 4. Overwrite the original function with our JMP instruction.
    DWORD oldProtect = 0;
    if (VirtualProtect(pOriginalVirtualAlloc, instructionLength, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        memcpy(pOriginalVirtualAlloc, jmpInstruction, instructionLength);
        VirtualProtect(pOriginalVirtualAlloc, instructionLength, oldProtect, &oldProtect);
        m_isVirtualAllocHooked = true;
    }
    else
    {
        AddEvidence(anti_cheat::RUNTIME_ERROR, "Hook安装失败: VirtualProtect #1 失败。");
        VirtualFree(pTrampolineVirtualAlloc, 0, MEM_RELEASE);
        pTrampolineVirtualAlloc = nullptr;
    }
}

/**
 * @brief 卸载对VirtualAlloc的钩子，恢复原始函数。
 */
void CheatMonitor::Pimpl::UninstallVirtualAllocHook()
{
    if (!m_isVirtualAllocHooked || !pTrampolineVirtualAlloc)
        return;

    std::lock_guard<std::mutex> hookLock(m_hookMutex);
    if (!m_isVirtualAllocHooked || !pTrampolineVirtualAlloc)
        return; // Double-check after lock

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32)
    {
        AddEvidence(anti_cheat::RUNTIME_ERROR, "Hook卸载失败: 无法获取kernel32.dll句柄。");
        return;
    }

    FARPROC pOriginalVirtualAlloc = GetProcAddress(hKernel32, "VirtualAlloc");
    if (!pOriginalVirtualAlloc)
    {
        AddEvidence(anti_cheat::RUNTIME_ERROR, "Hook卸载失败: 无法获取VirtualAlloc函数地址。");
        return;
    }

    constexpr size_t instructionLength = 5;

    DWORD oldProtect = 0;
    if (VirtualProtect(pOriginalVirtualAlloc, instructionLength, PAGE_EXECUTE_READWRITE, &oldProtect))
    {
        memcpy(pOriginalVirtualAlloc, m_originalVirtualAllocBytes, instructionLength);
        VirtualProtect(pOriginalVirtualAlloc, instructionLength, oldProtect, &oldProtect);
    }
    else
    {
        AddEvidence(anti_cheat::RUNTIME_ERROR, "Hook卸载失败: VirtualProtect 失败。");
    }

    VirtualFree(pTrampolineVirtualAlloc, 0, MEM_RELEASE);
    pTrampolineVirtualAlloc = nullptr;
    m_isVirtualAllocHooked = false;
}

void CheatMonitor::Pimpl::Sensor_CheckIatHooks()
{
    // [修复] 重写IAT Hook检测逻辑，使用哈希基线对比，而不是无效的GetProcAddress对比。
    const HMODULE hSelf = GetModuleHandle(NULL);
    if (!hSelf)
        return;

    const BYTE *baseAddress = reinterpret_cast<const BYTE *>(hSelf);
    const IMAGE_DOS_HEADER *pDosHeader = reinterpret_cast<const IMAGE_DOS_HEADER *>(baseAddress);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return;

    const IMAGE_NT_HEADERS *pNtHeaders = reinterpret_cast<const IMAGE_NT_HEADERS *>(baseAddress + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
        return;

    IMAGE_DATA_DIRECTORY importDirectory = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDirectory.VirtualAddress == 0)
        return;

    const IMAGE_IMPORT_DESCRIPTOR *pImportDesc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR *>(baseAddress + importDirectory.VirtualAddress);

    // 遍历每个导入的DLL
    while (pImportDesc->Name)
    {
        const char *dllName = reinterpret_cast<const char *>(baseAddress + pImportDesc->Name);

        // 查找该DLL的基线哈希
        auto it = m_iatBaselineHashes.find(dllName);
        if (it != m_iatBaselineHashes.end())
        {
            const std::vector<uint8_t> &baselineHash = it->second;
            const IMAGE_THUNK_DATA *pThunk = reinterpret_cast<const IMAGE_THUNK_DATA *>(baseAddress + pImportDesc->FirstThunk);

            // 计算当前IAT块的大小
            size_t entryCount = 0;
            const IMAGE_THUNK_DATA *pCurrentThunk = pThunk;
            while (pCurrentThunk->u1.AddressOfData)
            {
                entryCount++;
                pCurrentThunk++;
            }

            if (entryCount > 0)
            {
                // 计算当前IAT块的哈希
                size_t iatBlockSize = entryCount * sizeof(IMAGE_THUNK_DATA);
                std::vector<uint8_t> currentHash = CalculateHash(reinterpret_cast<const BYTE *>(pThunk), iatBlockSize);

                // 与基线哈希对比
                if (currentHash != baselineHash)
                {
                    AddEvidence(anti_cheat::INTEGRITY_API_HOOK, "检测到IAT Hook (哈希不匹配): " + std::string(dllName));
                    // [加固] 更新基线以避免重复报告同一篡改
                    m_iatBaselineHashes[dllName] = currentHash;
                }
            }
        }

        pImportDesc++;
    }
}