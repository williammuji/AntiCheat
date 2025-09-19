#include "CheatMonitor.h"
#include "CheatConfigManager.h"
#include "HardwareInfoCollector.h"
#include "Logger.h"

#include <sstream>
#include <iomanip>

// 定义 NOMINMAX 宏以防止 Windows.h 定义 min/max 宏,
// 从而解决与 std::max 的编译冲突。
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <windows.h>

#include <Iphlpapi.h>  // 为 GetAdaptersInfo 添加头文件
#include <Objbase.h>
#include <Psapi.h>
#include <ShlObj.h>   // CSIDL_PROGRAM_FILES, SHGetFolderPathW
#include <Softpub.h>  // 为 WINTRUST_ACTION_GENERIC_VERIFY_V2 GUID 添加头文件
#include <TlHelp32.h>
#include <intrin.h>
// 注意：ntstatus.h 和 winnt.h 中有重复的宏定义，会导致警告
// 我们只包含 winternl.h，它已经包含了必要的 NTSTATUS 定义
#include <winternl.h>  // 包含 NTSTATUS 等定义
#include <wintrust.h>  // 为 WinVerifyTrust 添加头文件

// 定义未公开的 Windows 系统句柄相关类型
#ifndef SystemHandleInformation
#define SystemHandleInformation 16
#endif

#ifndef SystemExtendedHandleInformation
#define SystemExtendedHandleInformation 64
#endif

// SYSTEM_HANDLE_TABLE_ENTRY_INFO 结构定义
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

// SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX 结构定义
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

#include <algorithm>
#include <array>
#include <deque>
#include <optional>
#include <atomic>
#include <cctype>
#include <cwctype>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <iostream>
#include <memory>
#include <mutex>
#include <numeric>
#include <cmath>
#include <queue>
#include <random>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// 全局NT API函数指针声明
extern "C" {
typedef NTSTATUS(WINAPI *NtQueryInformationThread_t)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI *NtQuerySystemInformation_t)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS(WINAPI *PNtSetInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
                                                  PVOID ThreadInformation, ULONG ThreadInformationLength);
}

// NT API函数指针将在SystemUtils命名空间中定义

// 系统信息结构体定义
typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
    BOOLEAN KernelDebuggerEnabled;
    BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

typedef struct _SYSTEM_CODE_INTEGRITY_INFORMATION
{
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SYSTEM_CODE_INTEGRITY_INFORMATION, *PSYSTEM_CODE_INTEGRITY_INFORMATION;

// 使用系统定义的SYSTEM_INFORMATION_CLASS
const SYSTEM_INFORMATION_CLASS SystemKernelDebuggerInformation = (SYSTEM_INFORMATION_CLASS)35;
// SystemCodeIntegrityInformation已在winternl.h中定义

// VEH相关结构体定义
typedef struct _VECTORED_HANDLER_ENTRY
{
    LIST_ENTRY List;
    PVOID Handler;
} VECTORED_HANDLER_ENTRY, *PVECTORED_HANDLER_ENTRY;

typedef struct _VECTORED_HANDLER_LIST_XP
{
    CRITICAL_SECTION CriticalSection;
    LIST_ENTRY List;
} VECTORED_HANDLER_LIST_XP, *PVECTORED_HANDLER_LIST_XP;

typedef struct _VECTORED_HANDLER_LIST_VISTA
{
    CRITICAL_SECTION CriticalSection;
    LIST_ENTRY ExceptionList;
} VECTORED_HANDLER_LIST_VISTA, *PVECTORED_HANDLER_LIST_VISTA;

typedef struct _VECTORED_HANDLER_LIST_WIN8
{
    CRITICAL_SECTION CriticalSection;
    LIST_ENTRY ExceptionList;
    CRITICAL_SECTION ContinueSection;
    LIST_ENTRY ContinueList;
} VECTORED_HANDLER_LIST_WIN8, *PVECTORED_HANDLER_LIST_WIN8;

namespace SystemUtils
{
// NT API函数指针定义
NtQueryInformationThread_t g_pNtQueryInformationThread = nullptr;
NtQuerySystemInformation_t g_pNtQuerySystemInformation = nullptr;
PNtSetInformationThread g_pNtSetInformationThread = nullptr;

// 初始化NT API函数指针
void EnsureNtApisLoaded()
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll)
        return;
    if (!g_pNtQuerySystemInformation)
    {
        g_pNtQuerySystemInformation =
                reinterpret_cast<NtQuerySystemInformation_t>(GetProcAddress(hNtdll, "NtQuerySystemInformation"));
    }
    if (!g_pNtQueryInformationThread)
    {
        g_pNtQueryInformationThread =
                reinterpret_cast<NtQueryInformationThread_t>(GetProcAddress(hNtdll, "NtQueryInformationThread"));
    }
    if (!g_pNtSetInformationThread)
    {
        g_pNtSetInformationThread =
                reinterpret_cast<PNtSetInformationThread>(GetProcAddress(hNtdll, "NtSetInformationThread"));
    }
}

// 函数声明
bool GetModuleCodeSectionInfo(HMODULE hModule, PVOID &outBase, DWORD &outSize);

// Windows版本枚举定义
enum WindowsVersion
{
    Win_XP,
    Win_Vista_Win7,
    Win_8_Win81,
    Win_10,
    Win_11,
    Win_Unknown
};

// 获取版本
WindowsVersion GetWindowsVersion()
{
    // 使用 RtlGetVersion 获取准确的OS版本信息, 它不受应用程序兼容性助手(shim)的影响。
    typedef NTSTATUS(WINAPI * RtlGetVersion_t)(LPOSVERSIONINFOEXW lpVersionInformation);
    static RtlGetVersion_t pRtlGetVersion =
            (RtlGetVersion_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");

    OSVERSIONINFOEXW osInfo = {0};
    osInfo.dwOSVersionInfoSize = sizeof(osInfo);

    if (pRtlGetVersion)
    {
        pRtlGetVersion(&osInfo);
    }
    else
    {
        // 为无法使用 RtlGetVersion 的旧系统提供降级方案
        if (!GetVersionExW((LPOSVERSIONINFOW)&osInfo))
        {
            return WindowsVersion::Win_Unknown;
        }
    }

    // Windows XP (5.1) - 只有5.1是Windows XP，5.2是Windows Server 2003
    if (osInfo.dwMajorVersion == 5 && osInfo.dwMinorVersion == 1)
        return WindowsVersion::Win_XP;

    // Windows Vista (6.0)
    if (osInfo.dwMajorVersion == 6 && osInfo.dwMinorVersion == 0)
        return WindowsVersion::Win_Vista_Win7;

    // Windows 7 (6.1)
    if (osInfo.dwMajorVersion == 6 && osInfo.dwMinorVersion == 1)
        return WindowsVersion::Win_Vista_Win7;

    // Windows 8 (6.2) 和 Windows 8.1 (6.3)
    if (osInfo.dwMajorVersion == 6 && (osInfo.dwMinorVersion == 2 || osInfo.dwMinorVersion == 3))
        return WindowsVersion::Win_8_Win81;

    // Windows 10 (10.0, Build < 22000)
    if (osInfo.dwMajorVersion == 10 && osInfo.dwBuildNumber < 22000)
        return WindowsVersion::Win_10;

    // Windows 11 (10.0, Build >= 22000)
    if (osInfo.dwMajorVersion == 10 && osInfo.dwBuildNumber >= 22000)
        return WindowsVersion::Win_11;

    return WindowsVersion::Win_Unknown;
}

// 模式扫描（x86）
PBYTE FindPattern(PBYTE base, SIZE_T size, const BYTE *pattern, SIZE_T patternSize, BYTE wildcard = 0x00)
{
    for (SIZE_T i = 0; i < size - patternSize; ++i)
    {
        bool found = true;
        for (SIZE_T j = 0; j < patternSize; ++j)
        {
            if (pattern[j] != wildcard && base[i + j] != pattern[j])
            {
                found = false;
                break;
            }
        }
        if (found)
            return base + i;
    }
    return nullptr;
}

// 辅助结构和函数，避免在SEH中使用C++对象
struct CallerValidationResult
{
    bool success = false;
    HMODULE hModule = nullptr;
    bool inCodeSection = false;
    bool hasModulePath = false;
    wchar_t modulePath[MAX_PATH] = {0};
};

static CallerValidationResult CheckCallerAddressSafe(PVOID caller_address)
{
    CallerValidationResult result;
    __try
    {
        HMODULE hModule = NULL;
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCWSTR)caller_address, &hModule) &&
            hModule)
        {
            result.hModule = hModule;
            result.success = true;

            PVOID codeBase = nullptr;
            DWORD codeSize = 0;
            if (SystemUtils::GetModuleCodeSectionInfo(hModule, codeBase, codeSize))
            {
                uintptr_t addr = reinterpret_cast<uintptr_t>(caller_address);
                uintptr_t start = reinterpret_cast<uintptr_t>(codeBase);
                uintptr_t end = start + codeSize;

                if (addr >= start && addr < end)
                {
                    result.inCodeSection = true;

                    // 获取模块路径
                    if (GetModuleFileNameW(hModule, result.modulePath, MAX_PATH) > 0)
                    {
                        result.hasModulePath = true;
                    }
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        result.success = false;
    }
    return result;
}

// 路径规范化工具：转为规范绝对路径并统一为小写
static std::wstring NormalizePathLowercase(const std::wstring &input)
{
    try
    {
        std::filesystem::path p(input);
        // 使用 weakly_canonical 以尽可能解析相对段但在 Win7 仍兼容
        std::filesystem::path canon = std::filesystem::weakly_canonical(p);
        std::wstring s = canon.wstring();
        std::transform(s.begin(), s.end(), s.begin(), ::towlower);
        return s;
    }
    catch (...)
    {
        std::wstring s = input;
        std::transform(s.begin(), s.end(), s.begin(), ::towlower);
        return s;
    }
}

// 为 NtCreateThreadEx (在代码中用于 DetourNtCreateThread) 定义兼容性结构体,
// 解决 PPS_ATTRIBUTE_LIST 未定义的问题。
typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

// --- 为 NtQuerySystemInformation 定义必要的结构体和类型 ---
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004L
#endif

#ifndef STATUS_INVALID_INFO_CLASS
#define STATUS_INVALID_INFO_CLASS 0xC0000003L
#endif

#ifndef STATUS_NOT_IMPLEMENTED
#define STATUS_NOT_IMPLEMENTED 0xC0000002L
#endif

// 为兼容旧版SDK，手动定义缺失的枚举值
// 注释：现代Windows 10 SDK已包含SystemCodeIntegrityInformation定义
// 但在某些开发环境中可能仍然需要手动定义
#ifndef SystemCodeIntegrityInformation
const int SystemCodeIntegrityInformation = 103;  // 使用标准值103
#endif
// 保留旧值以兼容脚本检查，但运行时不再使用该常量查询句柄信息

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

// 旧版 SYSTEM_HANDLE_INFORMATION（与 TABLE_ENTRY_INFO 搭配），用于回退路径
typedef struct _SYSTEM_HANDLE_INFORMATION_LEGACY
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION_LEGACY, *PSYSTEM_HANDLE_INFORMATION_LEGACY;

// 扩展句柄信息结构（用于SystemExtendedHandleInformation）
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

// 扩展句柄信息容器结构
typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

// 类型定义验证完成

typedef NTSTATUS(WINAPI *PNtQuerySystemInformation)(ULONG SystemInformationClass, PVOID SystemInformation,
                                                    ULONG SystemInformationLength, PULONG ReturnLength);

// --- 为线程隐藏定义必要的结构体和类型 ---

typedef NTSTATUS(WINAPI *PNtQueryInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
                                                    PVOID ThreadInformation, ULONG ThreadInformationLength,
                                                    PULONG ReturnLength);

// 这些定义将移到SystemUtils命名空间中

// PEB->VectoredExceptionHandlers 指向的结构体
typedef struct _VECTORED_HANDLER_LIST
{
    SRWLOCK Lock;
    LIST_ENTRY List;
} VECTORED_HANDLER_LIST, *PVECTORED_HANDLER_LIST;

// 链表中的节点结构

// 检查VBS/HVCI是否启用（返回三态）：true/false/unknown
std::optional<bool> IsVbsEnabled()
{
    HKEY hKey;
    LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", 0, KEY_READ, &hKey);
    if (rc != ERROR_SUCCESS)
    {
        // 权限或不存在等情况，返回unknown
        return std::nullopt;
    }
    DWORD enabled = 0;
    DWORD cb = sizeof(enabled);
    DWORD type = 0;
    if (RegQueryValueExW(hKey, L"EnableVirtualizationBasedSecurity", nullptr, &type, (LPBYTE)&enabled, &cb) !=
                ERROR_SUCCESS ||
        type != REG_DWORD)
    {
        RegCloseKey(hKey);
        return std::nullopt;
    }
    RegCloseKey(hKey);
    return std::optional<bool>(enabled != 0);
}

// 指针验证函数（需根据环境实现）
bool IsValidPointer(const void *ptr, size_t size)
{
    if (!ptr || size == 0)
    {  // 基本的空指针和大小检查
        return false;
    }

    // 检查地址和大小相加是否会导致整数溢出，这是一种更安全的做法
    uintptr_t start_addr = reinterpret_cast<uintptr_t>(ptr);
    if (size > 0 && start_addr > (UINTPTR_MAX - size))
    {
        return false;
    }

    MEMORY_BASIC_INFORMATION mbi;
    // 使用 VirtualQuery 查询内存信息。如果函数失败（返回0），则指针无效。
    if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0)
    {
        return false;
    }

    // 检查内存区域的状态：
    // 1. 必须是已提交的物理内存 (MEM_COMMIT)。
    // 2. 保护属性不能是 PAGE_NOACCESS (完全不可访问) 或 PAGE_GUARD
    // (访问时会触发异常)。
    if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD))
    {
        return false;
    }

    // 最后，确保请求的整个内存块 (从 ptr 到 ptr + size)
    // 完全位于这个查询到的、有效的内存区域内。
    return (start_addr + size) <= (reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize);
}

// 用于动态查找VEH链表偏移量的"诱饵"处理函数。
// 它什么也不做，只是作为一个可被识别的指针存在。
LONG WINAPI DecoyVehHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    UNREFERENCED_PARAMETER(ExceptionInfo);
    return EXCEPTION_CONTINUE_SEARCH;
}

// 此函数不应使用任何需要堆栈展开的C++对象。
// 使用 __try/__except 块来安全地执行此反调试检查。
// 如果没有调试器，会触发一个异常并被捕获。如果附加了调试器，它可能会"吞掉"这个异常，
// 从而改变程序的执行路径，但这本身不是一个可靠的证据来源，更多是用于增加逆向分析的难度。
void CheckCloseHandleException()
{
    __try
    {
        // 使用 reinterpret_cast 和 uintptr_t 以避免C4312警告
        // (在64位上从int到更大的指针的转换)
        CloseHandle(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(0xDEADBEEF)));
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // 异常被捕获，这是没有调试器时的预期行为。什么也不做。
    }
}

// 辅助函数：通过KUSER_SHARED_DATA检测内核调试器
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

// 前向声明
bool GetModuleCodeSectionInfo(HMODULE hModule, PVOID &outBase, DWORD &outSize);

// 辅助函数：计算内存块的FNV-1a哈希值
// 注意：FNV-1a是一种快速非密码学哈希。对于高安全要求，应考虑使用密码学安全哈希（如SHA-256）。
std::vector<uint8_t> CalculateFnv1aHash(const BYTE *data, size_t size)
{
    uint64_t hash = 14695981039346656037ULL;      // FNV_OFFSET_BASIS_64
    const uint64_t fnv_prime = 1099511628211ULL;  // FNV_PRIME_64

    for (size_t i = 0; i < size; ++i)
    {
        hash ^= data[i];
        hash *= fnv_prime;
    }
    std::vector<uint8_t> result(sizeof(hash));
    memcpy(result.data(), &hash, sizeof(hash));
    return result;
}

}  // namespace SystemUtils

namespace Utils
{

// 为签名验证定义四态返回值
enum class SignatureStatus
{
    UNKNOWN,          // 尚未验证
    TRUSTED,          // 可信签名
    UNTRUSTED,        // 不可信签名
    FAILED_TO_VERIFY  // 验证失败
};

std::string WideToString(const std::wstring &wstr)
{
    if (wstr.empty())
        return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    if (size_needed == 0)
    {
        return std::string();
    }
    std::string strTo(size_needed, 0);
    if (WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL) == 0)
    {
        return std::string();
    }
    return strTo;
}

std::wstring StringToWide(const std::string &str)
{
    if (str.empty())
        return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    if (size_needed == 0)
    {
        // Log("[AntiCheat] MultiByteToWideChar failed to get size");
        return std::wstring();
    }
    std::wstring wstrTo(size_needed, 0);
    if (MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed) == 0)
    {
        // Log("[AntiCheat] MultiByteToWideChar failed");
        return std::wstring();
    }
    return wstrTo;
}

// 使用单次遍历和哈希表来查找父进程，避免双重循环。
bool GetParentProcessInfo(DWORD &parentPid, std::string &parentName)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    // 使用智能指针确保句柄总是被关闭
    auto snapshot_closer = [](HANDLE h) { CloseHandle(h); };
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
        return false;  // 遍历失败
    }

    if (ppid > 0)
    {
        auto it = processMap.find(ppid);
        if (it != processMap.end())
        {
            parentPid = ppid;
            parentName = Utils::WideToString(it->second);
            return true;
        }
    }

    return false;  // 未找到父进程
}

std::string GenerateUuid()
{
    GUID guid;
    if (CoCreateGuid(&guid) == S_OK)
    {
        wchar_t uuid_w[40] = {0};
        StringFromGUID2(guid, uuid_w, 40);
        return Utils::WideToString(uuid_w);
    }
    else
    {
        // Log("[AntiCheat] GenerateUuid Error: CoCreateGuid failed.");
    }
    return "";
}

// 为兼容旧版Windows（Vista之前），提供一个QueryFullProcessImageNameW的安全替代方案。
std::wstring GetProcessFullName(HANDLE hProcess)
{
    wchar_t processName[MAX_PATH] = {0};

    // 优先使用 QueryFullProcessImageNameW (Vista+)
    typedef BOOL(WINAPI * PQueryFullProcessImageNameW)(HANDLE, DWORD, LPWSTR, PDWORD);
    static PQueryFullProcessImageNameW pQueryFullProcessImageNameW = (PQueryFullProcessImageNameW)GetProcAddress(
            GetModuleHandleW(L"kernel32.dll"), "QueryFullProcessImageNameW");

    if (pQueryFullProcessImageNameW)
    {
        DWORD size = MAX_PATH;
        if (pQueryFullProcessImageNameW(hProcess, 0, processName, &size))
        {
            return processName;
        }
    }

    // 降级方案：使用 GetModuleFileNameExW (XP+)
    if (GetModuleFileNameExW(hProcess, NULL, processName, MAX_PATH))
    {
        return processName;
    }

    return L"";  // 获取失败
}

// 通用的文件签名验证辅助函数
SignatureStatus VerifyFileSignature(const std::wstring &filePath, SystemUtils::WindowsVersion winVer)
{
    auto to_lower = [](std::wstring s) {
        std::transform(s.begin(), s.end(), s.begin(), ::towlower);
        return s;
    };
    auto ensure_trailing_bs = [](std::wstring &s) {
        if (!s.empty() && s.back() != L'\\')
            s.push_back(L'\\');
    };

    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath.c_str();
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    GUID guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA winTrustData = {};
    winTrustData.cbStruct = sizeof(winTrustData);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    // 关闭在线吊销检查并启用本地缓存，避免离线环境误判
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;  // 使用本地缓存，不访问网络
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileInfo;
    winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

    LONG result = WinVerifyTrust(NULL, &guid, &winTrustData);

    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &guid, &winTrustData);

    if (result == ERROR_SUCCESS)
    {
        return SignatureStatus::TRUSTED;
    }

    // 系统目录判断（用于离线误报降级）
    bool isInWindowsSystemDir = false;
    {
        wchar_t winDirBuf[MAX_PATH] = {0};
        if (GetWindowsDirectoryW(winDirBuf, MAX_PATH) > 0)
        {
            std::wstring winDir = to_lower(winDirBuf);
            ensure_trailing_bs(winDir);
            std::wstring sys32 = winDir + L"system32\\";
            std::wstring syswow64 = winDir + L"syswow64\\";
            std::wstring winsxs = winDir + L"winsxs\\";
            std::wstring drivers = winDir + L"system32\\drivers\\";

            std::wstring pathLower = to_lower(filePath);
            if (pathLower.rfind(sys32, 0) == 0 || pathLower.rfind(syswow64, 0) == 0 ||
                pathLower.rfind(winsxs, 0) == 0 || pathLower.rfind(drivers, 0) == 0)
            {
                isInWindowsSystemDir = true;
            }
        }
    }

    // 离线降噪策略：系统目录中的文件若返回以下错误，降级为“无法判断”（不当作未签名）：
    // - TRUST_E_NOSIGNATURE: 无嵌入签名（很多系统DLL走catalog签名，离线/无catalog场景易触发）
    // - CERT_E_CHAINING / CERT_E_UNTRUSTEDROOT: 链构建失败/不受信根（离线/企业策略常见）
    // - TRUST_E_SYSTEM_ERROR: WinVerifyTrust内部策略/组件出错
    // - CRYPT_E_NO_MATCH: 本地catalog未匹配（离线时常见）
    if (isInWindowsSystemDir)
    {
        if (result == TRUST_E_NOSIGNATURE || result == CERT_E_CHAINING || result == CERT_E_UNTRUSTEDROOT ||
            result == TRUST_E_SYSTEM_ERROR || result == CRYPT_E_NO_MATCH)
        {
            return SignatureStatus::FAILED_TO_VERIFY;
        }
    }

    // [XP兼容性] 对XP系统，宽容处理可能因系统老旧导致的验证错误
    if (winVer == SystemUtils::WindowsVersion::Win_XP)
    {
        switch (result)
        {
            case TRUST_E_SYSTEM_ERROR:
            case TRUST_E_PROVIDER_UNKNOWN:
            case CERT_E_CHAINING:
            case TRUST_E_BAD_DIGEST:                       // 在XP上，SHA-2签名可能导致错误的摘要
                return SignatureStatus::FAILED_TO_VERIFY;  // 降级为"无法判断"而非"不信任"
        }
    }

    // 对其他操作系统或未被XP兼容性规则覆盖的错误，进行标准判断
    switch (result)
    {
        case TRUST_E_NOSIGNATURE:
        case TRUST_E_BAD_DIGEST:
            return SignatureStatus::UNTRUSTED;
        default:
            return SignatureStatus::FAILED_TO_VERIFY;
    }
}

// 前向声明
class ISensor;

// GetModuleCodeSectionInfo 函数实现
// 内部函数，使用C风格参数避免对象展开问题
static bool GetModuleCodeSectionInfoInternal(HMODULE hModule, PVOID *outBase, DWORD *outSize)
{
    if (!hModule || !outBase || !outSize)
        return false;

    const BYTE *baseAddress = reinterpret_cast<const BYTE *>(hModule);

    __try
    {
        const auto *pDosHeader = reinterpret_cast<const IMAGE_DOS_HEADER *>(baseAddress);
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
            return false;
        }

        const auto *pNtHeaders = reinterpret_cast<const IMAGE_NT_HEADERS *>(baseAddress + pDosHeader->e_lfanew);
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
        {
            return false;
        }

        PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
        int codeSectionCount = 0;
        for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++)
        {
            // 寻找第一个可执行代码节 (通常是 .text)
            if (pSectionHeader->Characteristics & IMAGE_SCN_CNT_CODE)
            {
                codeSectionCount++;
                if (codeSectionCount == 1)  // 只取第一个代码节
                {
                    *outBase = (PVOID)(baseAddress + pSectionHeader->VirtualAddress);
                    *outSize = pSectionHeader->Misc.VirtualSize;
                    return true;
                }
            }
        }

        return false;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DWORD exceptionCode = GetExceptionCode();
        LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM,
                      "GetModuleCodeSectionInfo SEH Exception: hModule=0x%p, code=0x%08X", hModule, exceptionCode);
        return false;
    }
}

bool GetModuleCodeSectionInfo(HMODULE hModule, PVOID &outBase, DWORD &outSize)
{
    if (!hModule)
        return false;

    // 预先获取模块路径用于调试
    wchar_t modulePath[MAX_PATH] = {0};
    GetModuleFileNameW(hModule, modulePath, MAX_PATH);

    // 调用内部函数
    PVOID tempBase = nullptr;
    DWORD tempSize = 0;
    bool result = GetModuleCodeSectionInfoInternal(hModule, &tempBase, &tempSize);

    if (result)
    {
        outBase = tempBase;
        outSize = tempSize;
        return true;
    }

    // 记录调试信息
    std::string modulePathStr = "未知模块";
    if (wcslen(modulePath) > 0)
    {
        modulePathStr = WideToString(std::wstring(modulePath));
    }

    LOG_DEBUG_F(AntiCheatLogger::LogCategory::SYSTEM,
                "GetModuleCodeSectionInfo: 未找到代码节, hModule=0x%p, 模块路径=%s", hModule, modulePathStr.c_str());

    return false;
}

}  // namespace Utils

// --- 核心架构组件 ---

class ScanContext;

// 传感器权重分级枚举（基于专家审查建议）
enum class SensorWeight
{
    LIGHT,    // < 1ms: SystemIntegrity, AdvancedAntiDebug
    MEDIUM,   // 1-10ms: IatHook, SelfIntegrity
    HEAVY,    // 10-100ms: MemoryScan, ProcessHandle
    CRITICAL  // > 100ms: VehHook (需特殊处理)
};

// 传感器执行结果枚举
enum class SensorExecutionResult
{
    SUCCESS = 0,  // 成功执行
    TIMEOUT = 1,  // 执行超时
    FAILURE = 2   // 执行失败
};

// --- 传感器实现按重要程度从低到高排列 ---

// ISensor: 所有检测传感器的抽象基类接口 (策略模式)
class ISensor
{
   public:
    virtual ~ISensor() = default;
    virtual const char *GetName() const = 0;     // 用于日志和调试
    virtual SensorWeight GetWeight() const = 0;  // 获取传感器权重分级
    virtual SensorExecutionResult Execute(ScanContext &context) = 0;

   public:
    // 获取最后一次失败原因 - 基类实现
    anti_cheat::SensorFailureReason GetLastFailureReason() const
    {
        return m_lastFailureReason;
    }

   protected:
    // 统一的失败原因记录方法 - 基类实现
    void RecordFailure(anti_cheat::SensorFailureReason reason)
    {
        m_lastFailureReason = reason;
    }

    // 统一的失败原因成员变量 - 所有传感器共享
    anti_cheat::SensorFailureReason m_lastFailureReason = anti_cheat::UNKNOWN_FAILURE;

    // 统一的OS版本检查接口 - 声明
    bool IsOsSupported(ScanContext &context) const;

   private:
};

struct CheatMonitor::Pimpl
{
    Pimpl();  // 新增构造函数

    SystemUtils::WindowsVersion m_windowsVersion;  // 缓存检测到的Windows版本

    // === 系统状态变量 (atomic，无需mutex保护) ===
    std::atomic<bool> m_isSystemActive = false;
    std::atomic<bool> m_isSessionActive = false;
    std::atomic<bool> m_hasServerConfig = false;  // 用于标记是否已收到服务器配置
    std::atomic<bool> m_processBaselineEstablished = false;

    // === 线程和同步 ===
    std::thread m_monitorThread;
    std::condition_variable m_cv;  // 用于唤醒监控线程以快速关停或应用新配置
    std::mutex m_cvMutex;

    // === 模块路径管理 (受m_modulePathsMutex保护) ===
    std::mutex m_modulePathsMutex;
    std::unordered_set<std::wstring> m_legitimateModulePaths;  // 使用哈希集合以实现O(1)复杂度的快速查找

    // === 会话状态管理 (受m_sessionMutex保护) ===
    std::mutex m_sessionMutex;
    uint32_t m_currentUserId = 0;
    std::string m_currentUserName;
    std::set<std::pair<anti_cheat::CheatCategory, std::string>> m_uniqueEvidence;
    std::vector<anti_cheat::Evidence> m_evidences;
    bool m_evidenceOverflowed = false;  // 限流与容量控制
    // 记录每个用户、每种作弊类型的最近上报时间，防止重复上报
    std::map<std::pair<uint32_t, anti_cheat::CheatCategory>, std::chrono::steady_clock::time_point> m_lastReported;

    // === 统一传感器统计缓存 (受m_sensorStatsMutex保护) ===
    std::mutex m_sensorStatsMutex;
    // key: sensor name; value: SensorExecutionStats
    std::unordered_map<std::string, anti_cheat::SensorExecutionStats> m_sensorExecutionStats;

    // === 模块签名验证缓存 (无需mutex保护，串行访问) ===
    enum class SignatureVerdict
    {
        UNKNOWN,
        SIGNED_AND_TRUSTED,
        UNSIGNED_OR_UNTRUSTED,
        VERIFICATION_FAILED
    };
    std::unordered_map<std::wstring, std::pair<SignatureVerdict, std::chrono::steady_clock::time_point>>
            m_moduleSignatureCache;

    // === 签名验证节流 (无需mutex保护，串行访问) ===
    std::unordered_map<std::wstring, std::chrono::steady_clock::time_point> m_sigThrottleUntil;

    // === 跨扫描游标（时间片遍历） ===
    size_t m_handleCursorOffset = 0;  // 上次句柄扫描游标
    size_t m_moduleCursorOffset = 0;  // 上次模块扫描游标

    // === 跨扫描节流（Handle PID DuplicateHandle 尝试）===
    std::unordered_map<DWORD, std::chrono::steady_clock::time_point> m_pidThrottleUntil;

    // === 跨扫描进程签名缓存（减少 WinVerifyTrust 调用）===
    std::unordered_map<std::wstring, std::pair<Utils::SignatureStatus, std::chrono::steady_clock::time_point>>
            m_processSigCache;
    std::unordered_map<std::wstring, std::chrono::steady_clock::time_point> m_processSigThrottleUntil;

    // === 进程验证结果枚举 ===
    enum ProcessVerdict
    {
        SIGNED_AND_TRUSTED,
        UNSIGNED_OR_UNTRUSTED
    };

    // === 基线哈希值 (初始化后只读，无需mutex保护) ===
    std::unordered_map<std::wstring, std::vector<uint8_t>> m_moduleBaselineHashes;
    HMODULE m_hSelfModule = NULL;
    std::vector<uint8_t> m_selfModuleBaselineHash;
    std::unordered_map<std::string, std::vector<uint8_t>> m_iatBaselineHashes;
    uintptr_t m_vehListAddress = 0;  // 存储VEH链表(LdrpVectorHandlerList)的绝对地址

    // === 基线数据 (受m_baselineMutex保护) ===
    std::mutex m_baselineMutex;
    std::set<DWORD> m_knownThreadIds;  // 使用 std::set 以获得更快的查找速度 (O(logN)) 并自动处理重复项
    std::set<HMODULE> m_knownModules;

    std::unique_ptr<anti_cheat::HardwareInfoCollector>
            m_hwCollector;  // 硬件信息采集器（解耦出传感器体系，仅在上报时附带）

    // === 其他状态变量 (无需mutex保护) ===
    HWND m_hGameWindow = NULL;  // 游戏主窗口句柄
    std::random_device m_rd;    // 随机数种子
    std::mt19937 m_rng{std::random_device{}()};

    // === 传感器调度索引 (无需mutex保护，单线程访问) ===
    // 传感器统计上报间隔现在统一使用配置的report_upload_interval_minutes
    size_t m_lightSensorIndex = 0;
    size_t m_heavySensorIndex = 0;
    std::vector<std::unique_ptr<ISensor>> m_lightweightSensors;
    std::vector<std::unique_ptr<ISensor>> m_heavyweightSensors;

    // 执行状态枚举
    enum class ExecutionStatus : int
    {
        SUCCESS = 0,   // 成功执行
        FAILURE = 1,   // 执行失败
        TIMEOUT = 2,   // 执行超时
        EXCEPTION = 3  // 执行异常
    };

    void InitializeSystem();
    void InitializeProcessBaseline();

    void ResetSessionState();
    void OnConfigUpdated();

    // Main loop and state management
    void MonitorLoop();

    // 辅助方法声明
    const std::chrono::milliseconds GetLightScanInterval() const;
    const std::chrono::milliseconds GetHeavyScanInterval() const;
    void ExecuteLightweightSensors();
    void ExecuteHeavyweightSensors();
    void ExecuteAndMonitorSensor(ISensor *sensor, const char *name, bool isHeavyweight);
    void AddRandomJitter();
    void WakeMonitor()
    {
        std::lock_guard<std::mutex> lk(m_cvMutex);
        m_cv.notify_all();
    }

    // 新的分类上报方法
    void UploadHardwareReport();
    void UploadEvidenceReport();
    void UploadTelemetryMetricsReport(const anti_cheat::TelemetryMetrics &metrics);
    void SendReport(const anti_cheat::Report &report);
    // 统一传感器统计记录方法
    void RecordSensorExecutionStats(const char *name, int duration_ms, SensorExecutionResult result,
                                    anti_cheat::SensorFailureReason failureReason = anti_cheat::UNKNOWN_FAILURE);
    // 统一传感器统计批量上报方法
    void UploadSensorExecutionStatsReport();
    // 记录传感器工作量计数器
    void RecordSensorWorkloadCounters(const std::string &name, uint64_t snapshot_size, uint64_t attempts,
                                      uint64_t hits);

    void AddEvidence(anti_cheat::CheatCategory category, const std::string &description);

    // OS版本检查helper方法
    bool IsCurrentOsSupported() const;

    // 使用"诱饵处理函数"技术动态查找VEH链表的地址
    uintptr_t FindVehListAddress();

    void HardenProcessAndThreads();  //  进程与线程加固
    void CheckParentProcessAtStartup();

    void DetectVirtualMachine();
    // VM detection helpers
    void DetectVmByCpuid();
    void DetectVmByRegistry();
    void DetectVmByMacAddress();

    void VerifyModuleSignature(HMODULE hModule);

    // Helper to check if an address belongs to a whitelisted module
    bool IsAddressInLegitimateModule(PVOID address, std::wstring &outModulePath);
    // 只检查地址是否在合法模块中，不返回模块路径
    bool IsAddressInLegitimateModule(PVOID address);

    // IAT hook检查方法
    void CheckIatHooks(ScanContext &context, const BYTE *baseAddress, const IMAGE_IMPORT_DESCRIPTOR *pImportDesc);
};

// ScanContext: 为传感器提供所需依赖的上下文对象
// 这是"依赖倒置"原则的体现，传感器不直接依赖Pimpl，而是依赖这个抽象的上下文
class ScanContext
{
   private:
    CheatMonitor::Pimpl *m_pimpl;  //  持有对Pimpl的指针

   public:
    explicit ScanContext(CheatMonitor::Pimpl *p)
    {
        m_pimpl = p;
    }

    // --- 提供给传感器的服务 ---
    void AddEvidence(anti_cheat::CheatCategory category, const std::string &description)
    {
        m_pimpl->AddEvidence(category, description);
    }

    // --- 提供对配置的只读访问 ---
    std::shared_ptr<const std::vector<std::wstring>> GetHarmfulProcessNames() const
    {
        return CheatConfigManager::GetInstance().GetHarmfulProcessNames();
    }
    std::shared_ptr<const std::vector<std::wstring>> GetHarmfulKeywords() const
    {
        return CheatConfigManager::GetInstance().GetHarmfulKeywords();
    }
    std::shared_ptr<const std::unordered_set<std::wstring>> GetWhitelistedProcessPaths() const
    {
        return CheatConfigManager::GetInstance().GetWhitelistedProcessPaths();
    }
    std::shared_ptr<const std::unordered_set<std::wstring>> GetWhitelistedWindowKeywords() const
    {
        return CheatConfigManager::GetInstance().GetWhitelistedWindowKeywords();
    }
    std::shared_ptr<const std::unordered_set<std::wstring>> GetWhitelistedVEHModules() const
    {
        return CheatConfigManager::GetInstance().GetWhitelistedVEHModules();
    }
    const std::unordered_map<std::string, std::vector<uint8_t>> &GetIatBaselineHashes() const
    {
        return m_pimpl->m_iatBaselineHashes;
    }
    const std::unordered_map<std::wstring, std::vector<uint8_t>> &GetModuleBaselineHashes() const
    {
        return m_pimpl->m_moduleBaselineHashes;
    }
    const uintptr_t GetVehListAddress() const
    {
        return m_pimpl->m_vehListAddress;
    }

    SystemUtils::WindowsVersion GetWindowsVersion() const  // 为传感器提供OS版本信息
    {
        return m_pimpl->m_windowsVersion;
    }

    bool IsCurrentOsSupported() const  // 检查当前OS是否满足配置要求
    {
        return m_pimpl->IsCurrentOsSupported();
    }

    // 提供对Pimpl方法的访问
    void CheckIatHooks(const BYTE *baseAddress, const IMAGE_IMPORT_DESCRIPTOR *pImportDesc)
    {
        ScanContext context(m_pimpl);
        m_pimpl->CheckIatHooks(context, baseAddress, pImportDesc);
    }

    bool IsAddressInLegitimateModule(PVOID address, std::wstring &outModulePath)
    {
        return m_pimpl->IsAddressInLegitimateModule(address, outModulePath);
    }

    bool IsAddressInLegitimateModule(PVOID address)
    {
        return m_pimpl->IsAddressInLegitimateModule(address);
    }

    // 获取已知良好的句柄持有者
    std::shared_ptr<const std::unordered_set<std::wstring>> GetKnownGoodHandleHolders() const
    {
        return CheatConfigManager::GetInstance().GetWhitelistedProcessPaths();
    }

    void UploadTelemetryMetricsReport(const anti_cheat::TelemetryMetrics &metrics)
    {
        m_pimpl->UploadTelemetryMetricsReport(metrics);
    }

    // 记录每轮传感器工作量计数（便于遥测调参）
    void RecordSensorWorkloadCounters(const std::string &name, uint64_t snapshot_size, uint64_t attempts, uint64_t hits)
    {
        m_pimpl->RecordSensorWorkloadCounters(name, snapshot_size, attempts, hits);
    }

    // --- 提供对已知状态的访问 ---
    std::set<DWORD> GetKnownThreadIds() const
    {
        std::lock_guard<std::mutex> lock(m_pimpl->m_baselineMutex);
        return m_pimpl->m_knownThreadIds;
    }
    std::set<HMODULE> GetKnownModules() const
    {
        std::lock_guard<std::mutex> lock(m_pimpl->m_baselineMutex);
        return m_pimpl->m_knownModules;
    }

    // 线程安全地插入线程ID
    bool InsertKnownThreadId(DWORD threadId)
    {
        std::lock_guard<std::mutex> lock(m_pimpl->m_baselineMutex);
        return m_pimpl->m_knownThreadIds.insert(threadId).second;
    }

    // 线程安全地插入模块句柄
    bool InsertKnownModule(HMODULE hModule)
    {
        std::lock_guard<std::mutex> lock(m_pimpl->m_baselineMutex);
        return m_pimpl->m_knownModules.insert(hModule).second;
    }
    void VerifyModuleSignature(HMODULE hModule)
    {
        m_pimpl->VerifyModuleSignature(hModule);
    }

    // 为自我完整性检查提供基线访问
    const HMODULE GetSelfModuleHandle() const
    {
        return m_pimpl->m_hSelfModule;
    }

    // --- 游标与跨扫描状态访问（时间片遍历） ---
    size_t GetHandleCursorOffset() const
    {
        return m_pimpl->m_handleCursorOffset;
    }
    void SetHandleCursorOffset(size_t v)
    {
        m_pimpl->m_handleCursorOffset = v;
    }
    size_t GetModuleCursorOffset() const
    {
        return m_pimpl->m_moduleCursorOffset;
    }
    void SetModuleCursorOffset(size_t v)
    {
        m_pimpl->m_moduleCursorOffset = v;
    }
    std::unordered_map<DWORD, std::chrono::steady_clock::time_point> &GetPidThrottleUntil()
    {
        return m_pimpl->m_pidThrottleUntil;
    }

    // 进程签名缓存（跨扫描）
    std::unordered_map<std::wstring, std::pair<Utils::SignatureStatus, std::chrono::steady_clock::time_point>> &
    GetProcessSigCache()
    {
        return m_pimpl->m_processSigCache;
    }
    std::unordered_map<std::wstring, std::chrono::steady_clock::time_point> &GetProcessSigThrottleUntil()
    {
        return m_pimpl->m_processSigThrottleUntil;
    }
};

// ISensor基类方法实现（需要在ScanContext定义之后）
bool ISensor::IsOsSupported(ScanContext &context) const
{
    return context.IsCurrentOsSupported();
}

// ---- 公共扫描器类 ----
// 用于统一内存、模块、线程扫描逻辑，减少代码重复
class MemoryScanner
{
   public:
    // 内存区域扫描回调函数类型
    using MemoryRegionCallback = std::function<void(const MEMORY_BASIC_INFORMATION &)>;

    // 扫描所有内存区域
    static void ScanMemoryRegions(MemoryRegionCallback callback)
    {
        LPBYTE address = nullptr;
        MEMORY_BASIC_INFORMATION mbi;

        // 生产环境优化：32位系统地址空间保护
        const uintptr_t maxAddress = sizeof(void *) == 4 ? 0x7FFFFFFF : 0x7FFFFFFFFFFF;

        while (VirtualQuery(address, &mbi, sizeof(mbi)))
        {
            // 调用回调函数处理内存区域
            callback(mbi);

            address = reinterpret_cast<LPBYTE>(mbi.BaseAddress) + mbi.RegionSize;

            // 生产环境优化：地址溢出保护
            if (address < reinterpret_cast<LPBYTE>(mbi.BaseAddress) ||
                reinterpret_cast<uintptr_t>(address) > maxAddress)
            {
                break;
            }
        }
    }

    // 扫描私有可执行内存区域
    static void ScanPrivateExecutableMemory(MemoryRegionCallback callback)
    {
        ScanMemoryRegions([&callback](const MEMORY_BASIC_INFORMATION &mbi) {
            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
                (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
            {
                callback(mbi);
            }
        });
    }

    // 扫描可执行内存区域
    static void ScanExecutableMemory(MemoryRegionCallback callback)
    {
        ScanMemoryRegions([&callback](const MEMORY_BASIC_INFORMATION &mbi) {
            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
            {
                callback(mbi);
            }
        });
    }
};

class ModuleScanner
{
   public:
    // 模块扫描回调函数类型
    using ModuleCallback = std::function<void(HMODULE)>;

    // 枚举所有模块
    static void EnumerateModules(ModuleCallback callback)
    {
        std::vector<HMODULE> hMods(1024);  // 使用合理的默认值
        DWORD cbNeeded = 0;

        if (!EnumProcessModules(GetCurrentProcess(), hMods.data(), hMods.size() * sizeof(HMODULE), &cbNeeded))
        {
            DWORD error = GetLastError();
            LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR, "ModuleScanner: EnumProcessModules失败，错误码: 0x%08X",
                        error);
            return;
        }

        size_t moduleCount_actual = cbNeeded / sizeof(HMODULE);

        // 处理第一批模块
        for (size_t i = 0; i < std::min(moduleCount_actual, hMods.size()); ++i)
        {
            callback(hMods[i]);
        }

        // 如果还有更多模块，继续枚举
        while (moduleCount_actual > hMods.size())
        {
            if (!EnumProcessModules(GetCurrentProcess(), hMods.data(), hMods.size() * sizeof(HMODULE), &cbNeeded))
            {
                break;
            }

            moduleCount_actual = cbNeeded / sizeof(HMODULE);
            size_t startIndex = hMods.size();

            for (size_t i = 0; i < std::min(moduleCount_actual - startIndex, hMods.size()); ++i)
            {
                callback(hMods[i]);
            }
        }
    }

    // 获取所有模块句柄
    static std::vector<HMODULE> GetAllModules()
    {
        std::vector<HMODULE> modules;
        modules.reserve(1000);  // 预分配合理大小

        EnumerateModules([&modules](HMODULE hModule) { modules.push_back(hModule); });

        return modules;
    }
};

class ThreadScanner
{
   public:
    // 线程扫描回调函数类型
    using ThreadCallback = std::function<void(DWORD)>;

    // 枚举所有线程
    static void EnumerateThreads(ThreadCallback callback, DWORD targetProcessId = 0)
    {
        if (targetProcessId == 0)
            targetProcessId = GetCurrentProcessId();

        HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hThreadSnapshot == INVALID_HANDLE_VALUE)
        {
            DWORD error = GetLastError();
            LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR,
                        "ThreadScanner: CreateToolhelp32Snapshot失败，错误码: 0x%08X", error);
            return;
        }

        auto snapshot_closer = [](HANDLE h) { CloseHandle(h); };
        std::unique_ptr<void, decltype(snapshot_closer)> snapshot_handle(hThreadSnapshot, snapshot_closer);

        THREADENTRY32 te;
        te.dwSize = sizeof(te);

        if (Thread32First(hThreadSnapshot, &te))
        {
            do
            {
                if (te.th32OwnerProcessID == targetProcessId)
                {
                    callback(te.th32ThreadID);
                }
            } while (Thread32Next(hThreadSnapshot, &te));
        }
    }

    // 获取所有线程ID
    static std::vector<DWORD> GetAllThreads(DWORD targetProcessId = 0)
    {
        std::vector<DWORD> threads;
        threads.reserve(100);  // 预分配合理大小

        EnumerateThreads([&threads](DWORD threadId) { threads.push_back(threadId); }, targetProcessId);

        return threads;
    }

    // 获取线程起始地址
    static PVOID GetThreadStartAddress(DWORD threadId)
    {
        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
        if (!hThread)
            return nullptr;

        auto thread_closer = [](HANDLE h) { CloseHandle(h); };
        std::unique_ptr<void, decltype(thread_closer)> thread_handle(hThread, thread_closer);

        PVOID startAddress = nullptr;
        if (SystemUtils::g_pNtQueryInformationThread &&
            NT_SUCCESS(SystemUtils::g_pNtQueryInformationThread(hThread,
                                                                (THREADINFOCLASS)9,  // ThreadQuerySetWin32StartAddress
                                                                &startAddress, sizeof(startAddress), nullptr)))
        {
            return startAddress;
        }

        return nullptr;
    }
};

// --- 传感器实现按重要程度从低到高排列 ---

class AdvancedAntiDebugSensor : public ISensor
{
   public:
    const char *GetName() const override
    {
        return "AdvancedAntiDebugSensor";
    }
    SensorWeight GetWeight() const override
    {
        return SensorWeight::LIGHT;  // < 1ms: 轻量级反调试检测
    }
    SensorExecutionResult Execute(ScanContext &context) override
    {
        // 重置失败原因
        m_lastFailureReason = anti_cheat::UNKNOWN_FAILURE;

        // 策略1：配置版本门控 - 检查当前OS是否满足配置的最低要求
        if (!IsOsSupported(context))
        {
            LOG_DEBUG(AntiCheatLogger::LogCategory::SENSOR, "高级反调试检测已禁用：当前OS版本低于配置最低要求");
            RecordFailure(anti_cheat::ANTI_DEBUG_OS_VERSION_UNSUPPORTED);
            return SensorExecutionResult::FAILURE;
        }

        // 反调试检测数组 - 按检测速度排序，优先执行快速检测
        std::array<std::pair<std::string, std::function<void()>>, 6> checks = {
                {{"RemoteDebugger", [&]() { CheckRemoteDebugger(context); }},
                 {"PEB_BeingDebugged", [&]() { CheckPEBBeingDebugged(context); }},
                 {"CloseHandle", [&]() { CheckCloseHandleDebugger(context); }},
                 {"DebugRegisters", [&]() { CheckDebugRegisters(context); }},
                 {"KernelDebugger_NtQuery",
                  [&]() {
                      if (SystemUtils::IsVbsEnabled())
                          return;  // 修复：void函数不能返回值
                      CheckKernelDebuggerNtQuery(context);
                  }},
                 {"KernelDebugger_KUSER", [&]() {
                      if (SystemUtils::IsVbsEnabled())
                          return;  // 修复：void函数不能返回值
                      CheckKernelDebuggerKUSER(context);
                  }}}};

        // 执行检测，每两个检测后检查超时
        for (size_t i = 0; i < checks.size(); ++i)
        {
            checks[i].second();
        }

        // 统一的执行结果判断逻辑
        // 成功条件：没有失败原因记录
        if (m_lastFailureReason != anti_cheat::UNKNOWN_FAILURE)
        {
            return SensorExecutionResult::FAILURE;
        }

        return SensorExecutionResult::SUCCESS;
    }

   private:
    // 使用简单的结构体来传递检测结果，避免C++对象展开冲突
    struct DebugDetectionResult
    {
        bool detected;
        const char *description;
        DWORD exceptionCode;
    };

    // 为了避免SEH与C++对象展开冲突，使用C风格的静态函数
    static DebugDetectionResult CheckRemoteDebugger_Internal()
    {
        DebugDetectionResult result = {false, nullptr, 0};
        __try
        {
            BOOL isDebuggerPresent = FALSE;
            if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent) && isDebuggerPresent)
            {
                result.detected = true;
                result.description = "CheckRemoteDebuggerPresent() API返回true";
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            result.exceptionCode = GetExceptionCode();
        }
        return result;
    }

    static DebugDetectionResult CheckPEBBeingDebugged_Internal()
    {
        DebugDetectionResult result = {false, nullptr, 0};
        __try
        {
#ifdef _WIN64
            auto pPeb = (PPEB)__readgsqword(0x60);
#else
            auto pPeb = (PPEB)__readfsdword(0x30);
#endif
            if (pPeb && SystemUtils::IsValidPointer(pPeb, sizeof(PEB)) && pPeb->BeingDebugged)
            {
                result.detected = true;
                result.description = "PEB->BeingDebugged 标志位为true";
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            result.exceptionCode = GetExceptionCode();
        }
        return result;
    }

    static DebugDetectionResult CheckCloseHandleDebugger_Internal()
    {
        DebugDetectionResult result = {false, nullptr, 0};
        __try
        {
            SystemUtils::CheckCloseHandleException();
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            result.exceptionCode = GetExceptionCode();
        }
        return result;
    }

    static DebugDetectionResult CheckDebugRegisters_Internal()
    {
        DebugDetectionResult result = {false, nullptr, 0};
        __try
        {
            CONTEXT ctx = {};
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(GetCurrentThread(), &ctx))
            {
                if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0)
                {
                    result.detected = true;
                    result.description = "检测到硬件断点 (Debug Registers)";
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            result.exceptionCode = GetExceptionCode();
        }
        return result;
    }

    static DebugDetectionResult CheckKernelDebuggerNtQuery_Internal()
    {
        DebugDetectionResult result = {false, nullptr, 0};
        __try
        {
            SYSTEM_KERNEL_DEBUGGER_INFORMATION info;
            if (SystemUtils::g_pNtQuerySystemInformation &&
                NT_SUCCESS(SystemUtils::g_pNtQuerySystemInformation(SystemKernelDebuggerInformation, &info,
                                                                    sizeof(info), NULL)))
            {
                if (info.KernelDebuggerEnabled && !info.KernelDebuggerNotPresent)
                {
                    result.detected = true;
                    result.description = "检测到内核调试器 (NtQuerySystemInformation)";
                }
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            result.exceptionCode = GetExceptionCode();
        }
        return result;
    }

    static DebugDetectionResult CheckKernelDebuggerKUSER_Internal()
    {
        DebugDetectionResult result = {false, nullptr, 0};
        __try
        {
            if (SystemUtils::IsKernelDebuggerPresent_KUserSharedData())
            {
                result.detected = true;
                result.description = "检测到内核调试器 (KUSER_SHARED_DATA)";
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            result.exceptionCode = GetExceptionCode();
        }
        return result;
    }

    // 包装函数，处理结果并调用上下文
    void CheckRemoteDebugger(ScanContext &context)
    {
        auto result = CheckRemoteDebugger_Internal();
        if (result.detected)
        {
            context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, result.description);
        }
        else if (result.exceptionCode != 0)
        {
            LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "RemoteDebugger检测异常: 0x%08X", result.exceptionCode);
        }
    }

    void CheckPEBBeingDebugged(ScanContext &context)
    {
        auto result = CheckPEBBeingDebugged_Internal();
        if (result.detected)
        {
            context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, result.description);
        }
        else if (result.exceptionCode != 0)
        {
            LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "PEB检测异常: 0x%08X", result.exceptionCode);
        }
    }

    void CheckCloseHandleDebugger(ScanContext &context)
    {
        auto result = CheckCloseHandleDebugger_Internal();
        if (result.exceptionCode != 0)
        {
            LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "CloseHandle检测异常: 0x%08X", result.exceptionCode);
        }
    }

    void CheckDebugRegisters(ScanContext &context)
    {
        auto result = CheckDebugRegisters_Internal();
        if (result.detected)
        {
            context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, result.description);
        }
        else if (result.exceptionCode != 0)
        {
            LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "调试寄存器检测异常: 0x%08X", result.exceptionCode);
        }
    }

    void CheckKernelDebuggerNtQuery(ScanContext &context)
    {
        auto result = CheckKernelDebuggerNtQuery_Internal();
        if (result.detected)
        {
            context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, result.description);
        }
        else if (result.exceptionCode != 0)
        {
            LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "内核调试器检测异常: 0x%08X", result.exceptionCode);
        }
    }

    SensorExecutionResult CheckKernelDebuggerKUSER(ScanContext &context)
    {
        auto result = CheckKernelDebuggerKUSER_Internal();
        if (result.detected)
        {
            context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, result.description);
        }
        else if (result.exceptionCode != 0)
        {
            LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "KUSER调试器检测异常: 0x%08X", result.exceptionCode);
        }

        return SensorExecutionResult::SUCCESS;
    }
};

class SystemCodeIntegritySensor : public ISensor
{
   public:
    const char *GetName() const override
    {
        return "SystemCodeIntegritySensor";
    }
    SensorWeight GetWeight() const override
    {
        return SensorWeight::LIGHT;  // < 1ms: 系统代码完整性检测
    }
    SensorExecutionResult Execute(ScanContext &context) override
    {
        // 重置失败原因
        m_lastFailureReason = anti_cheat::UNKNOWN_FAILURE;

        // 策略1：配置版本门控 - 检查当前OS是否满足配置的最低要求
        if (!IsOsSupported(context))
        {
            LOG_DEBUG(AntiCheatLogger::LogCategory::SENSOR, "系统代码完整性检测已禁用：当前OS版本低于配置最低要求");
            RecordFailure(anti_cheat::SYSTEM_CODE_INTEGRITY_OS_VERSION_UNSUPPORTED);
            return SensorExecutionResult::FAILURE;
        }

        SYSTEM_CODE_INTEGRITY_INFORMATION sci = {sizeof(sci), 0};
        ULONG retLen = 0;
        if (SystemUtils::g_pNtQuerySystemInformation &&
            NT_SUCCESS(SystemUtils::g_pNtQuerySystemInformation(SystemCodeIntegrityInformation, &sci, sizeof(sci),
                                                                &retLen)))
        {
            if (sci.CodeIntegrityOptions & 0x02)
            {
                context.AddEvidence(anti_cheat::ENVIRONMENT_SUSPICIOUS_DRIVER,
                                    "系统开启了测试签名模式 (Test Signing Mode)");
            }
            if (sci.CodeIntegrityOptions & 0x01)
            {
                context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED,
                                    "系统开启了内核调试模式 (Kernel Debugging Enabled)");
            }
        }
        else
        {
            // NtQuerySystemInformation失败，记录失败原因
            LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR,
                        "SystemCodeIntegritySensor: NtQuerySystemInformation失败");
            RecordFailure(anti_cheat::SYSTEM_CODE_INTEGRITY_QUERY_FAILED);
            return SensorExecutionResult::FAILURE;
        }

        // 统一的执行结果判断逻辑
        // 成功条件：没有失败原因记录
        if (m_lastFailureReason != anti_cheat::UNKNOWN_FAILURE)
        {
            return SensorExecutionResult::FAILURE;
        }

        return SensorExecutionResult::SUCCESS;
    }
};

class ProcessAndWindowMonitorSensor : public ISensor
{
   public:
    const char *GetName() const override
    {
        return "ProcessAndWindowMonitorSensor";
    }
    SensorWeight GetWeight() const override
    {
        return SensorWeight::MEDIUM;  // 1-10ms: 进程和窗口监控
    }
    SensorExecutionResult Execute(ScanContext &context) override
    {
        // 重置失败原因
        m_lastFailureReason = anti_cheat::UNKNOWN_FAILURE;

        // 获取配置参数
        const int maxProcessesToScan = CheatConfigManager::GetInstance().GetMaxProcessesToScan();
        auto knownGoodProcesses = CheatConfigManager::GetInstance().GetKnownGoodProcesses();

        // 1. 首先，一次性遍历所有窗口，构建一个 PID -> WindowTitles 的映射
        std::unordered_map<DWORD, std::vector<std::wstring>> windowTitlesByPid;
        int windowCount = 0;
        auto enumProc = [](HWND hWnd, LPARAM lParam) -> BOOL {
            auto *pData = reinterpret_cast<std::pair<std::unordered_map<DWORD, std::vector<std::wstring>> *, int *> *>(
                    lParam);
            auto *pMap = pData->first;
            auto *pCount = pData->second;

            if (!IsWindowVisible(hWnd))
                return TRUE;

            if (*pCount >= CheatConfigManager::GetInstance()
                                   .GetMaxWindowCount())  // 窗口数量限制：正常系统通常不超过配置的最大窗口数量
                return FALSE;                             // 达到最大窗口数量限制

            DWORD processId = 0;
            if (!GetWindowThreadProcessId(hWnd, &processId))
            {
                // GetWindowThreadProcessId失败，跳过此窗口
                return TRUE;  // 继续处理下一个窗口
            }
            if (processId > 0)
            {
                int len = GetWindowTextLengthW(hWnd);
                if (len > 0)
                {
                    std::wstring title(static_cast<size_t>(len), L'\0');
                    // GetWindowTextW 会写入终止符，这里分配 len+1
                    std::vector<wchar_t> buf(static_cast<size_t>(len) + 1, L'\0');
                    int copied = GetWindowTextW(hWnd, buf.data(), static_cast<int>(buf.size()));
                    if (copied > 0)
                    {
                        (*pMap)[processId].emplace_back(buf.data());
                        (*pCount)++;
                    }
                    else
                    {
                        // GetWindowTextW失败，跳过此窗口
                    }
                }
            }
            return TRUE;
        };
        std::pair<std::unordered_map<DWORD, std::vector<std::wstring>> *, int *> enumData = {&windowTitlesByPid,
                                                                                             &windowCount};
        if (!EnumWindows(enumProc, reinterpret_cast<LPARAM>(&enumData)))
        {
            LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "ProcessAndWindowMonitorSensor: EnumWindows失败");
            RecordFailure(anti_cheat::PROCESS_WINDOW_ENUM_WINDOWS_FAILED);
            return SensorExecutionResult::FAILURE;
        }

        // 2. 然后，遍历进程列表，进行检查
        using UniqueSnapshotHandle = std::unique_ptr<void, decltype(&::CloseHandle)>;
        UniqueSnapshotHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), &::CloseHandle);
        if (hSnapshot.get() == INVALID_HANDLE_VALUE)
        {
            LOG_ERROR(AntiCheatLogger::LogCategory::SENSOR, "ProcessAndWindowMonitorSensor: 无法创建进程快照");
            RecordFailure(anti_cheat::PROCESS_ENUM_FAILED);
            return SensorExecutionResult::FAILURE;
        }

        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnapshot.get(), &pe))
        {
            int processCount = 0;
            do
            {
                if (processCount >= maxProcessesToScan)
                {
                    LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                                  "ProcessAndWindowMonitorSensor: 达到最大进程扫描数量限制(%d)，可能存在恶意进程干扰",
                                  maxProcessesToScan);
                    break;
                }
                processCount++;
                std::wstring processName = pe.szExeFile;
                std::transform(processName.begin(), processName.end(), processName.begin(), ::towlower);

                // 新增优化：首先通过进程名快速过滤已知的安全进程。
                if (knownGoodProcesses->count(processName) > 0)
                {
                    continue;
                }

                // 可信签名优先：先做昂贵的进程路径与签名检查
                Utils::SignatureStatus signatureStatus = Utils::SignatureStatus::UNKNOWN;
                // 检查点 2: 昂贵的进程路径白名单检查 (仅在需要时执行)
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                if (hProcess)
                {
                    std::wstring fullProcessPath = Utils::GetProcessFullName(hProcess);
                    CloseHandle(hProcess);
                    if (!fullProcessPath.empty())
                    {
                        std::transform(fullProcessPath.begin(), fullProcessPath.end(), fullProcessPath.begin(),
                                       ::towlower);
                        auto whitelistedPaths = context.GetWhitelistedProcessPaths();
                        if (whitelistedPaths && whitelistedPaths->count(fullProcessPath) > 0)
                        {
                            continue;  // 进程在路径白名单中，安全，继续检查下一个进程
                        }

                        // 可信签名优先：若签名可信，则不触发黑名单/窗口关键词告警
                        signatureStatus = Utils::VerifyFileSignature(fullProcessPath, context.GetWindowsVersion());
                        if (signatureStatus == Utils::SignatureStatus::TRUSTED)
                        {
                            continue;  // 已签名可信，跳过此进程
                        }
                    }
                    else
                    {
                        // 获取进程路径失败，记录失败原因和详细信息
                        DWORD lastError = GetLastError();
                        LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                                      "ProcessAndWindowSensor: 获取进程路径失败, 进程名=%s, PID=%lu, 错误=0x%08X (%s)",
                                      Utils::WideToString(pe.szExeFile).c_str(), pe.th32ProcessID, lastError,
                                      lastError == ERROR_ACCESS_DENIED       ? "访问被拒绝"
                                      : lastError == ERROR_INVALID_PARAMETER ? "参数无效"
                                      : lastError == ERROR_INVALID_HANDLE    ? "句柄无效"
                                                                             : "未知错误");
                        RecordFailure(anti_cheat::PROCESS_WINDOW_GET_PROCESS_PATH_FAILED);
                    }
                }
                else
                {
                    // OpenProcess失败，检查是否为正常的权限限制
                    DWORD lastError = GetLastError();

                    // 常见的正常失败情况：
                    // ERROR_ACCESS_DENIED (5) - 访问被拒绝，通常是由于：
                    //   1. 目标进程运行在更高权限级别（如SYSTEM进程）
                    //   2. 目标进程受到保护（如受保护的进程）
                    //   3. 当前进程权限不足（需要管理员权限）
                    // ERROR_INVALID_PARAMETER (87) - 参数无效
                    // ERROR_INVALID_HANDLE (6) - 句柄无效
                    if (lastError == ERROR_ACCESS_DENIED || lastError == ERROR_INVALID_PARAMETER ||
                        lastError == ERROR_INVALID_HANDLE)
                    {
                        // 这些是正常的权限限制，不记录为失败
                        // 提供更详细的错误信息以便调试
                        const char *errorType = (lastError == ERROR_ACCESS_DENIED)       ? "访问被拒绝(权限不足)"
                                                : (lastError == ERROR_INVALID_PARAMETER) ? "参数无效"
                                                                                         : "句柄无效";

                        // 为ERROR_ACCESS_DENIED提供更详细的解释
                        if (lastError == ERROR_ACCESS_DENIED)
                        {
                            LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                                        "无法打开进程 PID %lu (%s)，正常权限限制 (错误码: %lu) - 进程名: %s | "
                                        "可能原因: 1)系统进程 2)受保护进程 3)权限级别不足",
                                        pe.th32ProcessID, errorType, lastError, processName.c_str());
                        }
                        else
                        {
                            LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                                        "无法打开进程 PID %lu (%s)，正常权限限制 (错误码: %lu) - 进程名: %s",
                                        pe.th32ProcessID, errorType, lastError, processName.c_str());
                        }
                    }
                    else
                    {
                        // 其他错误可能是真正的系统问题
                        LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "OpenProcess失败: PID=%lu, 错误码=%lu",
                                      pe.th32ProcessID, lastError);
                        RecordFailure(anti_cheat::PROCESS_WINDOW_OPEN_PROCESS_FAILED);
                    }
                }

                // 检查点 1: 进程名黑名单检查（仅在签名不可信时）
                if (signatureStatus != Utils::SignatureStatus::TRUSTED)
                {
                    auto harmfulProcessNames = context.GetHarmfulProcessNames();
                    if (harmfulProcessNames)
                    {
                        for (const auto &harmful : *harmfulProcessNames)
                        {
                            if (processName.find(harmful) != std::wstring::npos)
                            {
                                context.AddEvidence(anti_cheat::ENVIRONMENT_HARMFUL_PROCESS,
                                                    "有害进程(文件名): " + Utils::WideToString(pe.szExeFile));
                                goto next_process_loop;  // 发现有害进程，直接跳到下一个进程的检查
                            }
                        }
                    }
                }

                // 检查点 3: 窗口标题黑名单检查
                if (signatureStatus != Utils::SignatureStatus::TRUSTED)
                {
                    auto it = windowTitlesByPid.find(pe.th32ProcessID);
                    if (it != windowTitlesByPid.end())
                    {
                        for (const auto &title : it->second)
                        {
                            std::wstring lowerTitle = title;
                            std::transform(lowerTitle.begin(), lowerTitle.end(), lowerTitle.begin(), ::towlower);

                            // 检查窗口标题是否在白名单中
                            bool isWhitelistedWindow = false;
                            auto whitelistedKeywords = context.GetWhitelistedWindowKeywords();
                            if (whitelistedKeywords)
                            {
                                for (const auto &whitelistedKeyword : *whitelistedKeywords)
                                {
                                    if (lowerTitle.find(whitelistedKeyword) != std::wstring::npos)
                                    {
                                        isWhitelistedWindow = true;
                                        break;
                                    }
                                }
                            }
                            if (isWhitelistedWindow)
                            {
                                continue;  // 窗口标题在白名单中，检查下一个窗口标题
                            }

                            // 检查窗口标题是否包含有害关键词
                            auto harmfulKeywords = context.GetHarmfulKeywords();
                            if (harmfulKeywords)
                            {
                                for (const auto &keyword : *harmfulKeywords)
                                {
                                    if (lowerTitle.find(keyword) != std::wstring::npos)
                                    {
                                        context.AddEvidence(anti_cheat::ENVIRONMENT_HARMFUL_PROCESS,
                                                            "有害进程(窗口标题): " + Utils::WideToString(title));
                                        goto next_process_loop;  // 跳出内外两层循环，检查下一个进程
                                    }
                                }
                            }
                        }
                    }
                }

            next_process_loop:;

            } while (Process32NextW(hSnapshot.get(), &pe));
        }

        // 统一的执行结果判断逻辑
        // 成功条件：没有失败原因记录
        if (m_lastFailureReason != anti_cheat::UNKNOWN_FAILURE)
        {
            return SensorExecutionResult::FAILURE;
        }

        return SensorExecutionResult::SUCCESS;
    }
};

class IatHookSensor : public ISensor
{
   public:
    const char *GetName() const override
    {
        return "IatHookSensor";
    }
    SensorWeight GetWeight() const override
    {
        return SensorWeight::MEDIUM;  // 1-10ms: IAT Hook检测
    }
    SensorExecutionResult Execute(ScanContext &context) override
    {
        // 重置失败原因
        m_lastFailureReason = anti_cheat::UNKNOWN_FAILURE;

        // 策略1：配置版本门控 - 检查当前OS是否满足配置的最低要求
        if (!IsOsSupported(context))
        {
            LOG_DEBUG(AntiCheatLogger::LogCategory::SENSOR, "IAT Hook检测已禁用：当前OS版本低于配置最低要求");
            RecordFailure(anti_cheat::IAT_OS_VERSION_UNSUPPORTED);
            return SensorExecutionResult::FAILURE;
        }

        const HMODULE hSelf = GetModuleHandle(NULL);
        if (!hSelf)
        {
            LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "IatHookSensor: 无法获取自身模块句柄");
            RecordFailure(anti_cheat::IAT_GET_MODULE_HANDLE_FAILED);
            return SensorExecutionResult::FAILURE;
        }

        // 生产环境优化：验证模块有效性
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQuery(hSelf, &mbi, sizeof(mbi)) != sizeof(mbi))
        {
            LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "IatHookSensor: 模块内存查询失败");
            RecordFailure(anti_cheat::IAT_VIRTUAL_QUERY_FAILED);
            return SensorExecutionResult::FAILURE;
        }

        // 检查内存状态
        if (mbi.State != MEM_COMMIT)
        {
            LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "IatHookSensor: 模块内存状态异常 (State=0x%08X)",
                          mbi.State);
            RecordFailure(anti_cheat::IAT_MEMORY_STATE_ABNORMAL);
            return SensorExecutionResult::FAILURE;
        }

        // 检查内存保护属性 - 模块基地址可能是数据段，不一定是可执行段
        // 只要内存是可访问的（可读或可执行），就认为是有效的模块内存
        bool hasValidAccess = (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
                                              PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

        if (!hasValidAccess)
        {
            LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "IatHookSensor: 模块内存访问权限异常 (Protect=0x%08X)",
                          mbi.Protect);
            RecordFailure(anti_cheat::IAT_MEMORY_STATE_ABNORMAL);
            return SensorExecutionResult::FAILURE;
        }

        // 记录调试信息
        LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                    "IatHookSensor: 模块内存状态正常 (State=0x%08X, Protect=0x%08X)", mbi.State, mbi.Protect);

        // 执行IAT钩子检测
        bool checkResult = PerformIatIntegrityCheck(context, hSelf);
        if (!checkResult)
        {
            // 失败原因已经在PerformIatIntegrityCheck中设置
            return SensorExecutionResult::FAILURE;
        }

        return SensorExecutionResult::SUCCESS;
    }

   private:
    // 执行IAT完整性检查
    bool PerformIatIntegrityCheck(ScanContext &context, HMODULE hSelf)
    {
        const BYTE *baseAddress = reinterpret_cast<const BYTE *>(hSelf);

        // 1. 验证PE文件结构
        if (!ValidatePeStructure(baseAddress, context))
        {
            return false;
        }

        // 2. 检查导入表完整性
        if (!CheckImportTableIntegrity(context, baseAddress))
        {
            return false;
        }

        return true;
    }

    // 验证PE文件基本结构
    bool ValidatePeStructure(const BYTE *baseAddress, ScanContext &context)
    {
        // 验证DOS头
        if (!baseAddress || !SystemUtils::IsValidPointer(baseAddress, sizeof(IMAGE_DOS_HEADER)))
        {
            LOG_ERROR(AntiCheatLogger::LogCategory::SENSOR, "IAT检测失败：无效的基地址");
            RecordFailure(anti_cheat::IAT_BASE_ADDRESS_INVALID);
            return false;
        }

        const IMAGE_DOS_HEADER *pDosHeader = reinterpret_cast<const IMAGE_DOS_HEADER *>(baseAddress);
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
            LOG_ERROR(AntiCheatLogger::LogCategory::SENSOR, "IAT检测失败：无效的DOS签名");
            RecordFailure(anti_cheat::IAT_DOS_SIGNATURE_INVALID);
            return false;
        }

        // 验证NT头
        const BYTE *ntHeaderAddress = baseAddress + pDosHeader->e_lfanew;
        if (!SystemUtils::IsValidPointer(ntHeaderAddress, sizeof(IMAGE_NT_HEADERS)))
        {
            LOG_ERROR(AntiCheatLogger::LogCategory::SENSOR, "IAT检测失败：NT头地址无效");
            RecordFailure(anti_cheat::IAT_NT_HEADER_INVALID);
            return false;
        }

        const IMAGE_NT_HEADERS *pNtHeaders = reinterpret_cast<const IMAGE_NT_HEADERS *>(ntHeaderAddress);
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
        {
            LOG_ERROR(AntiCheatLogger::LogCategory::SENSOR, "IAT检测失败：无效的NT签名");
            RecordFailure(anti_cheat::IAT_NT_SIGNATURE_INVALID);
            return false;
        }

        return true;
    }

    // 检查导入表完整性
    bool CheckImportTableIntegrity(ScanContext &context, const BYTE *baseAddress)
    {
        const IMAGE_NT_HEADERS *pNtHeaders = reinterpret_cast<const IMAGE_NT_HEADERS *>(
                baseAddress + reinterpret_cast<const IMAGE_DOS_HEADER *>(baseAddress)->e_lfanew);

        // 获取导入表目录
        IMAGE_DATA_DIRECTORY importDirectory = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDirectory.VirtualAddress == 0 || importDirectory.Size == 0)
        {
            // 对于反作弊程序，没有导入表是异常情况，因为需要调用大量系统API
            LOG_ERROR(AntiCheatLogger::LogCategory::SENSOR, "IAT检测失败：反作弊程序缺少导入表，可能被篡改");
            RecordFailure(anti_cheat::IAT_IMPORT_TABLE_ACCESS_FAILED);
            return false;
        }

        // 验证导入表地址
        const BYTE *importDescAddress = baseAddress + importDirectory.VirtualAddress;
        if (!SystemUtils::IsValidPointer(importDescAddress, sizeof(IMAGE_IMPORT_DESCRIPTOR)))
        {
            LOG_ERROR(AntiCheatLogger::LogCategory::SENSOR, "IAT检测失败：导入表地址无效");
            RecordFailure(anti_cheat::IAT_IMPORT_TABLE_ACCESS_FAILED);
            return false;
        }

        // 执行IAT钩子检测
        const IMAGE_IMPORT_DESCRIPTOR *pImportDesc =
                reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR *>(importDescAddress);
        context.CheckIatHooks(baseAddress, pImportDesc);

        return true;
    }
};

class ModuleIntegritySensor : public ISensor
{
   public:
    const char *GetName() const override
    {
        return "ModuleIntegritySensor";
    }
    SensorWeight GetWeight() const override
    {
        return SensorWeight::HEAVY;  // 10-100ms: 模块代码完整性检测
    }

    SensorExecutionResult Execute(ScanContext &context) override
    {
        // 重置失败原因
        m_lastFailureReason = anti_cheat::UNKNOWN_FAILURE;

        // 策略1：配置版本门控 - 检查当前OS版本是否满足配置的最低要求
        if (!IsOsSupported(context))
        {
            LOG_DEBUG(AntiCheatLogger::LogCategory::SENSOR, "模块代码完整性检测已禁用：当前OS版本低于配置最低要求");
            RecordFailure(anti_cheat::MODULE_INTEGRITY_OS_VERSION_UNSUPPORTED);
            return SensorExecutionResult::FAILURE;
        }

        const auto &baselineHashes = context.GetModuleBaselineHashes();

        // 2. 内存使用限制：代码节大小限制
        // ModuleIntegritySensor专注于检测所有模块的代码完整性，但限制单个代码节大小
        const size_t MAX_CODE_SECTION_SIZE = CheatConfigManager::GetInstance().GetMaxCodeSectionSize();
        const int budget_ms = CheatConfigManager::GetInstance().GetHeavyScanBudgetMs();
        const auto startTime = std::chrono::steady_clock::now();

        // 3. 使用公共扫描器枚举模块（游标 + 限额 + 时间片）
        size_t startCursor = context.GetModuleCursorOffset();
        size_t index = 0;
        size_t processed = 0;
        const int maxModules = std::max(1, CheatConfigManager::GetInstance().GetMaxModulesPerScan());
        bool timeoutOccurred = false;
        bool stopEnumerate = false;
        ModuleScanner::EnumerateModules([&](HMODULE hModule) {
            if (stopEnumerate)
                return;
            // 游标：跳过上次已处理过的部分
            if (index++ < startCursor)
                return;

            // 优化：每10个模块检查一次超时，因为模块完整性检查较重
            if (processed % 10 == 0)
            {
                auto now = std::chrono::steady_clock::now();
                if (std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count() > budget_ms)
                {
                    LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "ModuleIntegritySensor超时");
                    RecordFailure(anti_cheat::MODULE_SCAN_TIMEOUT);
                    timeoutOccurred = true;
                    stopEnumerate = true;
                    return;
                }
            }

            ProcessModuleCodeIntegrity(hModule, context, baselineHashes, MAX_CODE_SECTION_SIZE);
            processed++;
            if (processed >= (size_t)maxModules)
            {
                stopEnumerate = true;
                return;
            }
        });

        // 更新游标（按本轮实际处理的模块数轮转）
        if (index > 0)
        {
            size_t nextCursor = (startCursor + processed) % index;
            context.SetModuleCursorOffset(nextCursor);
        }

        // Telemetry: 记录本轮模块快照与处理量
        context.RecordSensorWorkloadCounters("ModuleIntegritySensor", (uint64_t)index, (uint64_t)processed,
                                             (uint64_t)processed);

        // 如果发生超时，直接返回失败
        if (timeoutOccurred)
        {
            return SensorExecutionResult::FAILURE;
        }

        // 检查模块枚举是否成功
        if (index == 0)
        {
            // 检查是否是系统级失败（EnumProcessModules失败）
            std::vector<HMODULE> hMods(1);
            DWORD cbNeeded = 0;
            if (!EnumProcessModules(GetCurrentProcess(), hMods.data(), hMods.size() * sizeof(HMODULE), &cbNeeded))
            {
                LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "ModuleIntegritySensor: 模块枚举失败");
                RecordFailure(anti_cheat::MODULE_INTEGRITY_ENUM_MODULES_FAILED);
                return SensorExecutionResult::FAILURE;
            }
            // 如果没有模块但枚举成功，这是正常情况（系统可能没有加载任何模块）
        }

        // 统一的执行结果判断逻辑
        // 成功条件：没有失败原因记录（包括超时）
        if (m_lastFailureReason != anti_cheat::UNKNOWN_FAILURE)
        {
            return SensorExecutionResult::FAILURE;
        }

        return SensorExecutionResult::SUCCESS;
    }

   private:
    // 处理单个模块的逻辑
    void ProcessModuleCodeIntegrity(HMODULE hModule, ScanContext &context,
                                    const std::unordered_map<std::wstring, std::vector<uint8_t>> &baselineHashes,
                                    size_t maxCodeSectionSize)
    {
        // 注意：不再跳过自身模块，让ModuleCodeIntegritySensor也检测自身完整性
        if (!hModule)
        {
            LOG_DEBUG(AntiCheatLogger::LogCategory::SENSOR, "ModuleIntegritySensor: 跳过空模块句柄");
            return;  // 空句柄，直接返回
        }

        // 获取模块路径
        wchar_t modulePath_w[MAX_PATH] = {0};
        if (GetModuleFileNameW(hModule, modulePath_w, MAX_PATH) == 0)
        {
            RecordFailure(anti_cheat::MODULE_INTEGRITY_GET_MODULE_PATH_FAILED);
            LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                          "ModuleIntegritySensor: 获取模块路径失败, hModule=0x%p, 错误=0x%08X", hModule,
                          GetLastError());
            return;  // 获取路径失败，直接返回
        }

        // 获取代码节信息
        PVOID codeBase = nullptr;
        DWORD codeSize = 0;
        if (!SystemUtils::GetModuleCodeSectionInfo(hModule, codeBase, codeSize))
        {
            // 对于某些特殊模块（如音频库、驱动等），获取代码节失败可能是正常的
            std::wstring moduleName = modulePath_w;
            std::transform(moduleName.begin(), moduleName.end(), moduleName.begin(), ::towlower);

            // 检查是否为已知的特殊模块类型（包括系统保护模块）
            bool isSpecialModule = (moduleName.find(L"fmodex") != std::wstring::npos) ||
                                   (moduleName.find(L"fmod") != std::wstring::npos) ||
                                   (moduleName.find(L"audio") != std::wstring::npos) ||
                                   (moduleName.find(L"sound") != std::wstring::npos) ||
                                   (moduleName.find(L"driver") != std::wstring::npos) ||
                                   // 系统保护模块（被Windows系统保护，无法访问代码节）
                                   (moduleName.find(L"sfc.dll") != std::wstring::npos) ||
                                   (moduleName.find(L"sfc_os.dll") != std::wstring::npos) ||
                                   (moduleName.find(L"wfp.dll") != std::wstring::npos) ||
                                   (moduleName.find(L"wfpdiag.dll") != std::wstring::npos) ||
                                   (moduleName.find(L"ntdll.dll") != std::wstring::npos) ||
                                   (moduleName.find(L"kernel32.dll") != std::wstring::npos) ||
                                   (moduleName.find(L"kernelbase.dll") != std::wstring::npos) ||
                                   (moduleName.find(L"user32.dll") != std::wstring::npos) ||
                                   (moduleName.find(L"gdi32.dll") != std::wstring::npos) ||
                                   (moduleName.find(L"advapi32.dll") != std::wstring::npos) ||
                                   (moduleName.find(L"ole32.dll") != std::wstring::npos) ||
                                   (moduleName.find(L"oleaut32.dll") != std::wstring::npos) ||
                                   (moduleName.find(L"shell32.dll") != std::wstring::npos) ||
                                   (moduleName.find(L"comctl32.dll") != std::wstring::npos) ||
                                   (moduleName.find(L"msvcrt.dll") != std::wstring::npos) ||
                                   (moduleName.find(L"ucrtbase.dll") != std::wstring::npos);

            if (isSpecialModule)
            {
                // 特殊模块的代码节获取失败是正常情况，记录调试信息
                LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                            "ModuleIntegritySensor: 特殊模块代码节获取失败（正常情况）, 模块=%s, hModule=0x%p",
                            Utils::WideToString(modulePath_w).c_str(), hModule);
                return;
            }
            else
            {
                // 普通模块的代码节获取失败需要记录
                RecordFailure(anti_cheat::MODULE_INTEGRITY_GET_CODE_SECTION_FAILED);
                LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                              "ModuleIntegritySensor: 获取代码节信息失败, 模块=%s, hModule=0x%p",
                              Utils::WideToString(modulePath_w).c_str(), hModule);
                return;
            }
        }

        // 检查代码节大小是否超过限制
        if (codeSize > maxCodeSectionSize)
        {
            LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                          "ModuleIntegritySensor: 代码节过大，跳过模块: %s (大小: %lu > %zu MB)",
                          Utils::WideToString(modulePath_w).c_str(), codeSize / (1024 * 1024),
                          maxCodeSectionSize / (1024 * 1024));
            return;
        }

        // 将复杂逻辑移到外部处理
        ValidateModuleCodeIntegrity(modulePath_w, hModule, codeBase, codeSize, context, baselineHashes);
    }

    // 处理模块代码完整性验证的逻辑
    void ValidateModuleCodeIntegrity(const wchar_t *modulePath_w, HMODULE hModule, PVOID codeBase, DWORD codeSize,
                                     ScanContext &context,
                                     const std::unordered_map<std::wstring, std::vector<uint8_t>> &baselineHashes)
    {
        std::wstring modulePath(modulePath_w);
        std::vector<uint8_t> currentHash = SystemUtils::CalculateFnv1aHash(static_cast<BYTE *>(codeBase), codeSize);

        // 检查是否为自身模块
        HMODULE selfModule = context.GetSelfModuleHandle();
        if (!selfModule)
        {
            LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "ModuleIntegritySensor: 无法获取自身模块句柄");
            RecordFailure(anti_cheat::MODULE_INTEGRITY_GET_SELF_MODULE_FAILED);
            return;
        }
        bool isSelfModule = (hModule == selfModule);

        auto it = baselineHashes.find(modulePath);

        if (it == baselineHashes.end())
        {
            // LEARNING MODE: 仅记录一次基线
            static std::set<std::wstring> learned_modules;
            if (learned_modules.find(modulePath) == learned_modules.end())
            {
                std::string hash_str;
                char buf[17];  // 用于 "0x" + 8*2 十六进制字符 + 空字符
                for (uint8_t byte : currentHash)
                {
                    sprintf_s(buf, sizeof(buf), "%02x", byte);
                    hash_str += buf;
                }
                // 基线学习是正常行为，记录到日志中，不产生证据
                LOG_INFO_F(AntiCheatLogger::LogCategory::SENSOR,
                           "ModuleIntegritySensor: 学习新模块基线: %s | Hash: %s | 代码节大小: %lu bytes",
                           Utils::WideToString(modulePath).c_str(), hash_str.c_str(), codeSize);
                learned_modules.insert(modulePath);
            }
        }
        else
        {
            // DETECTION MODE
            if (currentHash != it->second)
            {
                // 生成哈希值字符串用于日志
                std::string currentHash_str, baselineHash_str;
                char buf[17];
                for (uint8_t byte : currentHash)
                {
                    sprintf_s(buf, sizeof(buf), "%02x", byte);
                    currentHash_str += buf;
                }
                for (uint8_t byte : it->second)
                {
                    sprintf_s(buf, sizeof(buf), "%02x", byte);
                    baselineHash_str += buf;
                }

                if (isSelfModule)
                {
                    // 自身模块被篡改，使用专门的证据类型
                    LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR,
                                "ModuleIntegritySensor: 检测到反作弊模块自身被篡改: %s | 当前Hash: %s | 基线Hash: %s | "
                                "代码节大小: %lu bytes",
                                Utils::WideToString(modulePath).c_str(), currentHash_str.c_str(),
                                baselineHash_str.c_str(), codeSize);
                    context.AddEvidence(anti_cheat::INTEGRITY_SELF_TAMPERING,
                                        "检测到反作弊模块自身被篡改: " + Utils::WideToString(modulePath));
                }
                else
                {
                    // 其他模块被篡改
                    LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR,
                                "ModuleIntegritySensor: 检测到模块代码节被篡改: %s | 当前Hash: %s | 基线Hash: %s | "
                                "代码节大小: %lu bytes",
                                Utils::WideToString(modulePath).c_str(), currentHash_str.c_str(),
                                baselineHash_str.c_str(), codeSize);
                    context.AddEvidence(anti_cheat::INTEGRITY_MEMORY_PATCH,
                                        "检测到内存代码节被篡改: " + Utils::WideToString(modulePath));
                }
            }
        }
    }
};

class ProcessHandleSensor : public ISensor
{
   public:
    // 预分配缓冲区管理（C风格，兼容SEH）
    struct HandleBufferManager
    {
        BYTE *buffer;
        size_t size;

        HandleBufferManager() : buffer(nullptr), size(0)
        {
            const size_t initialSize = CheatConfigManager::GetInstance().GetInitialBufferSizeMb() * 1024 * 1024;
            buffer = new BYTE[initialSize];
            size = initialSize;
        }

        ~HandleBufferManager()
        {
            if (buffer)
            {
                delete[] buffer;
                buffer = nullptr;
            }
        }

        bool Resize(size_t newSize)
        {
            const size_t maxSize = CheatConfigManager::GetInstance().GetMaxBufferSizeMb() * 1024 * 1024;
            if (newSize > maxSize)
                return false;

            BYTE *newBuffer = new (std::nothrow) BYTE[newSize];
            if (!newBuffer)
                return false;

            if (buffer)
            {
                delete[] buffer;
            }
            buffer = newBuffer;
            size = newSize;
            return true;
        }

        void Reset()
        {
            if (buffer)
            {
                delete[] buffer;
                const size_t initialSize = CheatConfigManager::GetInstance().GetInitialBufferSizeMb() * 1024 * 1024;
                buffer = new BYTE[initialSize];
                size = initialSize;
            }
        }
    };

    const char *GetName() const override
    {
        return "ProcessHandleSensor";
    }
    SensorWeight GetWeight() const override
    {
        return SensorWeight::HEAVY;  // 10-100ms: 进程句柄扫描
    }

    // 获取进程创建时间标识（用于缓存验证）
    static uint32_t GetProcessCreationTime(DWORD pid)
    {
        // 使用更轻量的方式：检查进程是否仍然存在
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProcess)
            return 0;  // 进程不存在

        // 只获取创建时间，避免昂贵的GetProcessTimes调用
        FILETIME createTime, exitTime, kernelTime, userTime;
        uint32_t creationTime = 0;
        if (GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime))
        {
            // 使用创建时间的低32位作为标识
            creationTime = createTime.dwLowDateTime;
        }
        else
        {
            // GetProcessTimes失败，记录失败原因
            LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                          "ProcessHandleSensor: GetProcessTimes失败 PID %lu，错误: 0x%08X", pid, GetLastError());
            // 注意：这里不调用RecordFailure，因为这是静态方法，无法访问实例
        }

        CloseHandle(hProcess);
        return creationTime;
    }

    SensorExecutionResult Execute(ScanContext &context) override
    {
        // 重置失败原因
        m_lastFailureReason = anti_cheat::UNKNOWN_FAILURE;

        // 1. 配置版本门控
        if (!IsOsSupported(context))
        {
            LOG_DEBUG(AntiCheatLogger::LogCategory::SENSOR, "进程句柄检测已禁用：当前OS版本低于配置最低要求");
            RecordFailure(anti_cheat::PROCESS_HANDLE_OS_VERSION_UNSUPPORTED);
            return SensorExecutionResult::FAILURE;
        }

        // 获取超时预算
        const int budget_ms = CheatConfigManager::GetInstance().GetHeavyScanBudgetMs();
        const auto startTime = std::chrono::steady_clock::now();
        const auto nowCleanup = startTime;  // 用于清理过期缓存

        // 4. API可用性检查
        if (!SystemUtils::g_pNtQuerySystemInformation)
        {
            LOG_ERROR(AntiCheatLogger::LogCategory::SENSOR, "ProcessHandleSensor: NtQuerySystemInformation API不可用");
            RecordFailure(anti_cheat::PROCESS_HANDLE_QUERY_SYSTEM_INFO_FAILED);
            return SensorExecutionResult::FAILURE;
        }

        // 5. 性能上限配置 - 使用配置字段
        ULONG kMaxHandlesToScan = CheatConfigManager::GetInstance().GetMaxHandleScanCount();

        // 5.1 过期清理（PID节流 / 进程签名缓存与节流）
        {
            auto &pidTtl = context.GetPidThrottleUntil();
            for (auto it = pidTtl.begin(); it != pidTtl.end();)
            {
                if (nowCleanup >= it->second)
                    it = pidTtl.erase(it);
                else
                    ++it;
            }
            auto &procCache = context.GetProcessSigCache();
            auto &procThr = context.GetProcessSigThrottleUntil();
            const auto sigTtl =
                    std::chrono::minutes(CheatConfigManager::GetInstance().GetSignatureCacheDurationMinutes());
            for (auto it = procCache.begin(); it != procCache.end();)
            {
                if (nowCleanup >= it->second.second + sigTtl)
                    it = procCache.erase(it);
                else
                    ++it;
            }
            for (auto it = procThr.begin(); it != procThr.end();)
            {
                if (nowCleanup >= it->second)
                    it = procThr.erase(it);
                else
                    ++it;
            }
        }

        // 6. 内存管理优化：使用预分配缓冲区 + 兼容回退
        HandleBufferManager bufferManager;
        NTSTATUS status;
        int retries = 0;
        bool useLegacy = false;

        while (true)
        {
            status = SystemUtils::g_pNtQuerySystemInformation
                             ? SystemUtils::g_pNtQuerySystemInformation(
                                       useLegacy ? (SYSTEM_INFORMATION_CLASS)SystemHandleInformation
                                                 : (SYSTEM_INFORMATION_CLASS)SystemExtendedHandleInformation,
                                       bufferManager.buffer, static_cast<ULONG>(bufferManager.size), nullptr)
                             : (NTSTATUS)STATUS_NOT_IMPLEMENTED;

            if (status == STATUS_INFO_LENGTH_MISMATCH)
            {
                size_t newSize = bufferManager.size * 2;
                if (!bufferManager.Resize(newSize))
                {
                    LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR,
                                "ProcessHandleSensor: 缓冲区大小超过限制 (%zu bytes)，跳过扫描", newSize);
                    RecordFailure(anti_cheat::PROCESS_HANDLE_BUFFER_SIZE_EXCEEDED);
                    return SensorExecutionResult::FAILURE;
                }
                retries++;
                if (retries > 3)
                {
                    LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR,
                                "ProcessHandleSensor: 获取句柄信息重试过多 (%d次)，跳过扫描", retries);
                    RecordFailure(anti_cheat::PROCESS_HANDLE_RETRY_EXCEEDED);
                    return SensorExecutionResult::FAILURE;
                }
                continue;
            }

            if (!useLegacy && (status == STATUS_INVALID_INFO_CLASS || status == STATUS_NOT_IMPLEMENTED))
            {
                LOG_DEBUG(AntiCheatLogger::LogCategory::SENSOR,
                          "ProcessHandleSensor: 扩展句柄信息类不可用，回退到旧结构");
                useLegacy = true;
                bufferManager.Reset();
                retries = 0;
                continue;
            }
            break;
        }

        if (!NT_SUCCESS(status))
        {
            LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR,
                        "ProcessHandleSensor: NtQuerySystemInformation失败，状态码: 0x%08X", status);
            RecordFailure(anti_cheat::PROCESS_HANDLE_QUERY_SYSTEM_INFO_FAILED);
            return SensorExecutionResult::FAILURE;
        }

        // 7. 句柄数量上限检查（支持扩展/回退两种结构）
        const void *pHandleInfoEx = reinterpret_cast<const void *>(bufferManager.buffer);
        const void *pHandleInfoLegacy = reinterpret_cast<const void *>(bufferManager.buffer);
        ULONG_PTR totalHandles = useLegacy ? (ULONG_PTR)((const ULONG *)pHandleInfoLegacy)[0]
                                           : (ULONG_PTR)((const ULONG_PTR *)pHandleInfoEx)[0];
        if (totalHandles > kMaxHandlesToScan)
        {
            // 提供更详细的上下文信息
            double handleRatio = static_cast<double>(totalHandles) / kMaxHandlesToScan;
            LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                          "ProcessHandleSensor: 系统句柄数量超过上限 (%lu > %lu, 超出%.1f%%)，跳过扫描以确保系统性能。"
                          "建议：1) 检查系统是否有句柄泄漏 2) 考虑增加max_handle_scan_count配置值",
                          (ULONG)totalHandles, kMaxHandlesToScan, (handleRatio - 1.0) * 100.0);
            RecordFailure(anti_cheat::PROCESS_HANDLE_HANDLE_COUNT_EXCEEDED);
            return SensorExecutionResult::FAILURE;
        }

        // 记录句柄数量统计信息（仅在DEBUG级别）
        LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                    "ProcessHandleSensor: 开始扫描 %lu 个系统句柄 (上限: %lu, 使用率: %.1f%%)%s", (ULONG)totalHandles,
                    kMaxHandlesToScan, static_cast<double>(totalHandles) / kMaxHandlesToScan * 100.0,
                    useLegacy ? " [LEGACY]" : "");

        // 8. 主扫描循环
        const DWORD ownPid = GetCurrentProcessId();
        if (ownPid == 0)
        {
            LOG_ERROR(AntiCheatLogger::LogCategory::SENSOR, "ProcessHandleSensor: GetCurrentProcessId失败");
            RecordFailure(anti_cheat::PROCESS_HANDLE_GET_PROCESS_ID_FAILED);
            return SensorExecutionResult::FAILURE;
        }

        const auto now = std::chrono::steady_clock::now();
        // 跨扫描缓存：进程路径签名结果（减少 WinVerifyTrust 调用）
        auto &processSigCache = context.GetProcessSigCache();
        auto &processSigThrottleUntil = context.GetProcessSigThrottleUntil();

        // 系统目录前缀缓存（小工具）
        struct SysDirs
        {
            std::wstring sys32, syswow64, winsxs, drivers;
            bool initialized = false;
        };
        static SysDirs s_sysDirs;
        auto ensureSysDirs = [&]() {
            if (!s_sysDirs.initialized)
            {
                wchar_t winDirBuf[MAX_PATH] = {0};
                if (GetWindowsDirectoryW(winDirBuf, MAX_PATH) > 0)
                {
                    std::wstring winDir = winDirBuf;
                    std::transform(winDir.begin(), winDir.end(), winDir.begin(), ::towlower);
                    if (!winDir.empty() && winDir.back() != L'\\')
                        winDir.push_back(L'\\');
                    s_sysDirs.sys32 = winDir + L"system32\\";
                    s_sysDirs.syswow64 = winDir + L"syswow64\\";
                    s_sysDirs.winsxs = winDir + L"winsxs\\";
                    s_sysDirs.drivers = winDir + L"system32\\drivers\\";
                }
                s_sysDirs.initialized = true;
            }
        };
        auto isSystemDirPath = [&](const std::wstring &path) -> bool {
            ensureSysDirs();
            std::wstring lower = path;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
            if (lower.rfind(s_sysDirs.sys32, 0) == 0)
                return true;
            if (lower.rfind(s_sysDirs.syswow64, 0) == 0)
                return true;
            if (lower.rfind(s_sysDirs.winsxs, 0) == 0)
                return true;
            if (lower.rfind(s_sysDirs.drivers, 0) == 0)
                return true;
            return false;
        };
        std::unordered_set<DWORD> processedPidsThisScan;
        ULONG handlesProcessed = 0;
        ULONG openProcDeniedCount = 0;     // ERROR_ACCESS_DENIED
        ULONG openProcInvalidCount = 0;    // ERROR_INVALID_PARAMETER/ERROR_INVALID_HANDLE
        ULONG openProcOtherFailCount = 0;  // 其他错误

        // 智能缓存：使用路径作为键（移到SEH块外）
        struct PathCacheEntry
        {
            CheatMonitor::Pimpl::ProcessVerdict verdict;
            std::chrono::steady_clock::time_point cached_at;
            uint32_t process_creation_time;  // 修复：字段名更准确
            std::wstring process_name;
            Utils::SignatureStatus signature_status;
        };
        std::unordered_map<std::wstring, PathCacheEntry> pathCache;

        // 游标 + 限额（时间片遍历）
        ULONG_PTR total = totalHandles;
        ULONG_PTR cursorStart = (total > 0) ? (ULONG_PTR)(context.GetHandleCursorOffset() % total) : 0;
        const int maxPidAttempts = std::max(1, CheatConfigManager::GetInstance().GetMaxPidAttemptsPerScan());
        int pidAttempts = 0;
        ULONG_PTR entriesVisited = 0;
        auto &pidTtlMap = context.GetPidThrottleUntil();

        if (!useLegacy)
        {
            for (ULONG_PTR step = 0; step < total; ++step)
            {
                ULONG_PTR i = (cursorStart + step) % total;
                // 优化：每200个句柄检查一次超时，减少微小开销
                if (step % 200 == 0)
                {
                    auto currentTime = std::chrono::steady_clock::now();
                    auto elapsed_ms =
                            std::chrono::duration_cast<std::chrono::milliseconds>(currentTime - startTime).count();

                    if (elapsed_ms > budget_ms)
                    {
                        LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                                      "ProcessHandleSensor: 扫描超时，已处理 %lu/%lu 个句柄，耗时%ldms",
                                      handlesProcessed, (ULONG)total, elapsed_ms);
                        this->RecordFailure(anti_cheat::PROCESS_HANDLE_SCAN_TIMEOUT);
                        context.SetHandleCursorOffset(cursorStart + entriesVisited);
                        return SensorExecutionResult::FAILURE;
                    }
                }

                const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX &handle =
                        ((const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX *)((const BYTE *)pHandleInfoEx +
                                                                     sizeof(ULONG_PTR) * 2))[i];

                // 快速过滤
                DWORD ownerPid = static_cast<DWORD>(handle.UniqueProcessId);
                if (ownerPid == ownPid || processedPidsThisScan.count(ownerPid) > 0 ||
                    !(handle.GrantedAccess &
                      (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_ALL_ACCESS)))
                {
                    entriesVisited++;
                    continue;
                }

                // 跨扫描节流与限额
                const auto pidIt = pidTtlMap.find(ownerPid);
                if (pidIt != pidTtlMap.end() && now < pidIt->second)
                {
                    entriesVisited++;
                    continue;
                }
                if (pidAttempts >= maxPidAttempts)
                {
                    context.SetHandleCursorOffset(cursorStart + entriesVisited);
                    break;
                }
                pidAttempts++;

                // 句柄指向性验证
                if (!IsHandlePointingToUs_Safe((const void *)&handle, ownPid))
                {
                    pidTtlMap[ownerPid] =
                            now + std::chrono::minutes(CheatConfigManager::GetInstance().GetPidThrottleMinutes());
                    entriesVisited++;
                    continue;
                }

                processedPidsThisScan.insert(ownerPid);
                pidTtlMap[ownerPid] =
                        now + std::chrono::minutes(CheatConfigManager::GetInstance().GetPidThrottleMinutes());
                handlesProcessed++;
                entriesVisited++;

                // 进程路径获取（优化：避免重复获取）
                std::wstring ownerProcessPath;
                std::wstring lowerProcessName;
                Utils::SignatureStatus signatureStatus = Utils::SignatureStatus::UNKNOWN;

                using UniqueHandle = std::unique_ptr<void, decltype(&::CloseHandle)>;
                UniqueHandle hOwnerProcess(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ownerPid),
                                           &::CloseHandle);

                if (!hOwnerProcess.get())
                {
                    DWORD lastError = GetLastError();
                    if (lastError == ERROR_ACCESS_DENIED)
                    {
                        ++openProcDeniedCount;  // 常见且预期，不单独记录日志
                    }
                    else if (lastError == ERROR_INVALID_PARAMETER || lastError == ERROR_INVALID_HANDLE)
                    {
                        ++openProcInvalidCount;  // 常见且预期，不单独记录日志
                    }
                    else
                    {
                        ++openProcOtherFailCount;
                        LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                                      "ProcessHandleSensor: 无法打开进程进行句柄验证 PID %lu，错误: 0x%08X", ownerPid,
                                      lastError);
                        RecordFailure(anti_cheat::PROCESS_HANDLE_OPEN_PROCESS_FAILED);
                    }
                    continue;
                }

                // 获取进程路径
                ownerProcessPath = Utils::GetProcessFullName(hOwnerProcess.get());
                if (ownerProcessPath.empty())
                {
                    LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "ProcessHandleSensor: 无法获取进程路径 PID %lu",
                                  ownerPid);
                    // 无法获取进程路径本身就是可疑行为，作为证据上报
                    context.AddEvidence(
                            anti_cheat::INTEGRITY_SUSPICIOUS_HANDLE,
                            "一个无法识别路径的进程持有我们进程的句柄 (PID: " + std::to_string(ownerPid) + ")");
                    continue;
                }

                // 智能缓存：使用路径作为键（单次扫描）
                auto pathCacheIt = pathCache.find(ownerProcessPath);
                if (pathCacheIt != pathCache.end())
                {
                    // 检查缓存是否过期
                    auto cacheAge = now - pathCacheIt->second.cached_at;
                    auto cacheDuration =
                            std::chrono::minutes(CheatConfigManager::GetInstance().GetProcessCacheDurationMinutes());

                    if (cacheAge < cacheDuration)
                    {
                        // 检查进程状态是否变化
                        uint32_t currentCreationTime = GetProcessCreationTime(ownerPid);
                        if (currentCreationTime == 0)
                        {
                            // GetProcessCreationTime失败，记录失败原因
                            RecordFailure(anti_cheat::PROCESS_HANDLE_GET_PROCESS_TIMES_FAILED);
                            // 缓存失效，重新验证
                            pathCache.erase(pathCacheIt);
                            // 继续处理，不中断扫描
                        }
                        else if (currentCreationTime == pathCacheIt->second.process_creation_time)
                        {
                            // 使用缓存结果
                            signatureStatus = pathCacheIt->second.signature_status;
                            lowerProcessName = pathCacheIt->second.process_name;
                        }
                        else
                        {
                            // 进程状态已变，重新验证
                            pathCache.erase(pathCacheIt);
                        }
                    }
                    else
                    {
                        // 缓存过期，清理
                        pathCache.erase(pathCacheIt);
                    }
                }

                // 如果缓存未命中，进行完整验证
                if (signatureStatus == Utils::SignatureStatus::UNKNOWN)
                {
                    lowerProcessName = std::filesystem::path(ownerProcessPath).filename().wstring();
                    std::transform(lowerProcessName.begin(), lowerProcessName.end(), lowerProcessName.begin(),
                                   ::towlower);

                    // 白名单或系统目录：直接视为可信，无需签名验证
                    const auto &knownGoodProcesses = CheatConfigManager::GetInstance().GetKnownGoodProcesses();
                    if (knownGoodProcesses->count(lowerProcessName) > 0 || isSystemDirPath(ownerProcessPath))
                    {
                        signatureStatus = Utils::SignatureStatus::TRUSTED;
                    }
                    else
                    {
                        // 跨扫描缓存 + 节流（避免频繁 WinVerifyTrust）
                        const auto ttl = std::chrono::minutes(
                                CheatConfigManager::GetInstance().GetSignatureCacheDurationMinutes());
                        auto thrIt = processSigThrottleUntil.find(ownerProcessPath);
                        if (thrIt != processSigThrottleUntil.end() && now < thrIt->second)
                        {
                            // 节流期内，维持UNKNOWN，稍后会被视为FAILED_TO_VERIFY跳过
                            signatureStatus = Utils::SignatureStatus::FAILED_TO_VERIFY;
                        }
                        else
                        {
                            auto it = processSigCache.find(ownerProcessPath);
                            bool cacheHit = (it != processSigCache.end()) && (now < it->second.second + ttl);
                            if (cacheHit)
                            {
                                signatureStatus = it->second.first;
                            }
                            else
                            {
                                signatureStatus =
                                        Utils::VerifyFileSignature(ownerProcessPath, context.GetWindowsVersion());
                                if (signatureStatus == Utils::SignatureStatus::FAILED_TO_VERIFY)
                                {
                                    processSigThrottleUntil[ownerProcessPath] =
                                            now + std::chrono::milliseconds(
                                                          CheatConfigManager::GetInstance()
                                                                  .GetSignatureVerificationFailureThrottleMs());
                                }
                                else
                                {
                                    processSigCache[ownerProcessPath] = {signatureStatus, now};
                                    processSigThrottleUntil.erase(ownerProcessPath);
                                }
                            }
                        }
                    }

                    // 更新智能缓存
                    PathCacheEntry cacheEntry;
                    cacheEntry.verdict = (signatureStatus == Utils::SignatureStatus::TRUSTED)
                                                 ? CheatMonitor::Pimpl::ProcessVerdict::SIGNED_AND_TRUSTED
                                                 : CheatMonitor::Pimpl::ProcessVerdict::UNSIGNED_OR_UNTRUSTED;
                    cacheEntry.cached_at = now;
                    uint32_t creationTime = GetProcessCreationTime(ownerPid);
                    if (creationTime == 0)
                    {
                        // GetProcessCreationTime失败，记录失败原因
                        RecordFailure(anti_cheat::PROCESS_HANDLE_GET_PROCESS_TIMES_FAILED);
                        creationTime = 0;  // 使用0作为默认值
                        // 继续处理，不中断扫描
                    }
                    cacheEntry.process_creation_time = creationTime;
                    cacheEntry.process_name = lowerProcessName;
                    cacheEntry.signature_status = signatureStatus;

                    pathCache[ownerProcessPath] = cacheEntry;
                }

                // 判断结果
                const auto &knownGoodProcesses = CheatConfigManager::GetInstance().GetKnownGoodProcesses();
                CheatMonitor::Pimpl::ProcessVerdict currentVerdict;

                if (knownGoodProcesses->count(lowerProcessName) > 0 &&
                    signatureStatus == Utils::SignatureStatus::TRUSTED)
                {
                    currentVerdict = CheatMonitor::Pimpl::ProcessVerdict::SIGNED_AND_TRUSTED;
                }
                else if (signatureStatus == Utils::SignatureStatus::TRUSTED)
                {
                    currentVerdict = CheatMonitor::Pimpl::ProcessVerdict::SIGNED_AND_TRUSTED;
                }
                else if (signatureStatus == Utils::SignatureStatus::FAILED_TO_VERIFY)
                {
                    // 验证失败（离线/链信息缺失等）不作为可疑证据，仅跳过
                    continue;
                }
                else
                {
                    currentVerdict = CheatMonitor::Pimpl::ProcessVerdict::UNSIGNED_OR_UNTRUSTED;
                    context.AddEvidence(anti_cheat::INTEGRITY_SUSPICIOUS_HANDLE,
                                        "可疑进程持有我们进程的句柄: " + Utils::WideToString(ownerProcessPath) +
                                                " (PID: " + std::to_string(ownerPid) + ")");
                }
            }
        }
        else
        {
            for (ULONG step = 0; step < (ULONG)total; ++step)
            {
                ULONG i = (ULONG)((cursorStart + step) % total);
                if (step % 200 == 0)
                {
                    auto currentTime = std::chrono::steady_clock::now();
                    auto elapsed_ms =
                            std::chrono::duration_cast<std::chrono::milliseconds>(currentTime - startTime).count();
                    if (elapsed_ms > budget_ms)
                    {
                        LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                                      "ProcessHandleSensor: 扫描超时，已处理 %lu/%lu 个句柄，耗时%ldms",
                                      handlesProcessed, (ULONG)total, elapsed_ms);
                        this->RecordFailure(anti_cheat::PROCESS_HANDLE_SCAN_TIMEOUT);
                        context.SetHandleCursorOffset(cursorStart + entriesVisited);
                        return SensorExecutionResult::FAILURE;
                    }
                }

                const SYSTEM_HANDLE_TABLE_ENTRY_INFO &handle =
                        ((const SYSTEM_HANDLE_TABLE_ENTRY_INFO *)((const BYTE *)pHandleInfoLegacy + sizeof(ULONG)))[i];
                DWORD ownerPid = static_cast<DWORD>(handle.UniqueProcessId);
                if (ownerPid == ownPid || processedPidsThisScan.count(ownerPid) > 0 ||
                    !(handle.GrantedAccess &
                      (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_ALL_ACCESS)))
                {
                    entriesVisited++;
                    continue;
                }

                // 跨扫描节流与限额
                const auto pidIt2 = pidTtlMap.find(ownerPid);
                if (pidIt2 != pidTtlMap.end() && now < pidIt2->second)
                {
                    entriesVisited++;
                    continue;
                }
                if (pidAttempts >= maxPidAttempts)
                {
                    context.SetHandleCursorOffset(cursorStart + entriesVisited);
                    break;
                }
                pidAttempts++;

                if (!IsHandlePointingToUs_SafeLegacy((const void *)&handle, ownPid))
                {
                    pidTtlMap[ownerPid] =
                            now + std::chrono::minutes(CheatConfigManager::GetInstance().GetPidThrottleMinutes());
                    entriesVisited++;
                    continue;
                }

                processedPidsThisScan.insert(ownerPid);
                handlesProcessed++;
                pidTtlMap[ownerPid] =
                        now + std::chrono::minutes(CheatConfigManager::GetInstance().GetPidThrottleMinutes());
                entriesVisited++;

                std::wstring ownerProcessPath;
                std::wstring lowerProcessName;
                Utils::SignatureStatus signatureStatus = Utils::SignatureStatus::UNKNOWN;

                using UniqueHandle = std::unique_ptr<void, decltype(&::CloseHandle)>;
                UniqueHandle hOwnerProcess(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ownerPid),
                                           &::CloseHandle);
                if (!hOwnerProcess.get())
                {
                    DWORD lastError = GetLastError();
                    if (lastError == ERROR_ACCESS_DENIED)
                    {
                        ++openProcDeniedCount;
                    }
                    else if (lastError == ERROR_INVALID_PARAMETER || lastError == ERROR_INVALID_HANDLE)
                    {
                        ++openProcInvalidCount;
                    }
                    else
                    {
                        ++openProcOtherFailCount;
                        LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                                      "ProcessHandleSensor: 无法打开进程进行句柄验证 PID %lu，错误: 0x%08X", ownerPid,
                                      lastError);
                        RecordFailure(anti_cheat::PROCESS_HANDLE_OPEN_PROCESS_FAILED);
                    }
                    continue;
                }

                ownerProcessPath = Utils::GetProcessFullName(hOwnerProcess.get());
                if (ownerProcessPath.empty())
                {
                    LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "ProcessHandleSensor: 无法获取进程路径 PID %lu",
                                  ownerPid);
                    context.AddEvidence(
                            anti_cheat::INTEGRITY_SUSPICIOUS_HANDLE,
                            "一个无法识别路径的进程持有我们进程的句柄 (PID: " + std::to_string(ownerPid) + ")");
                    continue;
                }

                auto pathCacheIt = pathCache.find(ownerProcessPath);
                if (pathCacheIt != pathCache.end())
                {
                    auto cacheAge = now - pathCacheIt->second.cached_at;
                    auto cacheDuration =
                            std::chrono::minutes(CheatConfigManager::GetInstance().GetProcessCacheDurationMinutes());

                    if (cacheAge < cacheDuration)
                    {
                        uint32_t currentCreationTime = GetProcessCreationTime(ownerPid);
                        if (currentCreationTime == 0)
                        {
                            RecordFailure(anti_cheat::PROCESS_HANDLE_GET_PROCESS_TIMES_FAILED);
                            pathCache.erase(pathCacheIt);
                        }
                        else if (currentCreationTime == pathCacheIt->second.process_creation_time)
                        {
                            signatureStatus = pathCacheIt->second.signature_status;
                            lowerProcessName = pathCacheIt->second.process_name;
                        }
                        else
                        {
                            pathCache.erase(pathCacheIt);
                        }
                    }
                    else
                    {
                        pathCache.erase(pathCacheIt);
                    }
                }

                if (signatureStatus == Utils::SignatureStatus::UNKNOWN)
                {
                    lowerProcessName = std::filesystem::path(ownerProcessPath).filename().wstring();
                    std::transform(lowerProcessName.begin(), lowerProcessName.end(), lowerProcessName.begin(),
                                   ::towlower);

                    const auto &knownGoodProcesses = CheatConfigManager::GetInstance().GetKnownGoodProcesses();
                    if (knownGoodProcesses->count(lowerProcessName) > 0 || isSystemDirPath(ownerProcessPath))
                    {
                        signatureStatus = Utils::SignatureStatus::TRUSTED;
                    }
                    else
                    {
                        const auto ttl = std::chrono::minutes(
                                CheatConfigManager::GetInstance().GetSignatureCacheDurationMinutes());
                        auto &procCache = context.GetProcessSigCache();
                        auto &procThr = context.GetProcessSigThrottleUntil();
                        auto thrIt = procThr.find(ownerProcessPath);
                        if (thrIt != procThr.end() && now < thrIt->second)
                        {
                            signatureStatus = Utils::SignatureStatus::FAILED_TO_VERIFY;
                        }
                        else
                        {
                            auto it = procCache.find(ownerProcessPath);
                            bool cacheHit = (it != procCache.end()) && (now < it->second.second + ttl);
                            if (cacheHit)
                            {
                                signatureStatus = it->second.first;
                            }
                            else
                            {
                                signatureStatus =
                                        Utils::VerifyFileSignature(ownerProcessPath, context.GetWindowsVersion());
                                if (signatureStatus == Utils::SignatureStatus::FAILED_TO_VERIFY)
                                {
                                    procThr[ownerProcessPath] =
                                            now + std::chrono::milliseconds(
                                                          CheatConfigManager::GetInstance()
                                                                  .GetSignatureVerificationFailureThrottleMs());
                                }
                                else
                                {
                                    procCache[ownerProcessPath] = {signatureStatus, now};
                                    procThr.erase(ownerProcessPath);
                                }
                            }
                        }
                    }

                    PathCacheEntry cacheEntry;
                    cacheEntry.verdict = (signatureStatus == Utils::SignatureStatus::TRUSTED)
                                                 ? CheatMonitor::Pimpl::ProcessVerdict::SIGNED_AND_TRUSTED
                                                 : CheatMonitor::Pimpl::ProcessVerdict::UNSIGNED_OR_UNTRUSTED;
                    cacheEntry.cached_at = now;
                    uint32_t creationTime = GetProcessCreationTime(ownerPid);
                    if (creationTime == 0)
                    {
                        RecordFailure(anti_cheat::PROCESS_HANDLE_GET_PROCESS_TIMES_FAILED);
                        creationTime = 0;
                    }
                    cacheEntry.process_creation_time = creationTime;
                    cacheEntry.process_name = lowerProcessName;
                    cacheEntry.signature_status = signatureStatus;
                    pathCache[ownerProcessPath] = cacheEntry;
                }

                const auto &knownGoodProcesses = CheatConfigManager::GetInstance().GetKnownGoodProcesses();
                CheatMonitor::Pimpl::ProcessVerdict currentVerdict;
                if (knownGoodProcesses->count(lowerProcessName) > 0 &&
                    signatureStatus == Utils::SignatureStatus::TRUSTED)
                {
                    currentVerdict = CheatMonitor::Pimpl::ProcessVerdict::SIGNED_AND_TRUSTED;
                }
                else if (signatureStatus == Utils::SignatureStatus::TRUSTED)
                {
                    currentVerdict = CheatMonitor::Pimpl::ProcessVerdict::SIGNED_AND_TRUSTED;
                }
                else if (signatureStatus == Utils::SignatureStatus::FAILED_TO_VERIFY)
                {
                    // 验证失败（离线/链信息缺失等）不作为可疑证据，仅跳过
                    continue;
                }
                else
                {
                    currentVerdict = CheatMonitor::Pimpl::ProcessVerdict::UNSIGNED_OR_UNTRUSTED;
                    context.AddEvidence(anti_cheat::INTEGRITY_SUSPICIOUS_HANDLE,
                                        "可疑进程持有我们进程的句柄: " + Utils::WideToString(ownerProcessPath) +
                                                " (PID: " + std::to_string(ownerPid) + ")");
                }
            }
        }

        // 更新游标（正常结束）
        context.SetHandleCursorOffset(cursorStart + entriesVisited);

        // 9. 记录单次扫描性能指标
        auto endTime = std::chrono::steady_clock::now();
        auto scanDuration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();

        LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                    "ProcessHandleSensor: 扫描完成，处理 %lu/%lu 个命中进程/系统句柄，耗时 %lldms; OpenProcess统计 -> "
                    "拒绝: %lu, 参数/句柄无效: %lu, 其他失败: %lu; 本轮尝试PID: %d, 访问条目: %llu",
                    handlesProcessed, (ULONG)totalHandles, scanDuration, openProcDeniedCount, openProcInvalidCount,
                    openProcOtherFailCount, pidAttempts, (unsigned long long)entriesVisited);

        // Telemetry: 记录本轮快照与处理量
        context.RecordSensorWorkloadCounters("ProcessHandleSensor", (uint64_t)totalHandles, (uint64_t)pidAttempts,
                                             (uint64_t)handlesProcessed);

        // 根据统计数据判断执行结果
        // 注意：如果检测到作弊（AddEvidence），即使有系统级失败也应该返回SUCCESS
        if (m_lastFailureReason != anti_cheat::UNKNOWN_FAILURE)
        {
            return SensorExecutionResult::FAILURE;
        }

        return SensorExecutionResult::SUCCESS;
    }

   private:
    bool IsHandlePointingToUs_SafeLegacy(const void *handle, DWORD ownPid)
    {
        DWORD ownerPid = static_cast<DWORD>(((const SYSTEM_HANDLE_TABLE_ENTRY_INFO *)handle)->UniqueProcessId);
        HANDLE hOwnerProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, ownerPid);
        if (!hOwnerProcess)
        {
            return false;
        }

        HANDLE hDup = nullptr;
        BOOL success = DuplicateHandle(hOwnerProcess,
                                       (HANDLE)(uintptr_t)((const SYSTEM_HANDLE_TABLE_ENTRY_INFO *)handle)->HandleValue,
                                       GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS);
        CloseHandle(hOwnerProcess);
        if (!success || hDup == nullptr)
        {
            return false;
        }

        DWORD dupPid = GetProcessId(hDup);
        if (dupPid == 0)
        {
            CloseHandle(hDup);
            return false;
        }

        bool pointsToUs = (dupPid == ownPid);
        CloseHandle(hDup);
        return pointsToUs;
    }
    bool IsHandlePointingToUs_Safe(const void *handle, DWORD ownPid)
    {
        DWORD ownerPid = static_cast<DWORD>(((const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX *)handle)->UniqueProcessId);
        HANDLE hOwnerProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, ownerPid);
        if (!hOwnerProcess)
        {
            // 无法打开进程，跳过
            return false;
        }

        HANDLE hDup = nullptr;
        BOOL success = DuplicateHandle(
                hOwnerProcess, (HANDLE)(uintptr_t)((const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX *)handle)->HandleValue,
                GetCurrentProcess(), &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS);

        CloseHandle(hOwnerProcess);

        if (!success || hDup == nullptr)
        {
            // DuplicateHandle失败
            return false;
        }

        DWORD dupPid = GetProcessId(hDup);
        if (dupPid == 0)
        {
            CloseHandle(hDup);
            return false;
        }

        bool pointsToUs = (dupPid == ownPid);

        CloseHandle(hDup);

        return pointsToUs;
    }
};

class ThreadAndModuleActivitySensor : public ISensor
{
   public:
    const char *GetName() const override
    {
        return "ThreadAndModuleActivitySensor";
    }
    SensorWeight GetWeight() const override
    {
        return SensorWeight::HEAVY;  // 10-100ms: 线程和模块活动监控
    }

    SensorExecutionResult Execute(ScanContext &context) override
    {
        // 重置失败原因
        m_lastFailureReason = anti_cheat::UNKNOWN_FAILURE;

        // 策略1：配置版本门控 - 检查当前OS版本是否满足配置的最低要求
        if (!IsOsSupported(context))
        {
            LOG_DEBUG(AntiCheatLogger::LogCategory::SENSOR, "线程和模块活动监控检测已禁用：当前OS版本低于配置最低要求");
            RecordFailure(anti_cheat::THREAD_MODULE_OS_VERSION_UNSUPPORTED);
            return SensorExecutionResult::FAILURE;
        }

        // 获取超时预算
        const int budget_ms = CheatConfigManager::GetInstance().GetHeavyScanBudgetMs();
        const auto startTime = std::chrono::steady_clock::now();

        // 1. 检查系统API可用性（这是系统级别的检查）
        if (!SystemUtils::g_pNtQueryInformationThread)
        {
            LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "ThreadAndModuleActivitySensor: 系统API不可用");
            RecordFailure(anti_cheat::THREAD_MODULE_SYSTEM_API_FAILED);
            return SensorExecutionResult::FAILURE;
        }

        // 2. 扫描线程（新活动检测 + 完整性检测）
        if (!ScanThreadsWithTimeout(context, budget_ms, startTime))
        {
            // 失败原因已经在ScanThreadsWithTimeout中记录
            return SensorExecutionResult::FAILURE;
        }

        // 3. 扫描模块（新活动检测）
        if (!ScanModulesWithTimeout(context, budget_ms, startTime))
        {
            // 失败原因已经在ScanModulesWithTimeout中记录
            return SensorExecutionResult::FAILURE;
        }

        // 统一的执行结果判断逻辑
        // 成功条件：没有失败原因记录（包括超时）
        if (m_lastFailureReason != anti_cheat::UNKNOWN_FAILURE)
        {
            return SensorExecutionResult::FAILURE;
        }

        return SensorExecutionResult::SUCCESS;
    }

   private:
    bool ScanThreadsWithTimeout(ScanContext &context, int budget_ms,
                                const std::chrono::steady_clock::time_point &startTime)
    {
        int threadCount = 0;
        bool hasSystemFailure = false;
        bool timeoutOccurred = false;

        // 获取当前进程ID，检查失败
        DWORD currentPid = GetCurrentProcessId();
        if (currentPid == 0)
        {
            LOG_ERROR(AntiCheatLogger::LogCategory::SENSOR, "ThreadAndModuleActivitySensor: GetCurrentProcessId失败");
            RecordFailure(anti_cheat::THREAD_MODULE_GET_PROCESS_ID_FAILED);
            return false;
        }

        // 使用公共扫描器枚举线程
        ThreadScanner::EnumerateThreads(
                [&](DWORD threadId) {
                    // 优化：每25个线程检查一次超时，因为线程检查较重
                    if (threadCount % 25 == 0)
                    {
                        auto now = std::chrono::steady_clock::now();
                        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count() > budget_ms)
                        {
                            LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR,
                                        "ThreadAndModuleActivitySensor: 线程扫描超时");
                            RecordFailure(anti_cheat::THREAD_SCAN_TIMEOUT);
                            timeoutOccurred = true;
                            return;
                        }
                    }
                    threadCount++;

                    // 检查是否为新线程
                    bool isNewThread = context.InsertKnownThreadId(threadId);
                    if (isNewThread)
                    {
                        // 新线程检测：分析起始地址
                        AnalyzeNewThread(context, threadId);
                    }

                    // 完整性检测：对所有线程进行深度分析
                    AnalyzeThreadIntegrity(context, threadId);
                },
                currentPid);

        // 如果发生超时，直接返回失败
        if (timeoutOccurred)
        {
            return false;
        }

        // 检查是否有系统级失败（线程扫描失败）
        if (context.GetKnownThreadIds().empty())
        {
            // 检查是否是系统级失败（CreateToolhelp32Snapshot失败）
            HANDLE hTest = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (hTest == INVALID_HANDLE_VALUE)
            {
                LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "ThreadAndModuleActivitySensor: 线程快照创建失败");
                RecordFailure(anti_cheat::THREAD_MODULE_CREATE_SNAPSHOT_FAILED);
                hasSystemFailure = true;
            }
            else
            {
                CloseHandle(hTest);
                // 如果没有线程但快照成功，说明线程扫描失败
                RecordFailure(anti_cheat::THREAD_MODULE_THREAD_SCAN_FAILED);
                hasSystemFailure = true;
            }
        }

        return !hasSystemFailure;
    }

    void AnalyzeNewThread(ScanContext &context, DWORD threadId)
    {
        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
        if (hThread)
        {
            auto thread_closer = [](HANDLE h) { CloseHandle(h); };
            std::unique_ptr<void, decltype(thread_closer)> thread_handle(hThread, thread_closer);

            PVOID startAddress = nullptr;

            // 检查NT API是否可用
            if (!SystemUtils::g_pNtQueryInformationThread)
            {
                // API不可用，这是正常情况，不记录失败
                LOG_DEBUG(AntiCheatLogger::LogCategory::SENSOR,
                          "NtQueryInformationThread API不可用，跳过线程起始地址检测");
                return;
            }

            // 尝试查询线程起始地址
            NTSTATUS status =
                    SystemUtils::g_pNtQueryInformationThread(hThread,
                                                             (THREADINFOCLASS)9,  // ThreadQuerySetWin32StartAddress
                                                             &startAddress, sizeof(startAddress), nullptr);

            if (NT_SUCCESS(status))
            {
                if (startAddress)
                {
                    std::wstring modulePath;
                    if (!context.IsAddressInLegitimateModule(startAddress, modulePath))
                    {
                        std::ostringstream oss;
                        oss << "检测到新线程 (TID: " << threadId << ") 的起始地址 (0x" << std::hex << startAddress
                            << ") 不在任何已知模块中，疑似Shellcode。";
                        context.AddEvidence(anti_cheat::RUNTIME_THREAD_NEW_UNKNOWN, oss.str());
                    }
                }
            }
            else
            {
                // 只有在真正的API错误时才记录失败，某些NTSTATUS值是正常情况
                if (status != 0xC000000D && status != 0xC0000022)  // STATUS_INVALID_PARAMETER, STATUS_ACCESS_DENIED
                {
                    LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                                  "NtQueryInformationThread失败: NTSTATUS=0x%08X, TID=%lu", status, threadId);
                    RecordFailure(anti_cheat::THREAD_MODULE_QUERY_THREAD_FAILED);
                }
                else
                {
                    // 参数无效或访问被拒绝是正常情况，不记录失败
                    LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                                "NtQueryInformationThread返回正常状态: NTSTATUS=0x%08X, TID=%lu", status, threadId);
                }
            }
        }
        else
        {
            // OpenThread失败，但检测到新线程本身就算检测成功
            // 注意：不统计为m_openThreadFailures，因为检测到新线程就算成功
            context.AddEvidence(anti_cheat::RUNTIME_THREAD_NEW_UNKNOWN,
                                "检测到新线程 (TID: " + std::to_string(threadId) + "), 无法获取其起始地址。");
        }
    }

    void AnalyzeThreadIntegrity(ScanContext &context, DWORD threadId)
    {
        // API可用性检查
        if (!SystemUtils::g_pNtQueryInformationThread)
        {
            return;  // 静默跳过，不记录错误
        }

        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
        if (!hThread)
        {
            // OpenThread失败，但这是正常的系统限制，不算检测失败
            // 注意：不统计为m_openThreadFailures，因为这是正常的系统行为
            return;
        }

        auto thread_closer = [](HANDLE h) { CloseHandle(h); };
        std::unique_ptr<void, decltype(thread_closer)> thread_handle(hThread, thread_closer);

        // 检查线程起始地址
        PVOID startAddress = nullptr;
        NTSTATUS qsaStatus = SystemUtils::g_pNtQueryInformationThread(
                hThread, (THREADINFOCLASS)9,  // ThreadQuerySetWin32StartAddress
                &startAddress, sizeof(startAddress), nullptr);
        if (NT_SUCCESS(qsaStatus))
        {
            if (startAddress)
            {
                std::wstring modulePath;
                if (!context.IsAddressInLegitimateModule(startAddress, modulePath))
                {
                    std::ostringstream oss;
                    oss << "检测到线程(TID: " << threadId << ") 的起始地址 (0x" << std::hex << startAddress
                        << ") 不在任何已知模块中，疑似Shellcode。";
                    context.AddEvidence(anti_cheat::RUNTIME_THREAD_NEW_UNKNOWN, oss.str());
                }
            }
        }
        else
        {
            // 对常见可容忍状态不记失败
            if (qsaStatus != 0xC000000D &&  // STATUS_INVALID_PARAMETER
                qsaStatus != 0xC0000022 &&  // STATUS_ACCESS_DENIED
                qsaStatus != 0xC0000003 &&  // STATUS_INVALID_INFO_CLASS
                qsaStatus != 0xC0000002 &&  // STATUS_NOT_IMPLEMENTED
                qsaStatus != 0xC0000004)    // STATUS_INFO_LENGTH_MISMATCH（长度不匹配，部分系统正常）
            {
                RecordFailure(anti_cheat::THREAD_MODULE_QUERY_THREAD_FAILED);
                LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                            "NtQueryInformationThread(start) 失败且计为失败: NTSTATUS=0x%08X, TID=%lu", qsaStatus,
                            threadId);
            }
            else
            {
                LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                            "NtQueryInformationThread(start) 返回可容忍状态: NTSTATUS=0x%08X, TID=%lu", qsaStatus,
                            threadId);
            }
        }

        // 检查线程是否隐藏调试器
        ULONG isHidden = 0;
        NTSTATUS hideStatus =
                SystemUtils::g_pNtQueryInformationThread(hThread, (THREADINFOCLASS)17,  // ThreadHideFromDebugger
                                                         &isHidden, sizeof(isHidden), nullptr);
        if (NT_SUCCESS(hideStatus))
        {
            if (isHidden)
            {
                std::ostringstream oss;
                oss << "检测到线程(TID: " << threadId << ") 被设置为对调试器隐藏。";
                context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, oss.str());
            }
        }
        else
        {
            if (hideStatus != 0xC000000D &&  // STATUS_INVALID_PARAMETER
                hideStatus != 0xC0000022 &&  // STATUS_ACCESS_DENIED
                hideStatus != 0xC0000003 &&  // STATUS_INVALID_INFO_CLASS
                hideStatus != 0xC0000002 &&  // STATUS_NOT_IMPLEMENTED
                hideStatus != 0xC0000004)    // STATUS_INFO_LENGTH_MISMATCH（长度不匹配，部分系统正常）
            {
                RecordFailure(anti_cheat::THREAD_MODULE_QUERY_THREAD_FAILED);
                LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                            "NtQueryInformationThread(hide) 失败且计为失败: NTSTATUS=0x%08X, TID=%lu", hideStatus,
                            threadId);
            }
            else
            {
                LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                            "NtQueryInformationThread(hide) 返回可容忍状态: NTSTATUS=0x%08X, TID=%lu", hideStatus,
                            threadId);
            }
        }
    }

    bool ScanModulesWithTimeout(ScanContext &context, int budget_ms,
                                const std::chrono::steady_clock::time_point &startTime)
    {
        int moduleCount = 0;
        bool hasSystemFailure = false;
        bool timeoutOccurred = false;

        // 使用公共扫描器枚举模块
        ModuleScanner::EnumerateModules([&](HMODULE hModule) {
            // 优化：每15个模块检查一次超时，因为模块检查中等重量
            if (moduleCount % 15 == 0)
            {
                auto now = std::chrono::steady_clock::now();
                if (std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count() > budget_ms)
                {
                    LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "ThreadAndModuleActivitySensor: 模块扫描超时");
                    RecordFailure(anti_cheat::MODULE_SCAN_TIMEOUT);
                    timeoutOccurred = true;
                    return;
                }
            }
            moduleCount++;

            if (context.InsertKnownModule(hModule))
            {
                // New module detected, verify its signature
                context.VerifyModuleSignature(hModule);
            }
        });

        // 如果发生超时，直接返回失败
        if (timeoutOccurred)
        {
            return false;
        }

        // 检查是否有系统级失败（模块扫描失败）
        if (context.GetKnownModules().empty())
        {
            // 检查是否是系统级失败（EnumProcessModules失败）
            std::vector<HMODULE> hMods(1);
            DWORD cbNeeded = 0;
            if (!EnumProcessModules(GetCurrentProcess(), hMods.data(), hMods.size() * sizeof(HMODULE), &cbNeeded))
            {
                LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "ThreadAndModuleActivitySensor: 模块枚举失败");
                RecordFailure(anti_cheat::THREAD_MODULE_OPEN_MODULE_FAILED);
                hasSystemFailure = true;
            }
            else
            {
                // 如果没有模块但枚举成功，说明模块扫描失败
                RecordFailure(anti_cheat::THREAD_MODULE_MODULE_SCAN_FAILED);
                hasSystemFailure = true;
            }
        }

        return !hasSystemFailure;
    }
};

class MemorySecuritySensor : public ISensor
{
   public:
    const char *GetName() const override
    {
        return "MemorySecuritySensor";
    }
    SensorWeight GetWeight() const override
    {
        return SensorWeight::HEAVY;  // 10-100ms: 内存安全检测
    }

    SensorExecutionResult Execute(ScanContext &context) override
    {
        // 重置失败原因
        m_lastFailureReason = anti_cheat::UNKNOWN_FAILURE;

        // 策略1：配置版本门控 - 检查当前OS版本是否满足配置的最低要求
        if (!IsOsSupported(context))
        {
            LOG_DEBUG(AntiCheatLogger::LogCategory::SENSOR, "内存安全检测已禁用：当前OS版本低于配置最低要求");
            RecordFailure(anti_cheat::MEMORY_OS_VERSION_UNSUPPORTED);
            return SensorExecutionResult::FAILURE;
        }

        const int budget_ms = CheatConfigManager::GetInstance().GetHeavyScanBudgetMs();
        const auto startTime = std::chrono::steady_clock::now();

        // 4. 使用公共扫描器进行内存遍历
        bool timeoutOccurred = false;
        MemoryScanner::ScanMemoryRegions([&](const MEMORY_BASIC_INFORMATION &mbi) {
            // 检查超时
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count() > budget_ms)
            {
                LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "MemorySecuritySensor: 内存扫描超时");
                RecordFailure(anti_cheat::MEMORY_SCAN_TIMEOUT);
                timeoutOccurred = true;
                return;
            }

            // 性能优化：跳过已知安全区域
            uintptr_t currentAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            if (IsKnownSafeRegion(currentAddr, mbi.RegionSize))
            {
                return;
            }

            // 核心检测逻辑：专注于内存安全检测，不重复模块完整性检测
            if (mbi.State == MEM_COMMIT)
            {
                // 检测隐藏模块（不在模块列表中的可执行内存）
                if ((mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
                {
                    DetectHiddenModule(context, mbi);
                }

                // 检测私有可执行内存（动态分配的可执行代码）
                if (mbi.Type == MEM_PRIVATE && (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                                               PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
                {
                    DetectPrivateExecutableMemory(context, mbi);
                }
            }
        });

        // 如果发生超时，直接返回失败
        if (timeoutOccurred)
        {
            return SensorExecutionResult::FAILURE;
        }

        // 统一的执行结果判断逻辑
        // 成功条件：没有失败原因记录（包括超时）
        if (m_lastFailureReason != anti_cheat::UNKNOWN_FAILURE)
        {
            return SensorExecutionResult::FAILURE;
        }

        return SensorExecutionResult::SUCCESS;
    }

   private:
    // 检测隐藏模块
    void DetectHiddenModule(ScanContext &context, const MEMORY_BASIC_INFORMATION &mbi)
    {
        HMODULE hMod = nullptr;
        DWORD lastError = 0;

        // 尝试获取模块句柄，区分真正的API失败和正常的"不属于任何模块"情况
        BOOL result = GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                (LPCWSTR)mbi.BaseAddress, &hMod);

        if (!result)
        {
            lastError = GetLastError();
            // 只有在真正的API错误时才记录失败，以下错误码是正常情况：
            // ERROR_INVALID_ADDRESS (487) - 地址无效
            // ERROR_MOD_NOT_FOUND (126) - 找不到模块（地址不属于任何已加载模块）
            if (lastError != ERROR_INVALID_ADDRESS && lastError != ERROR_MOD_NOT_FOUND)
            {
                LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "GetModuleHandleExW失败: 错误码=%lu, 地址=0x%p",
                              lastError, mbi.BaseAddress);
                RecordFailure(anti_cheat::MEMORY_GET_MODULE_HANDLE_FAILED);
                return;
            }
            else
            {
                // 记录调试信息，说明这是正常的"地址不属于任何模块"情况
                LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                            "GetModuleHandleExW: 地址0x%p不属于任何已加载模块 (错误码=%lu)，继续检测隐藏模块",
                            mbi.BaseAddress, lastError);
            }
        }

        // 如果GetModuleHandleExW成功，说明地址属于已知模块，不是隐藏模块
        if (result && hMod != nullptr)
        {
            return;  // 地址在已知模块中，跳过检测
        }

        // 地址不属于任何已知模块，继续检测是否为隐藏模块
        uintptr_t baseAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        SIZE_T regionSize = mbi.RegionSize;

        // 使用配置化的检测阈值
        const uint32_t minRegionSize = CheatConfigManager::GetInstance().GetMinMemoryRegionSize();
        const uint32_t maxRegionSize = CheatConfigManager::GetInstance().GetMaxMemoryRegionSize();

        if (baseAddr > 0x10000 && regionSize >= minRegionSize && regionSize <= maxRegionSize)
        {
            auto peCheckResult = CheckHiddenMemoryRegion(mbi.BaseAddress, regionSize);
            if (peCheckResult.shouldReport)
            {
                char msgBuffer[256];
                if (peCheckResult.accessible)
                {
                    sprintf_s(msgBuffer, sizeof(msgBuffer), "检测到隐藏的可执行内存区域: 0x%p 大小: %zu 字节",
                              (void *)baseAddr, regionSize);
                }
                else
                {
                    sprintf_s(msgBuffer, sizeof(msgBuffer),
                              "检测到隐藏的可执行内存区域（无法读取）: 0x%p 大小: %zu 字节", (void *)baseAddr,
                              regionSize);
                }
                context.AddEvidence(anti_cheat::INTEGRITY_MEMORY_PATCH, std::string(msgBuffer));
            }
        }
    }

    // 检测私有可执行内存
    void DetectPrivateExecutableMemory(ScanContext &context, const MEMORY_BASIC_INFORMATION &mbi)
    {
        // 使用配置化的检测阈值
        const uint32_t minRegionSize = CheatConfigManager::GetInstance().GetMinMemoryRegionSize();
        const uint32_t maxRegionSize = CheatConfigManager::GetInstance().GetMaxMemoryRegionSize();

        // 降噪：仅对RWX（或WRITECOPY执行）页面直接上报；
        // 对仅RX的小页（例如JIT/系统stub的正常情况）提高阈值，避免误报。
        const bool isRWX = (mbi.Protect & PAGE_EXECUTE_READWRITE) || (mbi.Protect & PAGE_EXECUTE_WRITECOPY);
        const bool isRXOnly = (mbi.Protect & PAGE_EXECUTE_READ) && !isRWX;

        // 若仅RX且区域较小（< 128KB），认为常见且低风险，忽略
        const SIZE_T rxSmallThreshold = 128 * 1024;

        if (mbi.RegionSize >= minRegionSize && mbi.RegionSize <= maxRegionSize)
        {
            if (!context.IsAddressInLegitimateModule(mbi.BaseAddress))
            {
                if (isRXOnly && mbi.RegionSize < rxSmallThreshold)
                {
                    return;  // 降噪：跳过常见的小型RX私有页
                }
                std::ostringstream oss;
                oss << "检测到私有可执行内存. 地址: 0x" << std::hex << reinterpret_cast<uintptr_t>(mbi.BaseAddress)
                    << ", 大小: " << std::dec << mbi.RegionSize << " 字节.";

                context.AddEvidence(anti_cheat::RUNTIME_MEMORY_EXEC_PRIVATE, oss.str());
                // 私有可执行内存检测完成
            }
        }
    }

    // 性能优化：智能安全区域检测
    static bool IsKnownSafeRegion(uintptr_t baseAddr, SIZE_T regionSize)
    {
        // 跳过系统保留区域
        if (baseAddr < 0x10000)
            return true;  // 64KB以下

        // 跳过大内存池（通常由内存分配器管理）
        if (regionSize > CheatConfigManager::GetInstance().GetMaxMemoryRegionSize())
            return true;  // 超过配置的最大内存区域大小

        // 跳过特定地址范围（根据系统特性调整）
        if (baseAddr >= 0x7FFE0000 && baseAddr < 0x7FFF0000)
            return true;  // 系统保留

        return false;
    }

    struct HiddenMemoryCheckResult
    {
        bool shouldReport = false;
        bool accessible = false;
    };

    static HiddenMemoryCheckResult CheckHiddenMemoryRegion(PVOID baseAddress, SIZE_T regionSize)
    {
        HiddenMemoryCheckResult result;
        __try
        {
            // 简单检查是否可能是PE文件头
            const BYTE *pMem = reinterpret_cast<const BYTE *>(baseAddress);
            bool mightBePE = (regionSize >= CheatConfigManager::GetInstance().GetMinMemoryRegionSize() &&
                              pMem[0] == 'M' && pMem[1] == 'Z');

            result.accessible = true;
            result.shouldReport = mightBePE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            // 如果读取内存失败，仍然报告，因为这很可能是恶意隐藏
            result.accessible = false;
            result.shouldReport = true;
            // 记录内存访问异常失败
            // m_lastFailureReason = anti_cheat::MEMORY_ACCESS_EXCEPTION; // 静态方法中无法访问成员变量
        }
        return result;
    }
};

class VehHookSensor : public ISensor
{
   public:
    const char *GetName() const override
    {
        return "VehHookSensor";
    }
    SensorWeight GetWeight() const override
    {
        return SensorWeight::CRITICAL;  // > 100ms: VEH检测需特殊处理
    }

    SensorExecutionResult Execute(ScanContext &context) override
    {
        // 重置失败原因
        m_lastFailureReason = anti_cheat::UNKNOWN_FAILURE;

        // 策略1：配置版本门控 - 检查当前OS版本是否满足配置的最低要求
        if (!IsOsSupported(context))
        {
            LOG_DEBUG(AntiCheatLogger::LogCategory::SENSOR, "VEH检测已禁用：当前OS版本低于配置最低要求");
            m_lastFailureReason = anti_cheat::VEH_OS_VERSION_UNSUPPORTED;
            return SensorExecutionResult::FAILURE;
        }

        auto winVer = context.GetWindowsVersion();
        // 策略2：版本检查 - 只在已知稳定的版本上运行
        if (winVer == SystemUtils::WindowsVersion::Win_Unknown)
        {
            LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "VEH检测在未知Windows版本上禁用以确保稳定性");
            m_lastFailureReason = anti_cheat::VEH_WINDOWS_VERSION_UNKNOWN;
            return SensorExecutionResult::FAILURE;
        }

        const uintptr_t base = context.GetVehListAddress();
        if (base == 0)
        {
            LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "VEH链表地址获取失败，跳过检测");
            m_lastFailureReason = anti_cheat::VEH_LIST_ADDRESS_FAILED;
            return SensorExecutionResult::FAILURE;
        }

        // 策略3：内存验证 - 确保VEH链表基地址有效
        MEMORY_BASIC_INFORMATION baseMbi = {};
        if (VirtualQuery((PVOID)base, &baseMbi, sizeof(baseMbi)) != sizeof(baseMbi))
        {
            LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "VEH链表基地址内存查询失败");
            RecordFailure(anti_cheat::VEH_VIRTUAL_QUERY_FAILED);
            return SensorExecutionResult::FAILURE;
        }

        if (baseMbi.State != MEM_COMMIT)
        {
            LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "VEH链表基地址内存状态异常: 0x%08X", baseMbi.State);
            RecordFailure(anti_cheat::VEH_MEMORY_STATE_ABNORMAL);
            return SensorExecutionResult::FAILURE;
        }

        const int budget_ms = CheatConfigManager::GetInstance().GetHeavyScanBudgetMs();
        const auto startTime = std::chrono::steady_clock::now();

        LIST_ENTRY *pHead = nullptr;

        // 策略4：结构体访问保护
        auto accessResult = AccessVehStructSafe(base, winVer);
        if (!accessResult.success)
        {
            LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR, "VEH结构体访问异常: 0x%08X", accessResult.exceptionCode);
            RecordFailure(anti_cheat::VEH_LIST_ACCESS_FAILED);
            return SensorExecutionResult::FAILURE;
        }

        pHead = accessResult.pHead;
        if (!pHead || !SystemUtils::IsValidPointer(pHead, sizeof(LIST_ENTRY)))
        {
            LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "VEH链表头指针无效");
            RecordFailure(anti_cheat::VEH_HEAD_POINTER_INVALID);
            return SensorExecutionResult::FAILURE;
        }

        // 策略5：保守的处理器枚举
        std::vector<PVOID> handlers;
        auto traverseResult = TraverseVehListSafe(pHead, budget_ms);
        if (!traverseResult.success)
        {
            if (traverseResult.exceptionCode != 0)
            {
                LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR, "VEH链表遍历异常: 0x%08X",
                            traverseResult.exceptionCode);
                RecordFailure(anti_cheat::VEH_TRAVERSE_FAILED);
            }
            else
            {
                LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "VEH链表遍历超时");
                RecordFailure(anti_cheat::VEH_EXECUTION_TIMEOUT);
            }
            return SensorExecutionResult::FAILURE;
        }

        for (int i = 0; i < traverseResult.handlerCount; ++i)
        {
            handlers.push_back(traverseResult.handlers[i]);
        }

        if (traverseResult.success && !handlers.empty())
        {
            // 策略6：限制检查数量和频率
            const size_t maxHandlers = (size_t)CheatConfigManager::GetInstance().GetMaxVehHandlersToScan();
            const size_t checkCount = std::min(handlers.size(), maxHandlers);

            LOG_INFO_F(AntiCheatLogger::LogCategory::SENSOR, "VEH检测: 发现%zu个处理器，检查前%zu个", handlers.size(),
                       checkCount);

            for (size_t i = 0; i < checkCount; ++i)
            {
                // 每5次循环检查一次时间，因为VEH处理器数量少但检查很重
                if (i % 5 == 0)
                {
                    auto now = std::chrono::steady_clock::now();
                    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count();

                    if (elapsed_ms > budget_ms)
                    {
                        LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                                      "VEH检测超时，已检查%zu/%zu个处理器，耗时%ldms", i, checkCount, elapsed_ms);
                        RecordFailure(anti_cheat::VEH_EXECUTION_TIMEOUT);
                        return SensorExecutionResult::FAILURE;
                    }
                }

                // 使用统一的指针验证接口
                if (!SystemUtils::IsValidPointer(handlers[i], sizeof(VECTORED_HANDLER_ENTRY)))
                {
                    LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR, "VEH处理器#%zu指针验证失败", i);
                    RecordFailure(anti_cheat::VEH_POINTER_VALIDATION_FAILED);  // 统计指针验证失败
                }
                else
                {
                    this->AnalyzeHandlerSecurity(context, handlers[i], (int)i);
                }
            }
        }
        else
        {
            if (traverseResult.success)
            {
                LOG_INFO(AntiCheatLogger::LogCategory::SENSOR, "VEH检测: 未发现处理器");
            }
            // 注意：如果traverseResult.success为false，TraverseVehListSafe方法中已经有相应的LOG记录
        }

        // 统一的执行结果判断逻辑
        // 成功条件：没有失败原因记录（包括超时）
        if (m_lastFailureReason != anti_cheat::UNKNOWN_FAILURE)
        {
            return SensorExecutionResult::FAILURE;
        }

        return SensorExecutionResult::SUCCESS;
    }

   private:
    struct VehAccessResult
    {
        bool success = false;
        LIST_ENTRY *pHead = nullptr;
        DWORD exceptionCode = 0;
    };

    static VehAccessResult AccessVehStructSafe(uintptr_t base, SystemUtils::WindowsVersion winVer)
    {
        VehAccessResult result;
        __try
        {
            switch (winVer)
            {
                case SystemUtils::WindowsVersion::Win_XP: {
                    auto *pList = reinterpret_cast<VECTORED_HANDLER_LIST_XP *>(base);
                    if (SystemUtils::IsValidPointer(pList, sizeof(VECTORED_HANDLER_LIST_XP)))
                    {
                        result.pHead = &pList->List;
                    }
                    break;
                }
                case SystemUtils::WindowsVersion::Win_Vista_Win7: {
                    auto *pList = reinterpret_cast<VECTORED_HANDLER_LIST_VISTA *>(base);
                    if (SystemUtils::IsValidPointer(pList, sizeof(VECTORED_HANDLER_LIST_VISTA)))
                    {
                        result.pHead = &pList->ExceptionList;
                    }
                    break;
                }
                case SystemUtils::WindowsVersion::Win_8_Win81:
                case SystemUtils::WindowsVersion::Win_10:
                case SystemUtils::WindowsVersion::Win_11:
                default: {
                    auto *pList = reinterpret_cast<VECTORED_HANDLER_LIST_WIN8 *>(base);
                    if (SystemUtils::IsValidPointer(pList, sizeof(VECTORED_HANDLER_LIST_WIN8)))
                    {
                        result.pHead = &pList->ExceptionList;
                    }
                    break;
                }
            }
            result.success = true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            result.exceptionCode = GetExceptionCode();
        }
        return result;
    }

    // 合并的VEH链表遍历函数 - 分析：VEH链表遍历通常很快，但为了安全起见保留budget_ms检查
    struct VehTraverseResult
    {
        bool success;
        PVOID handlers[2048];
        int handlerCount;
        DWORD exceptionCode;
    };

    static VehTraverseResult TraverseVehListSafe(LIST_ENTRY *pHead, int budget_ms)
    {
        VehTraverseResult result = {false, {0}, 0, 0};
        __try
        {
            const auto startTime = std::chrono::steady_clock::now();
            LIST_ENTRY *pNode = pHead->Flink;
            int safetyCounter = 0;
            const int kMaxNodes = 2048;

            while (pNode && pNode != pHead && safetyCounter++ < kMaxNodes && result.handlerCount < 2048)
            {
                // 优化：每25次循环检查一次超时，因为安全计数器需要更频繁的检查
                if (safetyCounter % 25 == 0)
                {
                    auto now = std::chrono::steady_clock::now();
                    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count() > budget_ms)
                    {
                        result.success = false;  // 超时视为失败
                        return result;           // Timeout
                    }
                }

                if (!SystemUtils::IsValidPointer(pNode, sizeof(LIST_ENTRY)))
                    break;

                auto *pEntry = CONTAINING_RECORD(pNode, VECTORED_HANDLER_ENTRY, List);
                if (!SystemUtils::IsValidPointer(pEntry, sizeof(VECTORED_HANDLER_ENTRY)))
                    break;

                // 检查Handler是否为空，空的Handler可能是异常情况
                if (pEntry->Handler != nullptr)
                {
                    result.handlers[result.handlerCount++] = pEntry->Handler;
                }
                else
                {
                    // 空的VEH Handler可能是异常情况，记录但继续处理
                    LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "VEH检测: 发现空的Handler，可能是异常情况");
                }

                LIST_ENTRY *pNext = pNode->Flink;
                if (!SystemUtils::IsValidPointer(pNext, sizeof(LIST_ENTRY)))
                    break;
                pNode = pNext;
            }
            result.success = true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            result.success = false;
            result.exceptionCode = GetExceptionCode();
        }
        return result;
    }

    // VEH处理器安全分析
    void AnalyzeHandlerSecurity(ScanContext &context, PVOID handlerAddress, int index)
    {
        if (!handlerAddress)
            return;

        std::wstring modulePath;
        bool isInBaselineModule = context.IsAddressInLegitimateModule(handlerAddress, modulePath);

        if (isInBaselineModule)
        {
            // 地址在基线建立的模块中，进一步验证其是否在代码节内
            // 先检查页面保护，避免读取无效/非执行内存导致访问冲突
            MEMORY_BASIC_INFORMATION mbi = {};
            if (VirtualQuery(handlerAddress, &mbi, sizeof(mbi)) == 0)
            {
                m_lastFailureReason = anti_cheat::VEH_VIRTUAL_QUERY_FAILED;  // 统计VirtualQuery失败
                return;                                                      // 无法查询，保守退出
            }
            const DWORD prot = mbi.Protect & 0xFF;
            const bool isExec = (prot == PAGE_EXECUTE) || (prot == PAGE_EXECUTE_READ) ||
                                (prot == PAGE_EXECUTE_READWRITE) || (prot == PAGE_EXECUTE_WRITECOPY);
            if (!isExec)
            {
                // 非可执行页面中的处理函数极不正常，作为可疑迹象上报
                context.AddEvidence(anti_cheat::INTEGRITY_API_HOOK,
                                    "VEH 处理函数位于非可执行页面，疑似劫持或保护绕过。");
                return;
            }

            HMODULE hModule = NULL;
            if (GetModuleHandleExW(
                        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                        (LPCWSTR)handlerAddress, &hModule) &&
                hModule)
            {
                PVOID codeBase = nullptr;
                DWORD codeSize = 0;
                if (SystemUtils::GetModuleCodeSectionInfo(hModule, codeBase, codeSize))
                {
                    uintptr_t addr = reinterpret_cast<uintptr_t>(handlerAddress);
                    uintptr_t start = reinterpret_cast<uintptr_t>(codeBase);
                    if (addr >= start && addr < (start + codeSize))
                    {
                        return;  // 在基线模块的合法代码节内，安全
                    }
                }
                else
                {
                    // 检查是否为系统保护模块，系统保护模块的GetModuleCodeSectionInfo失败是正常的
                    std::wstring moduleName = modulePath;
                    std::transform(moduleName.begin(), moduleName.end(), moduleName.begin(), ::towlower);

                    bool isSystemProtectedModule = (moduleName.find(L"sfc.dll") != std::wstring::npos) ||
                                                   (moduleName.find(L"sfc_os.dll") != std::wstring::npos) ||
                                                   (moduleName.find(L"wfp.dll") != std::wstring::npos) ||
                                                   (moduleName.find(L"wfpdiag.dll") != std::wstring::npos) ||
                                                   (moduleName.find(L"ntdll.dll") != std::wstring::npos) ||
                                                   (moduleName.find(L"kernel32.dll") != std::wstring::npos) ||
                                                   (moduleName.find(L"kernelbase.dll") != std::wstring::npos) ||
                                                   (moduleName.find(L"user32.dll") != std::wstring::npos) ||
                                                   (moduleName.find(L"gdi32.dll") != std::wstring::npos) ||
                                                   (moduleName.find(L"advapi32.dll") != std::wstring::npos) ||
                                                   (moduleName.find(L"ole32.dll") != std::wstring::npos) ||
                                                   (moduleName.find(L"oleaut32.dll") != std::wstring::npos) ||
                                                   (moduleName.find(L"shell32.dll") != std::wstring::npos) ||
                                                   (moduleName.find(L"comctl32.dll") != std::wstring::npos) ||
                                                   (moduleName.find(L"msvcrt.dll") != std::wstring::npos) ||
                                                   (moduleName.find(L"ucrtbase.dll") != std::wstring::npos);

                    if (isSystemProtectedModule)
                    {
                        // 系统保护模块的GetModuleCodeSectionInfo失败是正常情况，跳过检测
                        LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                                    "VehHookSensor: 系统保护模块代码节获取失败（正常情况）, 模块=%s, 地址=0x%p",
                                    Utils::WideToString(modulePath).c_str(), handlerAddress);
                        return;
                    }
                    else
                    {
                        // 非系统保护模块的GetModuleCodeSectionInfo失败是可疑行为，作为证据上报
                        std::wostringstream woss;
                        woss << L"检测到VEH处理器被劫持到基线模块的非代码区. 模块: "
                             << (modulePath.empty() ? L"未知" : modulePath) << L", 地址: 0x" << std::hex
                             << handlerAddress << L" (GetModuleCodeSectionInfo失败)";
                        context.AddEvidence(anti_cheat::INTEGRITY_API_HOOK, Utils::WideToString(woss.str()));
                        return;
                    }
                }
            }
            else
            {
                // GetModuleHandleExW失败本身就是可疑行为，作为证据上报
                std::wostringstream woss;
                woss << L"检测到VEH处理器被劫持到基线模块的非代码区. 模块: "
                     << (modulePath.empty() ? L"未知" : modulePath) << L", 地址: 0x" << std::hex << handlerAddress
                     << L" (GetModuleHandleExW失败)";
                context.AddEvidence(anti_cheat::INTEGRITY_API_HOOK, Utils::WideToString(woss.str()));
                return;
            }
            // 不在代码节内，或无法获取信息，视为劫持
            std::wostringstream woss;
            woss << L"检测到VEH处理器被劫持到基线模块的非代码区. 模块: " << (modulePath.empty() ? L"未知" : modulePath)
                 << L", 地址: 0x" << std::hex << handlerAddress;
            context.AddEvidence(anti_cheat::INTEGRITY_API_HOOK, Utils::WideToString(woss.str()));
        }
        else
        {
            // 地址不在基线建立的模块中，需要检查是否在白名单中
            auto whitelistedVEHModules = context.GetWhitelistedVEHModules();
            bool isWhitelisted = false;
            // 如果modulePath不为空，说明地址在某个模块中（非基线模块）
            if (!modulePath.empty() && whitelistedVEHModules)
            {
                // 修复：提取文件名进行比对，而不是完整路径
                std::wstring modulePathLower = modulePath;
                std::transform(modulePathLower.begin(), modulePathLower.end(), modulePathLower.begin(), ::towlower);

                // 提取文件名（去除路径）
                size_t lastSlash = modulePathLower.find_last_of(L"\\/");
                std::wstring fileName =
                        (lastSlash != std::wstring::npos) ? modulePathLower.substr(lastSlash + 1) : modulePathLower;

                if (whitelistedVEHModules->count(fileName) > 0)
                {
                    isWhitelisted = true;
                    LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR, "VEH处理器在白名单中: %s (文件名: %s)",
                                Utils::WideToString(modulePath).c_str(), Utils::WideToString(fileName).c_str());
                }
            }

            if (!isWhitelisted)
            {
                std::wostringstream woss;
                if (!modulePath.empty())
                {
                    woss << L"检测到可疑的VEH Hook (Handler #" << index << L"). 来源: " << modulePath << L", 地址: 0x"
                         << std::hex << handlerAddress;
                }
                else
                {
                    woss << L"检测到来自Shellcode的VEH Hook (Handler #" << index << L"). 地址: 0x" << std::hex
                         << handlerAddress;
                }
                context.AddEvidence(anti_cheat::INTEGRITY_API_HOOK, Utils::WideToString(woss.str()));
            }
            else
            {
                // 白名单处理器，不记录到Metrics中
                LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR, "VEH处理器在白名单中，跳过上报: %s",
                            Utils::WideToString(modulePath).c_str());
            }
        }
    }
};

CheatMonitor &CheatMonitor::GetInstance()
{
    static CheatMonitor instance;
    return instance;
}

CheatMonitor::CheatMonitor() : m_pimpl(std::make_unique<Pimpl>())
{
}
CheatMonitor::~CheatMonitor()
{
    Shutdown();
}

bool CheatMonitor::Initialize()
{
    if (!m_pimpl)
        m_pimpl = std::make_unique<Pimpl>();
    if (m_pimpl->m_isSystemActive.load())
        return true;  // 已经初始化成功，直接返回true

    // 先置位运行标志，再启动线程，避免线程读取到旧的false而提前退出
    m_pimpl->m_isSystemActive = true;
    try
    {
        m_pimpl->m_monitorThread = std::thread(&Pimpl::MonitorLoop, m_pimpl.get());
    }
    catch (const std::system_error &e)
    {
        LOG_ERROR_F(AntiCheatLogger::LogCategory::SYSTEM,
                    "Initialize Error: Failed to create monitor thread. Error: %s", e.what());
        return false;
    }

    return true;
}

void CheatMonitor::Shutdown()
{
    if (!m_pimpl || !m_pimpl->m_isSystemActive.load())
        return;

    if (m_pimpl->m_isSessionActive.load())
        OnPlayerLogout();

    // 先发出停止信号，并唤醒监控线程，避免长时间sleep导致关停缓慢
    m_pimpl->m_isSystemActive = false;
    m_pimpl->WakeMonitor();

    if (m_pimpl->m_monitorThread.joinable())
        m_pimpl->m_monitorThread.join();

    // 最后清理Pimpl实例
    m_pimpl.reset();
}

void CheatMonitor::OnPlayerLogin(uint32_t user_id, const std::string &user_name)
{
    if (!m_pimpl || !m_pimpl->m_isSystemActive.load())
        return;

    // 先登出上一个玩家，这会处理上一个会话的报告上传和状态清理
    OnPlayerLogout();

    // 为新玩家重置会话状态
    m_pimpl->ResetSessionState();

    {
        std::lock_guard<std::mutex> lock(m_pimpl->m_sessionMutex);
        m_pimpl->m_currentUserId = user_id;
        m_pimpl->m_currentUserName = user_name;
    }

    m_pimpl->m_hasServerConfig = false;  // 重置配置状态，等待服务器下发
    m_pimpl->m_isSessionActive = true;

    LOG_INFO_F(AntiCheatLogger::LogCategory::SYSTEM, "Player %s logged in. Session started.",
               m_pimpl->m_currentUserName.c_str());

    // 玩家登录时上报硬件信息，确保每个玩家的硬件信息都能统计到
    m_pimpl->UploadHardwareReport();

    // 唤醒监控线程，快速应用新的会话状态
    m_pimpl->WakeMonitor();
}

void CheatMonitor::OnPlayerLogout()
{
    if (!m_pimpl || !m_pimpl->m_isSystemActive.load())
        return;

    m_pimpl->UploadEvidenceReport();
    m_pimpl->UploadSensorExecutionStatsReport();

    if (m_pimpl->m_isSessionActive.load())
    {
        LOG_INFO_F(AntiCheatLogger::LogCategory::SYSTEM, "Player %s logged out. Session ended.",
                   m_pimpl->m_currentUserName.c_str());

        {
            std::lock_guard<std::mutex> lock(m_pimpl->m_sessionMutex);
            m_pimpl->m_currentUserId = 0;        // 清理用户ID
            m_pimpl->m_currentUserName.clear();  // 清理用户名
        }

        m_pimpl->m_isSessionActive = false;
        m_pimpl->m_hasServerConfig = false;  // 玩家登出，配置失效
    }

    // 唤醒监控线程，快速结束可能的等待
    m_pimpl->WakeMonitor();
}

void CheatMonitor::OnServerConfigUpdated()
{
    if (m_pimpl)
    {
        // 调用Pimpl的函数来处理配置更新的细节
        m_pimpl->OnConfigUpdated();

        m_pimpl->m_hasServerConfig = true;
        // 配置更新完成，监控线程可以根据新配置开始扫描
        m_pimpl->WakeMonitor();
    }
}

bool CheatMonitor::IsCallerLegitimate()
{
    if (!m_pimpl || !m_pimpl->m_isSystemActive.load())
    {
        return false;
    }

    PVOID caller_address = _ReturnAddress();

    // 先做基本的SEH保护检查
    auto validationResult = SystemUtils::CheckCallerAddressSafe(caller_address);
    if (!validationResult.success)
    {
        return false;
    }

    if (validationResult.hModule && validationResult.inCodeSection && validationResult.hasModulePath)
    {
        // 地址在代码节内，现在检查模块是否在白名单中
        std::wstring modulePath(validationResult.modulePath);
        std::transform(modulePath.begin(), modulePath.end(), modulePath.begin(), ::towlower);

        // m_legitimateModulePaths存储的是完整文件路径，直接比较即可
        std::lock_guard<std::mutex> lock(m_pimpl->m_modulePathsMutex);
        if (m_pimpl->m_legitimateModulePaths.count(modulePath) > 0)
        {
            return true;  // 合法：在白名单模块的代码节内
        }
    }
    else if (validationResult.hModule && !validationResult.inCodeSection)
    {
        // 地址在已知模块中，但不在其代码节内，非常可疑
        std::wostringstream woss;
        woss << L"IsCallerLegitimate: 调用来自已知模块，但位于非代码节. 地址: 0x" << std::hex << caller_address;
        m_pimpl->AddEvidence(anti_cheat::RUNTIME_ILLEGAL_FUNCTION_CALL, Utils::WideToString(woss.str()));
        return false;
    }

    // 默认情况下，如果模块未找到或不在白名单中，则为非法调用
    return false;
}

CheatMonitor::Pimpl::Pimpl()
{
    m_windowsVersion = SystemUtils::GetWindowsVersion();  // 初始化时检测并缓存Windows版本
    SystemUtils::EnsureNtApisLoaded();                    // 确保NT API指针已初始化
}

void CheatMonitor::Pimpl::InitializeSystem()
{
    m_rng.seed(m_rd());
    m_isSessionActive = false;

    // --- 传感器注册（基于权重精细化分级） ---
    // 创建所有传感器实例
    std::vector<std::unique_ptr<ISensor>> allSensors;
    // 按重要程度从低到高注册传感器
    // LIGHT WEIGHT (最低重要程度)
    allSensors.emplace_back(std::make_unique<AdvancedAntiDebugSensor>());
    allSensors.emplace_back(std::make_unique<SystemCodeIntegritySensor>());

    // MEDIUM WEIGHT (较低重要程度)
    allSensors.emplace_back(std::make_unique<IatHookSensor>());
    allSensors.emplace_back(std::make_unique<ProcessAndWindowMonitorSensor>());

    // HEAVY WEIGHT (中等重要程度)
    allSensors.emplace_back(std::make_unique<ModuleIntegritySensor>());
    allSensors.emplace_back(std::make_unique<ProcessHandleSensor>());
    allSensors.emplace_back(std::make_unique<ThreadAndModuleActivitySensor>());
    allSensors.emplace_back(std::make_unique<MemorySecuritySensor>());

    // CRITICAL WEIGHT (最高重要程度)
    allSensors.emplace_back(std::make_unique<VehHookSensor>());

    // 根据权重自动分类传感器
    for (auto &sensor : allSensors)
    {
        SensorWeight weight = sensor->GetWeight();
        switch (weight)
        {
            case SensorWeight::LIGHT:
            case SensorWeight::MEDIUM:
                m_lightweightSensors.emplace_back(std::move(sensor));
                break;
            case SensorWeight::HEAVY:
            case SensorWeight::CRITICAL:
                m_heavyweightSensors.emplace_back(std::move(sensor));
                break;
        }
    }

    LOG_INFO_F(AntiCheatLogger::LogCategory::SYSTEM, "传感器注册完成: %zu轻量级, %zu重量级",
               m_lightweightSensors.size(), m_heavyweightSensors.size());

    // --- 初始化 ---
    InitializeProcessBaseline();
    // HardenProcessAndThreads();
    CheckParentProcessAtStartup();
    DetectVirtualMachine();

    m_vehListAddress = FindVehListAddress();
    if (m_vehListAddress == 0)
    {
        AddEvidence(anti_cheat::RUNTIME_ERROR, "未能动态定位VEH链表地址。");
    }
}

void CheatMonitor::Pimpl::InitializeProcessBaseline()
{
    if (m_processBaselineEstablished.load())
        return;

    LOG_INFO(AntiCheatLogger::LogCategory::SYSTEM, "Initializing process baseline...");

    // 使用GetModuleHandle(NULL)获取当前模块句柄，这是最可靠的方法
    // 之前的this指针方法会失败，因为this指向堆上的对象，不在代码段中
    m_hSelfModule = GetModuleHandle(NULL);
    if (!m_hSelfModule)
    {
        AddEvidence(anti_cheat::RUNTIME_ERROR, "无法获取自身模块句柄以建立完整性基线。");
    }
    else
    {
        PVOID codeBase = nullptr;
        DWORD codeSize = 0;
        if (SystemUtils::GetModuleCodeSectionInfo(m_hSelfModule, codeBase, codeSize))
        {
            m_selfModuleBaselineHash = SystemUtils::CalculateFnv1aHash(static_cast<BYTE *>(codeBase), codeSize);
        }
        else
        {
            AddEvidence(anti_cheat::RUNTIME_ERROR, "无法获取自身代码节以建立完整性基线。");
        }
    }

    // 1. 建立已知模块列表和路径白名单
    std::vector<HMODULE> hMods(1024);  // 使用合理的默认值
    DWORD cbNeeded;
    if (EnumProcessModules(GetCurrentProcess(), hMods.data(), hMods.size() * sizeof(HMODULE), &cbNeeded))
    {
        if (hMods.size() * sizeof(HMODULE) < cbNeeded)
        {
            hMods.resize(cbNeeded / sizeof(HMODULE));
            EnumProcessModules(GetCurrentProcess(), hMods.data(), hMods.size() * sizeof(HMODULE), &cbNeeded);
        }

        // 先收集所有数据，最后一次性加锁更新
        std::vector<std::wstring> modulePaths;
        std::set<HMODULE> tempKnownModules;
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            tempKnownModules.insert(hMods[i]);
            wchar_t szModName[MAX_PATH];
            if (GetModuleFileNameW(hMods[i], szModName, MAX_PATH))
            {
                std::wstring path(szModName);
                std::transform(path.begin(), path.end(), path.begin(), ::towlower);
                modulePaths.push_back(path);
            }
        }

        // 一次性加锁更新m_knownModules
        {
            std::lock_guard<std::mutex> lock(m_baselineMutex);
            m_knownModules = std::move(tempKnownModules);
        }

        // 最小化锁范围：只保护最终的集合更新
        {
            std::lock_guard<std::mutex> lock(m_modulePathsMutex);
            m_legitimateModulePaths.clear();
            for (const auto &path : modulePaths)
            {
                m_legitimateModulePaths.insert(path);
            }
        }
    }

    // 2. 建立已知线程列表
    std::vector<DWORD> threadIds;
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
                    threadIds.push_back(te.th32ThreadID);
                }
            } while (Thread32Next(hThreadSnapshot, &te));
        }
        CloseHandle(hThreadSnapshot);
    }

    // 一次性更新基线数据
    {
        std::lock_guard<std::mutex> lock(m_baselineMutex);
        for (DWORD threadId : threadIds)
        {
            m_knownThreadIds.insert(threadId);
        }
    }

    // 3. 建立关键模块代码节的哈希基线
    m_moduleBaselineHashes.clear();
    {
        std::lock_guard<std::mutex> lock(m_baselineMutex);
        for (const auto &hModule : m_knownModules)
        {
            if (hModule == m_hSelfModule)
                continue;
            wchar_t modulePath_w[MAX_PATH];
            if (GetModuleFileNameW(hModule, modulePath_w, MAX_PATH) == 0)
                continue;
            std::wstring modulePath(modulePath_w);

            PVOID codeBase = nullptr;
            DWORD codeSize = 0;
            if (SystemUtils::GetModuleCodeSectionInfo(hModule, codeBase, codeSize))
            {
                m_moduleBaselineHashes[modulePath] =
                        SystemUtils::CalculateFnv1aHash(static_cast<BYTE *>(codeBase), codeSize);
            }
        }
    }

    // 4. 建立IAT Hook检测基线
    m_iatBaselineHashes.clear();
    const HMODULE hSelf = GetModuleHandle(NULL);
    if (hSelf)
    {
        const BYTE *baseAddress = reinterpret_cast<const BYTE *>(hSelf);
        const auto *pDosHeader = reinterpret_cast<const IMAGE_DOS_HEADER *>(baseAddress);
        if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
        {
            const auto *pNtHeaders = reinterpret_cast<const IMAGE_NT_HEADERS *>(baseAddress + pDosHeader->e_lfanew);
            if (pNtHeaders->Signature == IMAGE_NT_SIGNATURE)
            {
                IMAGE_DATA_DIRECTORY importDirectory =
                        pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
                if (importDirectory.VirtualAddress != 0)
                {
                    const auto *pImportDesc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR *>(
                            baseAddress + importDirectory.VirtualAddress);
                    const auto *pCurrentDesc = pImportDesc;
                    while (pCurrentDesc->Name)
                    {
                        const char *dllName = (const char *)(baseAddress + pCurrentDesc->Name);
                        std::vector<uint8_t> iat_hashes;
                        const auto *pThunk =
                                reinterpret_cast<const IMAGE_THUNK_DATA *>(baseAddress + pCurrentDesc->FirstThunk);
                        while (pThunk && pThunk->u1.AddressOfData)
                        {
                            uintptr_t func_ptr = pThunk->u1.Function;
                            iat_hashes.insert(iat_hashes.end(), (uint8_t *)&func_ptr,
                                              (uint8_t *)&func_ptr + sizeof(func_ptr));
                            pThunk++;
                        }
                        m_iatBaselineHashes[dllName] =
                                SystemUtils::CalculateFnv1aHash(iat_hashes.data(), iat_hashes.size());
                        pCurrentDesc++;
                    }
                }
            }
        }
    }

    if (!m_hwCollector)
        m_hwCollector = std::make_unique<anti_cheat::HardwareInfoCollector>();
    m_hwCollector->EnsureCollected();

    AddEvidence(anti_cheat::SYSTEM_INITIALIZED, "Process baseline established.");
    m_processBaselineEstablished = true;
}

void CheatMonitor::Pimpl::MonitorLoop()
{
    InitializeSystem();

    // 初始化扫描时间
    auto next_light_scan = std::chrono::steady_clock::now();
    auto next_heavy_scan = std::chrono::steady_clock::now();
    auto next_report_upload = std::chrono::steady_clock::now();
    auto next_sensor_stats_upload = std::chrono::steady_clock::now();

    while (m_isSystemActive.load())
    {
        // 计算下一次应当唤醒的时间点（最早的调度时间），支持快速关停
        const auto now_before_wait = std::chrono::steady_clock::now();
        auto earliest = now_before_wait + std::chrono::seconds(1);  // 默认1秒检查一次状态

        if (m_isSessionActive.load() && m_hasServerConfig.load())
        {
            earliest = std::min({next_light_scan, next_heavy_scan, next_report_upload, next_sensor_stats_upload});
        }

        {
            std::unique_lock<std::mutex> lk(m_cvMutex);
            m_cv.wait_until(lk, earliest, [&]() { return !m_isSystemActive.load(); });
        }

        if (!m_isSystemActive.load())
            break;

        // 核心逻辑：只有在会话激活并且已收到服务器配置后才执行扫描
        if (!m_isSessionActive.load() || !m_hasServerConfig.load())
        {
            continue;
        }

        // 在循环开始时定义now变量，确保在整个循环迭代中都有效
        const auto now = std::chrono::steady_clock::now();

        // === 轻量级传感器扫描 (45秒间隔) ===
        if (now >= next_light_scan)
        {
            ExecuteLightweightSensors();
            next_light_scan = now + GetLightScanInterval();
        }

        // === 重量级传感器扫描 (8分钟间隔) ===
        if (now >= next_heavy_scan)
        {
            ExecuteHeavyweightSensors();
            next_heavy_scan = now + GetHeavyScanInterval();
        }

        // === 报告上传调度 ===
        if (now >= next_report_upload)
        {
            UploadEvidenceReport();
            next_report_upload =
                    now + std::chrono::minutes(CheatConfigManager::GetInstance().GetReportUploadIntervalMinutes());
        }

        // === 统一传感器统计上报调度 (配置间隔) ===
        // 包含重量级和轻量级传感器的所有统计信息
        if (now >= next_sensor_stats_upload)
        {
            UploadSensorExecutionStatsReport();
            next_sensor_stats_upload =
                    now + std::chrono::minutes(CheatConfigManager::GetInstance().GetSensorStatsUploadIntervalMinutes());
        }
    }
}

void CheatMonitor::Pimpl::ResetSessionState()
{
    // 重置会话状态变量（受m_sessionMutex保护）
    {
        std::lock_guard<std::mutex> lock(m_sessionMutex);
        m_currentUserId = 0;
        m_currentUserName.clear();
        m_uniqueEvidence.clear();
        m_evidences.clear();
        m_lastReported.clear();
        m_evidenceOverflowed = false;
    }

    // 重置统一传感器统计（受m_sensorStatsMutex保护）
    {
        std::lock_guard<std::mutex> lock(m_sensorStatsMutex);
        m_sensorExecutionStats.clear();
    }

    // 重置基线数据（受m_baselineMutex保护）
    {
        std::lock_guard<std::mutex> lock(m_baselineMutex);
        m_knownThreadIds.clear();
        m_knownModules.clear();
    }

    LOG_INFO(AntiCheatLogger::LogCategory::SYSTEM, "Session state reset completed");
}

void CheatMonitor::Pimpl::OnConfigUpdated()
{
    // 获取配置信息
    std::string osVersionName = CheatConfigManager::GetInstance().GetMinOsVersionName();
    anti_cheat::OsVersion requiredOsVersion = CheatConfigManager::GetInstance().GetMinOsVersion();

    // 使用统一的IsCurrentOsSupported()方法检查版本兼容性
    const bool osVersionSupported = IsCurrentOsSupported();

    LOG_INFO_F(AntiCheatLogger::LogCategory::SYSTEM, "OS版本门控结果: 当前OS=%d, 配置要求min_os=%d, 版本兼容=%s",
               (int)m_windowsVersion, (int)requiredOsVersion, osVersionSupported ? "是" : "否");
}

bool CheatMonitor::Pimpl::IsCurrentOsSupported() const
{
    anti_cheat::OsVersion requiredOsVersion = CheatConfigManager::GetInstance().GetMinOsVersion();

    switch (requiredOsVersion)
    {
        case anti_cheat::OS_ANY:
            return true;
        case anti_cheat::OS_WIN_XP:
            return m_windowsVersion == SystemUtils::WindowsVersion::Win_XP ||
                   m_windowsVersion == SystemUtils::WindowsVersion::Win_Vista_Win7 ||
                   m_windowsVersion == SystemUtils::WindowsVersion::Win_8_Win81 ||
                   m_windowsVersion == SystemUtils::WindowsVersion::Win_10 ||
                   m_windowsVersion == SystemUtils::WindowsVersion::Win_11;
        case anti_cheat::OS_WIN7_SP1:
            return m_windowsVersion == SystemUtils::WindowsVersion::Win_Vista_Win7 ||
                   m_windowsVersion == SystemUtils::WindowsVersion::Win_8_Win81 ||
                   m_windowsVersion == SystemUtils::WindowsVersion::Win_10 ||
                   m_windowsVersion == SystemUtils::WindowsVersion::Win_11;
        case anti_cheat::OS_WIN10:
            return m_windowsVersion == SystemUtils::WindowsVersion::Win_10 ||
                   m_windowsVersion == SystemUtils::WindowsVersion::Win_11;
        default:
            return false;
    }
}

void CheatMonitor::Pimpl::AddEvidence(anti_cheat::CheatCategory category, const std::string &description)
{
    std::lock_guard<std::mutex> lock(m_sessionMutex);

    if (m_evidenceOverflowed)
        return;

    if (m_evidences.size() >= (size_t)CheatConfigManager::GetInstance().GetMaxEvidencesPerSession())
    {
        m_evidenceOverflowed = true;
        // 添加一条特殊证据，表明证据缓冲区已满
        anti_cheat::Evidence overflow_evidence;
        overflow_evidence.set_client_timestamp_ms(std::chrono::duration_cast<std::chrono::milliseconds>(
                                                          std::chrono::system_clock::now().time_since_epoch())
                                                          .count());
        overflow_evidence.set_category(anti_cheat::RUNTIME_ERROR);
        overflow_evidence.set_description("Evidence buffer overflow. Further events for this session are suppressed.");
        m_evidences.push_back(overflow_evidence);
        return;
    }

    // 使用 m_uniqueEvidence 集合进行去重检查
    if (m_uniqueEvidence.find({category, description}) != m_uniqueEvidence.end())
    {
        return;  // 相同的证据已经存在，直接返回
    }

    // 检查上报冷却时间
    const auto now = std::chrono::steady_clock::now();

    auto it = m_lastReported.find({m_currentUserId, category});
    if (it != m_lastReported.end())
    {
        auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(now - it->second);
        if (elapsed < std::chrono::minutes(CheatConfigManager::GetInstance().GetReportCooldownMinutes()))
        {
            return;  // 未达到冷却时间，不添加新证据
        }
    }

    // 添加新证据
    anti_cheat::Evidence evidence;
    evidence.set_client_timestamp_ms(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                    .count());
    evidence.set_category(category);
    evidence.set_description(description);

    m_evidences.push_back(evidence);
    m_uniqueEvidence.insert({category, description});
    m_lastReported[{m_currentUserId, category}] = now;  // 更新上报时间

    LOG_WARNING_F(AntiCheatLogger::LogCategory::SECURITY, "Evidence added: %s", description.c_str());
}

void CheatMonitor::Pimpl::UploadHardwareReport()
{
    if (!m_hwCollector)
        return;

    auto fp = m_hwCollector->ConsumeFingerprint();
    if (!fp)
        return;

    anti_cheat::Report report;
    report.set_type(anti_cheat::REPORT_HARDWARE);

    auto hardware_report = report.mutable_hardware();
    hardware_report->set_report_id(Utils::GenerateUuid());
    hardware_report->set_report_timestamp_ms(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                    .count());
    *hardware_report->mutable_fingerprint() = *fp;

    SendReport(report);
}

void CheatMonitor::Pimpl::UploadEvidenceReport()
{
    std::lock_guard<std::mutex> lock(m_sessionMutex);

    if (m_evidences.empty())
        return;

    anti_cheat::Report report;
    report.set_type(anti_cheat::REPORT_EVIDENCE);

    auto evidence_report = report.mutable_evidence();
    evidence_report->set_report_id(Utils::GenerateUuid());
    evidence_report->set_report_timestamp_ms(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                    .count());

    // 移动证据到报告中，并清空本地缓存
    for (auto &evidence : m_evidences)
    {
        *evidence_report->add_evidences() = std::move(evidence);
    }
    m_evidences.clear();
    m_uniqueEvidence.clear();  // 清空去重集合

    SendReport(report);
}

void CheatMonitor::Pimpl::UploadTelemetryMetricsReport(const anti_cheat::TelemetryMetrics &metrics)
{
    anti_cheat::Report report;
    report.set_type(anti_cheat::REPORT_TELEMETRY);

    auto telemetry_report = report.mutable_telemetry();
    telemetry_report->set_report_id(Utils::GenerateUuid());
    telemetry_report->set_report_timestamp_ms(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                    .count());
    *telemetry_report->mutable_metrics() = metrics;

    SendReport(report);
}

void CheatMonitor::Pimpl::UploadSensorExecutionStatsReport()
{
    // 创建TelemetryMetrics并填充统一传感器统计数据
    anti_cheat::TelemetryMetrics metrics;
    {
        std::lock_guard<std::mutex> lock(m_sensorStatsMutex);

        // 填充每个传感器的详细执行统计
        for (const auto &kv : m_sensorExecutionStats)
        {
            const std::string &name = kv.first;
            const auto &stats = kv.second;
            // 跳过全0统计，避免后台出现大量0字段
            bool nonEmpty = false;
            if (stats.success_count() > 0 || stats.failure_count() > 0 || stats.timeout_count() > 0 ||
                stats.total_success_time_ms() > 0 || stats.total_failure_time_ms() > 0 ||
                stats.avg_success_time_ms() > 0 || stats.avg_failure_time_ms() > 0 || stats.max_success_time_ms() > 0 ||
                stats.min_success_time_ms() > 0 || stats.max_failure_time_ms() > 0 || stats.min_failure_time_ms() > 0 ||
                stats.workload_snapshot_size_total() > 0 || stats.workload_attempts_total() > 0 ||
                stats.workload_hits_total() > 0 || stats.workload_last_snapshot_size() > 0 ||
                stats.workload_last_attempts() > 0 || stats.workload_last_hits() > 0)
            {
                nonEmpty = true;
            }
            if (!nonEmpty)
                continue;
            // 添加到metrics中
            (*metrics.mutable_sensor_execution_stats())[name] = stats;
        }

        // 清空统计数据，准备下一轮统计
        m_sensorExecutionStats.clear();
    }

    // 汇总上报不需要设置基础信息字段，只包含传感器统计数据

    UploadTelemetryMetricsReport(metrics);
}

void CheatMonitor::Pimpl::RecordSensorExecutionStats(const char *name, int duration_ms, SensorExecutionResult result,
                                                     anti_cheat::SensorFailureReason failureReason)
{
    std::lock_guard<std::mutex> lock(m_sensorStatsMutex);

    auto &stats = m_sensorExecutionStats[name];

    // 更新执行次数和时间统计
    switch (result)
    {
        case SensorExecutionResult::SUCCESS:
            stats.set_success_count(stats.success_count() + 1);
            stats.set_total_success_time_ms(stats.total_success_time_ms() + duration_ms);
            if (stats.success_count() > 0)
            {
                stats.set_avg_success_time_ms(stats.total_success_time_ms() / stats.success_count());
            }
            // 更新最大/最小成功执行时间
            if (stats.max_success_time_ms() == 0 || duration_ms > stats.max_success_time_ms())
            {
                stats.set_max_success_time_ms(duration_ms);
            }
            if (stats.min_success_time_ms() == 0 || duration_ms < stats.min_success_time_ms())
            {
                stats.set_min_success_time_ms(duration_ms);
            }
            break;
        case SensorExecutionResult::FAILURE:
            stats.set_failure_count(stats.failure_count() + 1);
            stats.set_total_failure_time_ms(stats.total_failure_time_ms() + duration_ms);
            if (stats.failure_count() > 0)
            {
                stats.set_avg_failure_time_ms(stats.total_failure_time_ms() / stats.failure_count());
            }
            // 更新最大/最小失败执行时间
            if (stats.max_failure_time_ms() == 0 || duration_ms > stats.max_failure_time_ms())
            {
                stats.set_max_failure_time_ms(duration_ms);
            }
            if (stats.min_failure_time_ms() == 0 || duration_ms < stats.min_failure_time_ms())
            {
                stats.set_min_failure_time_ms(duration_ms);
            }
            break;
        case SensorExecutionResult::TIMEOUT:
            stats.set_timeout_count(stats.timeout_count() + 1);
            // 超时统计只记录次数，不记录时间
            break;
    }

    // 记录失败原因（使用enum索引）
    if (result == SensorExecutionResult::FAILURE && failureReason != anti_cheat::UNKNOWN_FAILURE)
    {
        (*stats.mutable_failure_reasons())[static_cast<int32_t>(failureReason)]++;
    }
}

void CheatMonitor::Pimpl::RecordSensorWorkloadCounters(const std::string &name, uint64_t snapshot_size,
                                                       uint64_t attempts, uint64_t hits)
{
    std::lock_guard<std::mutex> lock(m_sensorStatsMutex);
    auto &stats = m_sensorExecutionStats[name];
    // 仅在非零时赋值，避免上报全0字段
    if (snapshot_size)
    {
        stats.set_workload_snapshot_size_total(stats.workload_snapshot_size_total() + snapshot_size);
        stats.set_workload_last_snapshot_size(snapshot_size);
    }
    if (attempts)
    {
        stats.set_workload_attempts_total(stats.workload_attempts_total() + attempts);
        stats.set_workload_last_attempts(attempts);
    }
    if (hits)
    {
        stats.set_workload_hits_total(stats.workload_hits_total() + hits);
        stats.set_workload_last_hits(hits);
    }
}

void CheatMonitor::Pimpl::SendReport(const anti_cheat::Report &report)
{
    std::string serialized_report;
    if (!report.SerializeToString(&serialized_report))
    {
        LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM, "Failed to serialize report");
        return;
    }

    const char *report_type_name = "Unknown";
    size_t content_size = 0;

    switch (report.type())
    {
        case anti_cheat::REPORT_HARDWARE:
            report_type_name = "Hardware";
            if (report.has_hardware())
            {
                content_size = 1;  // 1个硬件指纹
            }
            break;
        case anti_cheat::REPORT_EVIDENCE:
            report_type_name = "Evidence";
            if (report.has_evidence())
            {
                content_size = report.evidence().evidences_size();
            }
            break;
        case anti_cheat::REPORT_TELEMETRY:
            report_type_name = "Telemetry";
            if (report.has_telemetry())
            {
                content_size = 1;  // 1个遥测包
            }
            break;
        default:
            break;
    }

    LOG_INFO_F(AntiCheatLogger::LogCategory::SYSTEM, "Uploading %s report... Size: %zu bytes, content items: %zu",
               report_type_name, serialized_report.length(), content_size);

    // TODO: 将 report 序列化并通过网络发送到服务器
    // HttpSend(server_url, serialized_report);
}

void CheatMonitor::Pimpl::HardenProcessAndThreads()
{
    // 1. 检查当前进程权限
    bool isElevated = false;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size))
        {
            isElevated = elevation.TokenIsElevated != 0;
        }
        CloseHandle(hToken);
    }

    if (!isElevated)
    {
        LOG_WARNING(AntiCheatLogger::LogCategory::SYSTEM, "进程未以管理员权限运行，某些安全策略可能无法设置");
    }

    // 2. 启用进程缓解策略 (DEP, 禁止创建子进程等)
    // 动态加载 SetProcessMitigationPolicy
    typedef BOOL(WINAPI * PSetProcessMitigationPolicy)(PROCESS_MITIGATION_POLICY Policy, PVOID lpBuffer,
                                                       SIZE_T dwLength);
    static PSetProcessMitigationPolicy pSetProcessMitigationPolicy = (PSetProcessMitigationPolicy)GetProcAddress(
            GetModuleHandleW(L"kernel32.dll"), "SetProcessMitigationPolicy");

    if (pSetProcessMitigationPolicy)
    {
        int successCount = 0;
        int totalPolicies = 2;

        // 启用DEP - 检查返回值和错误
        PROCESS_MITIGATION_DEP_POLICY depPolicy = {};
        depPolicy.Enable = 1;
        depPolicy.Permanent = false;  // 改为false，减少权限要求
        BOOL depResult = pSetProcessMitigationPolicy(ProcessDEPPolicy, &depPolicy, sizeof(depPolicy));
        if (depResult)
        {
            successCount++;
            LOG_INFO(AntiCheatLogger::LogCategory::SYSTEM, "DEP缓解策略已启用");
        }
        else
        {
            DWORD error = GetLastError();
            // 对于常见的预期错误，使用INFO级别而不是WARNING
            if (error == ERROR_ACCESS_DENIED || error == ERROR_NOT_SUPPORTED || error == ERROR_ALREADY_EXISTS)
            {
                LOG_INFO_F(AntiCheatLogger::LogCategory::SYSTEM, "DEP缓解策略设置跳过，错误代码: %lu (预期情况)",
                           error);
            }
            else
            {
                LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM, "DEP缓解策略设置失败，错误代码: %lu", error);
            }
        }

        // 禁止创建子进程 - 检查返回值和错误
        PROCESS_MITIGATION_CHILD_PROCESS_POLICY childPolicy = {};
        childPolicy.NoChildProcessCreation = 1;
        BOOL childResult = pSetProcessMitigationPolicy(ProcessChildProcessPolicy, &childPolicy, sizeof(childPolicy));
        if (childResult)
        {
            successCount++;
            LOG_INFO(AntiCheatLogger::LogCategory::SYSTEM, "子进程禁止策略已启用");
        }
        else
        {
            DWORD error = GetLastError();
            // 对于常见的预期错误，使用INFO级别而不是WARNING
            if (error == ERROR_ACCESS_DENIED || error == ERROR_NOT_SUPPORTED || error == ERROR_ALREADY_EXISTS)
            {
                LOG_INFO_F(AntiCheatLogger::LogCategory::SYSTEM, "子进程禁止策略设置跳过，错误代码: %lu (预期情况)",
                           error);
            }
            else
            {
                LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM, "子进程禁止策略设置失败，错误代码: %lu", error);
            }
        }

        // 总结策略设置结果
        if (successCount == totalPolicies)
        {
            LOG_INFO(AntiCheatLogger::LogCategory::SYSTEM, "所有进程缓解策略已成功启用");
        }
        else if (successCount > 0)
        {
            LOG_INFO_F(AntiCheatLogger::LogCategory::SYSTEM, "已启用 %d/%d 个进程缓解策略", successCount,
                       totalPolicies);
        }
        else
        {
            LOG_INFO(AntiCheatLogger::LogCategory::SYSTEM, "未能启用进程缓解策略 (这在某些环境下是正常的)");
        }
    }
    else
    {
        // API不可用通常是因为系统版本过低，不视为错误
        LOG_WARNING(AntiCheatLogger::LogCategory::SYSTEM,
                    "SetProcessMitigationPolicy API 不可用，可能是系统版本过低。");
    }

    // 2. 隐藏我们自己的监控线程，增加逆向分析难度
    // 使用SystemUtils命名空间中的g_pNtSetInformationThread
    if (SystemUtils::g_pNtSetInformationThread)
    {
        NTSTATUS status = SystemUtils::g_pNtSetInformationThread(GetCurrentThread(),
                                                                 (THREADINFOCLASS)17,  // ThreadHideFromDebugger
                                                                 nullptr, 0);
        if (!NT_SUCCESS(status))
        {
            // 线程隐藏失败通常不影响功能，只记录日志
            LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM, "线程隐藏设置失败，NTSTATUS: 0x%08X", status);
        }
        else
        {
            LOG_INFO(AntiCheatLogger::LogCategory::SYSTEM, "监控线程已设置为对调试器隐藏");
        }
    }
    else
    {
        LOG_WARNING(AntiCheatLogger::LogCategory::SYSTEM, "NtSetInformationThread API 不可用，无法隐藏监控线程");
    }
}

void CheatMonitor::Pimpl::CheckParentProcessAtStartup()
{
    // 最终版逻辑：考虑到启动器loader.exe启动后立即退出的竞态条件。
    // 1. 如果父进程存在，则必须是 loader.exe，否则立即上报。
    // 2. 如果父进程不存在（孤儿进程），则标记为可疑，交由 SuspiciousLaunchSensor 做后续关联分析。
    DWORD parentPid = 0;
    std::string parentName;
    if (Utils::GetParentProcessInfo(parentPid, parentName))
    {
        // Case 1: Parent process was found.
        std::transform(parentName.begin(), parentName.end(), parentName.begin(), ::tolower);
        if (parentName != "loader.exe")
        {
            AddEvidence(anti_cheat::ENVIRONMENT_INVALID_PARENT_PROCESS,
                        "Invalid parent process: " + parentName + " (PID: " + std::to_string(parentPid) + ")");
        }
        // If parent is loader.exe, this is a valid launch. m_parentWasMissingAtStartup remains false.
    }
    else
    {
        // Case 2: Parent process not found (orphaned).
        // This could indicate an abnormal launch, but we don't treat it as definitive evidence
        // since many legitimate launchers exit after starting the game.
        LOG_INFO(AntiCheatLogger::LogCategory::SYSTEM, "Parent process not found - could be normal launcher behavior");
    }
}

void CheatMonitor::Pimpl::DetectVirtualMachine()
{
    DetectVmByCpuid();
    DetectVmByRegistry();
    DetectVmByMacAddress();
}

void CheatMonitor::Pimpl::DetectVmByCpuid()
{
    std::array<int, 4> cpuid_info;
    __cpuid(cpuid_info.data(), 1);
    if ((cpuid_info[2] >> 31) & 1)
    {
        AddEvidence(anti_cheat::ENVIRONMENT_VIRTUAL_MACHINE, "检测到虚拟机环境 (CPUID hypervisor bit)");
    }

    __cpuid(cpuid_info.data(), 0x40000000);
    std::string vendor_id;
    vendor_id.append(reinterpret_cast<char *>(&cpuid_info[1]), 4);
    vendor_id.append(reinterpret_cast<char *>(&cpuid_info[2]), 4);
    vendor_id.append(reinterpret_cast<char *>(&cpuid_info[3]), 4);

    if (vendor_id.find("VMware") != std::string::npos || vendor_id.find("KVMKVMKVM") != std::string::npos ||
        vendor_id.find("VBoxVBoxVBox") != std::string::npos || vendor_id.find("Microsoft Hv") != std::string::npos)
    {
        AddEvidence(anti_cheat::ENVIRONMENT_VIRTUAL_MACHINE, "检测到虚拟机环境 (CPUID vendor ID: " + vendor_id + ")");
    }
}

void CheatMonitor::Pimpl::DetectVmByRegistry()
{
    const wchar_t *vmKeys[] = {L"HARDWARE\\DESCRIPTION\\System\\BIOS\\SystemManufacturer",
                               L"HARDWARE\\DESCRIPTION\\System\\BIOS\\SystemProductName"};
    const wchar_t *vmValues[] = {L"vmware", L"virtualbox", L"qemu", L"kvm", L"microsoft"};

    for (const auto &key : vmKeys)
    {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
        {
            wchar_t buffer[256];
            DWORD size = sizeof(buffer);
            if (RegQueryValueExW(hKey, L"SystemManufacturer", NULL, NULL, (LPBYTE)buffer, &size) == ERROR_SUCCESS)
            {
                std::wstring manufacturer(buffer);
                std::transform(manufacturer.begin(), manufacturer.end(), manufacturer.begin(), ::towlower);
                for (const auto &vm : vmValues)
                {
                    if (manufacturer.find(vm) != std::wstring::npos)
                    {
                        AddEvidence(anti_cheat::ENVIRONMENT_VIRTUAL_MACHINE,
                                    "检测到虚拟机环境 (Registry: " + Utils::WideToString(manufacturer) + ")");
                        RegCloseKey(hKey);
                        return;
                    }
                }
            }
            RegCloseKey(hKey);
        }
    }
}

void CheatMonitor::Pimpl::DetectVmByMacAddress()
{
    // VMware, VirtualBox, Hyper-V 等常用虚拟机的MAC地址前缀
    const std::vector<std::string> vmMacPrefixes = {"00:05:69", "00:0C:29", "00:1C:14",
                                                    "00:50:56", "08:00:27", "00:15:5D"};

    ULONG bufferSize = sizeof(IP_ADAPTER_INFO);
    std::vector<BYTE> buffer(bufferSize);
    PIP_ADAPTER_INFO pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());

    if (GetAdaptersInfo(pAdapterInfo, &bufferSize) == ERROR_BUFFER_OVERFLOW)
    {
        buffer.resize(bufferSize);
        pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
    }

    if (GetAdaptersInfo(pAdapterInfo, &bufferSize) == NO_ERROR)
    {
        while (pAdapterInfo)
        {
            char macStr[18];
            sprintf_s(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X", pAdapterInfo->Address[0],
                      pAdapterInfo->Address[1], pAdapterInfo->Address[2], pAdapterInfo->Address[3],
                      pAdapterInfo->Address[4], pAdapterInfo->Address[5]);

            for (const auto &prefix : vmMacPrefixes)
            {
                if (std::string(macStr).rfind(prefix, 0) == 0)
                {
                    AddEvidence(anti_cheat::ENVIRONMENT_VIRTUAL_MACHINE,
                                "检测到虚拟机环境 (MAC Address: " + std::string(macStr) + ")");
                    return;
                }
            }
            pAdapterInfo = pAdapterInfo->Next;
        }
    }
}

void CheatMonitor::Pimpl::VerifyModuleSignature(HMODULE hModule)
{
    wchar_t modulePath_w[MAX_PATH];
    if (GetModuleFileNameW(hModule, modulePath_w, MAX_PATH) == 0)
    {
        return;
    }
    // 统一规范化为绝对路径并转小写，避免缓存/节流键不一致
    std::wstring modulePath = modulePath_w;
    std::transform(modulePath.begin(), modulePath.end(), modulePath.begin(), ::towlower);

    const auto now = std::chrono::steady_clock::now();
    // 读取TTL一次，减少锁内工作量
    const auto ttl = std::chrono::minutes(CheatConfigManager::GetInstance().GetSignatureCacheDurationMinutes());
    {
        // 确定性清理：每次调用都清理过期项，确保内存使用稳定
        // 使用迭代器安全删除过期项
        for (auto it = m_moduleSignatureCache.begin(); it != m_moduleSignatureCache.end();)
        {
            if (now >= it->second.second + ttl)
                it = m_moduleSignatureCache.erase(it);
            else
                ++it;
        }
        // 节流：同一路径在短窗口内只验证一次，避免一个扫描周期内的重复开销
        const auto itThr = m_sigThrottleUntil.find(modulePath);
        if (itThr != m_sigThrottleUntil.end() && now < itThr->second)
        {
            return;
        }

        auto it = m_moduleSignatureCache.find(modulePath);
        if (it != m_moduleSignatureCache.end())
        {
            // Check cache expiry (TTL)
            if (now < it->second.second + ttl)
            {
                return;  // Still valid, no need to re-verify
            }
        }
    }

    //  改进签名验证逻辑，更严格地处理验证失败的情况，解决专家提出的"宽松处理"问题。
    // 只有在明确验证为"可信"或"不可信"时才更新缓存。
    // 如果验证过程本身失败（例如，网络问题导致无法检查吊销列表），则不更新缓存，
    // 以便在下一次扫描时重试。
    switch (Utils::VerifyFileSignature(modulePath, m_windowsVersion))
    {
        case Utils::SignatureStatus::TRUSTED: {
            m_moduleSignatureCache[modulePath] = {SignatureVerdict::SIGNED_AND_TRUSTED, now};
            // 设置短节流窗口，避免本周期内重复验证
            m_sigThrottleUntil[modulePath] =
                    now +
                    std::chrono::seconds(CheatConfigManager::GetInstance().GetSignatureVerificationThrottleSeconds());
        }
        break;
        case Utils::SignatureStatus::UNTRUSTED: {
            m_moduleSignatureCache[modulePath] = {SignatureVerdict::UNSIGNED_OR_UNTRUSTED, now};
            // 未签名：也进行短节流
            m_sigThrottleUntil[modulePath] =
                    now +
                    std::chrono::seconds(CheatConfigManager::GetInstance().GetSignatureVerificationThrottleSeconds());
            // 在 XP/Vista/Win7 上，避免将现代SHA-2签名缺失误判为不受信任，降低证据等级：仅缓存，不立即上报。
            if (m_windowsVersion != SystemUtils::WindowsVersion::Win_XP &&
                m_windowsVersion != SystemUtils::WindowsVersion::Win_Vista_Win7)
            {
                AddEvidence(anti_cheat::RUNTIME_MODULE_NEW_UNKNOWN,
                            "加载了未签名的模块: " + Utils::WideToString(modulePath));
            }
        }
        break;
        case Utils::SignatureStatus::FAILED_TO_VERIFY:
            // 不缓存验证失败的结果，以便下次扫描时可以重试。
            // 但为了避免频繁抖动，设置更短的节流窗口。
            m_sigThrottleUntil[modulePath] =
                    now + std::chrono::milliseconds(
                                  CheatConfigManager::GetInstance().GetSignatureVerificationFailureThrottleMs());
            break;
    }
}

bool CheatMonitor::Pimpl::IsAddressInLegitimateModule(PVOID address, std::wstring &outModulePath)
{
    HMODULE hModule = NULL;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)address, &hModule) &&
        hModule)
    {
        wchar_t modulePath_w[MAX_PATH];
        if (GetModuleFileNameW(hModule, modulePath_w, MAX_PATH) > 0)
        {
            outModulePath = modulePath_w;
            std::wstring originalPath = outModulePath;
            std::transform(outModulePath.begin(), outModulePath.end(), outModulePath.begin(), ::towlower);

            std::lock_guard<std::mutex> lock(m_modulePathsMutex);
            bool isLegitimate = m_legitimateModulePaths.count(outModulePath) > 0;

            // 添加调试日志：记录模块检查结果
            if (!isLegitimate)
            {
                // 使用OutputDebugString记录详细信息
                std::wostringstream debugMsg;
                debugMsg << L"[IsAddressInLegitimateModule] 地址 0x" << std::hex << address
                         << L" 不在合法模块中. 模块路径: " << originalPath << L" (小写: " << outModulePath << L")"
                         << std::endl;
                OutputDebugStringW(debugMsg.str().c_str());

                // 同时记录到日志系统
                LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                            "IsAddressInLegitimateModule: 地址 0x%p 不在合法模块中, 模块路径=%s", address,
                            Utils::WideToString(originalPath).c_str());
            }
            else
            {
                // 记录成功的匹配（可选，用于验证）
                LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                            "IsAddressInLegitimateModule: 地址 0x%p 匹配合法模块, 模块路径=%s", address,
                            Utils::WideToString(originalPath).c_str());
            }

            return isLegitimate;
        }
        else
        {
            // GetModuleFileNameW失败
            LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                        "IsAddressInLegitimateModule: 地址 0x%p 获取模块路径失败, hModule=0x%p", address, hModule);
        }
    }
    else
    {
        // GetModuleHandleExW失败
        LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR, "IsAddressInLegitimateModule: 地址 0x%p 不属于任何模块",
                    address);
    }
    return false;
}

bool CheatMonitor::Pimpl::IsAddressInLegitimateModule(PVOID address)
{
    std::wstring dummyPath;  // 不需要的路径参数
    return IsAddressInLegitimateModule(address, dummyPath);
}

uintptr_t CheatMonitor::Pimpl::FindVehListAddress()
{
    //  采用单一、更可靠的"诱饵处理函数"方法来定位VEH链表。
    // 此方法比依赖脆弱的字节码模式匹配要稳定得多，能更好地适应Windows版本更新。

    // 添加retry机制：AddVectoredExceptionHandler可能因为系统负载等原因失败
    PVOID pDecoyHandler = nullptr;
    int retryCount = 0;
    int maxRetries = 3;

    while (!pDecoyHandler && retryCount < 3)
    {
        pDecoyHandler = AddVectoredExceptionHandler(1, SystemUtils::DecoyVehHandler);
        if (!pDecoyHandler)
        {
            retryCount++;
            DWORD error = GetLastError();
            LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM,
                          "FindVehListAddress: AddVectoredExceptionHandler失败 (尝试 %d/%d)，错误码: 0x%08X",
                          retryCount, maxRetries, error);

            if (retryCount < maxRetries)
            {
                Sleep(300);
            }
        }
    }

    if (!pDecoyHandler)
    {
        LOG_ERROR_F(AntiCheatLogger::LogCategory::SYSTEM,
                    "FindVehListAddress Error: AddVectoredExceptionHandler failed after %d retries.", maxRetries);
        return 0;
    }

    uintptr_t listHeadAddress = 0;
    __try
    {
        const auto *pEntry = reinterpret_cast<const VECTORED_HANDLER_ENTRY *>(pDecoyHandler);
        const LIST_ENTRY *pCurrent = &pEntry->List;

        // 向后遍历链表以查找头节点，设置迭代上限以防意外的循环
        for (int i = 0; i < 100; ++i)
        {
            const LIST_ENTRY *pBlink = pCurrent->Blink;
            if (!SystemUtils::IsValidPointer(pBlink, sizeof(LIST_ENTRY)) ||
                !SystemUtils::IsValidPointer(pBlink->Flink, sizeof(LIST_ENTRY *)))
            {
                break;  // 链表指针无效，终止遍历
            }

            // 链表头的特征：Blink->Flink == 当前节点
            if (pBlink->Flink == pCurrent)
            {
                listHeadAddress = reinterpret_cast<uintptr_t>(pBlink);
                break;
            }
            pCurrent = pBlink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        //  记录异常代码
        LOG_ERROR_F(AntiCheatLogger::LogCategory::SYSTEM, "FindVehListAddress SEH Exception. Code: 0x%08X",
                    GetExceptionCode());
        listHeadAddress = 0;
    }

    if (!RemoveVectoredExceptionHandler(pDecoyHandler))
    {
        LOG_ERROR_F(AntiCheatLogger::LogCategory::SYSTEM,
                    "FindVehListAddress Error: Failed to remove decoy VEH handler. Error: 0x%08X", GetLastError());
    }

    if (listHeadAddress == 0)
    {
        LOG_ERROR(AntiCheatLogger::LogCategory::SYSTEM, "FindVehListAddress Error: Could not find VEH list head.");
        return 0;
    }

    // 根据Windows版本，从链表头地址计算整个VEH列表结构的基地址
    // 这是必要的，因为VEH列表结构在不同Windows版本中不同
    uintptr_t structBaseAddress = 0;
    SystemUtils::WindowsVersion ver = SystemUtils::GetWindowsVersion();
    if (ver == SystemUtils::WindowsVersion::Win_Unknown)
    {
        LOG_WARNING(AntiCheatLogger::LogCategory::SYSTEM,
                    "Unknown Windows version. Assuming Win8+ VEH list structure.");
        // 对于未知或未来的版本，默认使用最新的已知结构是一个合理的降级策略。
    }

    switch (ver)
    {
        case SystemUtils::WindowsVersion::Win_XP:
            // 在XP中，List成员在CRITICAL_SECTION之后
            structBaseAddress = listHeadAddress - offsetof(VECTORED_HANDLER_LIST_XP, List);
            break;
        case SystemUtils::WindowsVersion::Win_Vista_Win7:
            // 在Vista/7中，是ExceptionList成员在CRITICAL_SECTION之后
            structBaseAddress = listHeadAddress - offsetof(VECTORED_HANDLER_LIST_VISTA, ExceptionList);
            break;
        case SystemUtils::WindowsVersion::Win_Unknown:  // 让未知情况的处理更明确
        default:                                        // Win8及更新版本
            structBaseAddress = listHeadAddress - offsetof(VECTORED_HANDLER_LIST_WIN8, ExceptionList);
            break;
    }

    LOG_INFO_F(AntiCheatLogger::LogCategory::SYSTEM, "Dynamically located VEH list structure at: 0x%p",
               (void *)structBaseAddress);
    return structBaseAddress;
}

void CheatMonitor::Pimpl::CheckIatHooks(ScanContext &context, const BYTE *baseAddress,
                                        const IMAGE_IMPORT_DESCRIPTOR *pImportDesc)
{
    const auto &baselineHashes = context.GetIatBaselineHashes();
    while (pImportDesc->Name)
    {
        const char *dllName = (const char *)(baseAddress + pImportDesc->Name);
        auto it = baselineHashes.find(dllName);
        if (it != baselineHashes.end())
        {
            // Calculate current hash
            std::vector<uint8_t> current_iat_hashes;
            auto *pThunk = reinterpret_cast<IMAGE_THUNK_DATA *>((BYTE *)baseAddress + pImportDesc->FirstThunk);
            while (pThunk->u1.AddressOfData)
            {
                uintptr_t func_ptr = pThunk->u1.Function;
                current_iat_hashes.insert(current_iat_hashes.end(), (uint8_t *)&func_ptr,
                                          (uint8_t *)&func_ptr + sizeof(func_ptr));
                pThunk++;
            }
            std::vector<uint8_t> currentHash =
                    SystemUtils::CalculateFnv1aHash(current_iat_hashes.data(), current_iat_hashes.size());

            if (currentHash != it->second)
            {
                context.AddEvidence(anti_cheat::INTEGRITY_API_HOOK, "检测到IAT Hook: " + std::string(dllName));
            }
        }
        pImportDesc++;
    }
}

const std::chrono::milliseconds CheatMonitor::Pimpl::GetLightScanInterval() const
{
    // 轻量级传感器：使用配置的扫描间隔 + 随机抖动
    const auto base_interval = std::chrono::seconds(CheatConfigManager::GetInstance().GetBaseScanInterval());
    const auto jitter = std::chrono::milliseconds(const_cast<std::mt19937 &>(m_rng)() % 2000);
    return base_interval + jitter;
}

const std::chrono::milliseconds CheatMonitor::Pimpl::GetHeavyScanInterval() const
{
    // 重量级传感器：使用配置的扫描间隔 + 随机抖动
    const auto base_interval = std::chrono::minutes(CheatConfigManager::GetInstance().GetHeavyScanIntervalMinutes());
    const auto jitter = std::chrono::milliseconds(const_cast<std::mt19937 &>(m_rng)() % 60000);
    return base_interval + jitter;
}

void CheatMonitor::Pimpl::ExecuteLightweightSensors()
{
    if (m_lightweightSensors.empty())
        return;

    // 轻量级传感器：依次按index扫描
    m_lightSensorIndex %= m_lightweightSensors.size();
    const auto &sensor = m_lightweightSensors[m_lightSensorIndex];
    ExecuteAndMonitorSensor(sensor.get(), sensor->GetName(), false /*isHeavyweight*/);
    m_lightSensorIndex = (m_lightSensorIndex + 1) % m_lightweightSensors.size();
}

void CheatMonitor::Pimpl::ExecuteHeavyweightSensors()
{
    if (m_heavyweightSensors.empty())
        return;

    // 重量级传感器：依次按index扫描
    m_heavySensorIndex %= m_heavyweightSensors.size();
    const auto &sensor = m_heavyweightSensors[m_heavySensorIndex];
    ExecuteAndMonitorSensor(sensor.get(), sensor->GetName(), true /*isHeavyweight*/);
    m_heavySensorIndex = (m_heavySensorIndex + 1) % m_heavyweightSensors.size();
}

void CheatMonitor::Pimpl::ExecuteAndMonitorSensor(ISensor *sensor, const char *name, bool isHeavyweight)
{
    const auto startTime = std::chrono::steady_clock::now();
    ScanContext context(this);

    try
    {
        SensorExecutionResult result = sensor->Execute(context);
        const auto end = std::chrono::steady_clock::now();
        const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - startTime).count();

        // 获取失败原因
        anti_cheat::SensorFailureReason failureReason = anti_cheat::UNKNOWN_FAILURE;
        if (result == SensorExecutionResult::FAILURE)
        {
            failureReason = sensor->GetLastFailureReason();
        }

        // 统一记录传感器执行统计
        RecordSensorExecutionStats(name, (int)elapsed_ms, result, failureReason);
    }
    catch (const std::exception &e)
    {
        // 统一异常处理：既记录日志又记录统计
        const auto end = std::chrono::steady_clock::now();
        const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - startTime).count();
        LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR, "传感器异常: %s - %s", name, e.what());

        // 记录异常执行统计 - 使用更明确的C++异常失败原因
        RecordSensorExecutionStats(name, (int)elapsed_ms, SensorExecutionResult::FAILURE,
                                   anti_cheat::CPP_EXCEPTION_FAILURE);
    }
    catch (...)
    {
        // 统一未知异常处理
        const auto end = std::chrono::steady_clock::now();
        const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - startTime).count();
        LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR, "传感器未知异常: %s", name);

        // 记录异常执行统计 - 使用更明确的未知异常失败原因
        RecordSensorExecutionStats(name, (int)elapsed_ms, SensorExecutionResult::FAILURE,
                                   anti_cheat::UNKNOWN_EXCEPTION_FAILURE);
    }
}

void CheatMonitor::Pimpl::AddRandomJitter()
{
    // 增加随机抖动，避免可预测的扫描周期
    std::uniform_int_distribution<long> jitter_dist(0, CheatConfigManager::GetInstance().GetJitterMilliseconds());
    std::this_thread::sleep_for(std::chrono::milliseconds(jitter_dist(m_rng)));
}
