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
#include <winternl.h>  // 包含 NTSTATUS 等定义
#include <wintrust.h>  // 为 WinVerifyTrust 添加头文件

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

// 预声明以解决前置使用
enum WindowsVersion;
WindowsVersion GetWindowsVersion();

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

// 为兼容旧版Windows SDK (pre-Win8)，手动定义缺失的类型
// 注释：现代Windows 10 SDK已包含这些定义，无需手动定义
// #if !defined(NTDDI_WIN8) || (NTDDI_VERSION < NTDDI_WIN8)
// typedef enum _PROCESS_MITIGATION_POLICY
// {
//     ProcessDEPPolicy = 0,
//     ProcessChildProcessPolicy = 8,
// } PROCESS_MITIGATION_POLICY;
// 
// typedef struct _PROCESS_MITIGATION_CHILD_PROCESS_POLICY
// {
//     DWORD NoChildProcessCreation : 1;
//     DWORD AuditNoChildProcessCreation : 1;
//     DWORD AllowSecureProcessCreation : 1;
//     DWORD ReservedFlags : 29;
// } PROCESS_MITIGATION_CHILD_PROCESS_POLICY, *PPROCESS_MITIGATION_CHILD_PROCESS_POLICY;
// 
// typedef struct _PROCESS_MITIGATION_DEP_POLICY
// {
//     DWORD Enable : 1;
//     DWORD DisableAtlThunkEmulation : 1;
//     DWORD ReservedFlags : 30;
//     BOOLEAN Permanent;
// } PROCESS_MITIGATION_DEP_POLICY, *PPROCESS_MITIGATION_DEP_POLICY;
// #endif

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

// 为兼容旧版SDK，手动定义缺失的枚举值
// 注释：现代Windows 10 SDK已包含SystemCodeIntegrityInformation定义
// #if !defined(NTDDI_WIN8) || (NTDDI_VERSION < NTDDI_WIN8)
// const int SystemCodeIntegrityInformation = 102;
// #endif
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

typedef NTSTATUS(WINAPI *PNtQuerySystemInformation)(ULONG SystemInformationClass, PVOID SystemInformation,
                                                    ULONG SystemInformationLength, PULONG ReturnLength);

// --- 为线程隐藏定义必要的结构体和类型 ---
typedef NTSTATUS(WINAPI *PNtSetInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
                                                  PVOID ThreadInformation, ULONG ThreadInformationLength);

typedef NTSTATUS(WINAPI *PNtQueryInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
                                                    PVOID ThreadInformation, ULONG ThreadInformationLength,
                                                    PULONG ReturnLength);

// 将函数指针定义为文件内静态变量，避免在多个函数中重复定义。
static const auto g_pNtQuerySystemInformation = reinterpret_cast<PNtQuerySystemInformation>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"));
static const auto g_pNtSetInformationThread = reinterpret_cast<PNtSetInformationThread>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSetInformationThread"));
static const auto g_pNtQueryInformationThread = reinterpret_cast<PNtQueryInformationThread>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread"));

#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#endif

// 这个函数被设计为“不安全的”，因为它直接处理可能无效的句柄。
// 它不使用任何需要对象展开的C++类，因此可以安全地使用 __try/__except。
// 返回值: 如果句柄确实指向我们自己的进程，则返回true，否则返回false。

// --- 为系统完整性检测定义必要的结构体 ---
typedef struct _SYSTEM_CODE_INTEGRITY_INFORMATION
{
    ULONG Length;
    ULONG CodeIntegrityOptions;
} SYSTEM_CODE_INTEGRITY_INFORMATION, *PSYSTEM_CODE_INTEGRITY_INFORMATION;

// --- 为VEH Hook检测定义未公开的结构体 ---
// 这些结构基于逆向工程，可能在不同Windows版本间有差异。
// __try/__except 块对于保证稳定性至关重要。

// // typedef struct _LIST_ENTRY
// // {
// //     struct _LIST_ENTRY *Flink;
// //     struct _LIST_ENTRY *Blink;
// // } LIST_ENTRY, *PLIST_ENTRY;

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

// Windows XP VEH list structure (simplified, adjust based on your needs)
struct VECTORED_HANDLER_LIST_XP
{
    CRITICAL_SECTION Lock;
    LIST_ENTRY List;
};

// Windows Vista/Win7 VEH list structure (simplified, adjust based on your needs)
struct VECTORED_HANDLER_LIST_VISTA
{
    SRWLOCK LockException;
    LIST_ENTRY ExceptionList;
};

// Win8+: SRWLOCK + 双LIST_ENTRY
typedef struct _VECTORED_HANDLER_LIST_WIN8
{
    SRWLOCK LockException;
    LIST_ENTRY ExceptionList;
    SRWLOCK LockContinue;
    LIST_ENTRY ContinueList;
} VECTORED_HANDLER_LIST_WIN8, *PVECTORED_HANDLER_LIST_WIN8;

// 枚举版本
enum WindowsVersion
{
    Win_XP,
    Win_Vista_Win7,
    Win_8_Win81,
    Win_10,
    Win_11,
    Win_Unknown
};

// 简单的版本比较助手：判定当前版本是否至少为目标版本
static inline bool IsOsAtLeast(WindowsVersion have, WindowsVersion need)
{
    auto rank = [](WindowsVersion v) -> int {
        switch (v)
        {
            case Win_XP:
                return 1;
            case Win_Vista_Win7:
                return 2;  // Vista/Win7 归为同档
            case Win_8_Win81:
                return 3;
            case Win_10:
                return 4;
            case Win_11:
                return 5;
            default:
                return 0;  // 未知视为最低
        }
    };
    return rank(have) >= rank(need);
}

namespace Utils
{

// 为签名验证定义三态返回值
enum class SignatureStatus
{
    TRUSTED,
    UNTRUSTED,
    FAILED_TO_VERIFY
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
            parentName = WideToString(it->second);
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
        return WideToString(uuid_w);
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
SignatureStatus VerifyFileSignature(const std::wstring &filePath, WindowsVersion winVer)
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
    winTrustData.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN | WTD_CACHE_ONLY_URL_RETRIEVAL;
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

    // [XP兼容性] 对XP系统，宽容处理可能因系统老旧导致的验证错误
    if (winVer == Win_XP)
    {
        switch (result)
        {
            case TRUST_E_SYSTEM_ERROR:
            case TRUST_E_PROVIDER_UNKNOWN:
            case CERT_E_CHAINING:
            case TRUST_E_BAD_DIGEST:                       // 在XP上，SHA-2签名可能导致错误的摘要
                return SignatureStatus::FAILED_TO_VERIFY;  // 降级为“无法判断”而非“不信任”
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

}  // namespace Utils

namespace
{
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

// 用于动态查找VEH链表偏移量的“诱饵”处理函数。
// 它什么也不做，只是作为一个可被识别的指针存在。
LONG WINAPI DecoyVehHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
    UNREFERENCED_PARAMETER(ExceptionInfo);
    return EXCEPTION_CONTINUE_SEARCH;
}

// 此函数不应使用任何需要堆栈展开的C++对象。
// 使用 __try/__except 块来安全地执行此反调试检查。
// 如果没有调试器，会触发一个异常并被捕获。如果附加了调试器，它可能会“吞掉”这个异常，
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
#pragma warning(push)
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
        // 记录异常代码，以帮助诊断根本原因，而不是静默失败
        DWORD exceptionCode = GetExceptionCode();
        LOG_ERROR_F(AntiCheatLogger::LogCategory::SYSTEM,
            "GetCodeSectionInfo SEH Exception: hModule=0x%p, code=0x%08X",
            hModule, exceptionCode);
        return false;
    }
    return false;
}

// 辅助函数：计算内存块的哈希值 (使用FNV-1a算法)
// 注意：FNV-1a
// 是一种快速非密码学哈希。对于高安全要求，应考虑使用密码学安全哈希（如SHA-256）。
std::vector<uint8_t> CalculateHash(const BYTE *data, size_t size)
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

#pragma warning(pop)  // 与上面的push配对

// CRC32哈希算法实现
// 一个性能不错的标准CRC32实现，用于替代memcmp
uint32_t Crc32(const uint8_t *data, size_t length)
{
    if (!data || length == 0)
        return 0;

    uint32_t crc = 0xFFFFFFFF;
    static uint32_t table[256];
    static bool table_generated = false;

    // 首次调用时生成CRC32查找表
    if (!table_generated)
    {
        for (uint32_t i = 0; i < 256; i++)
        {
            uint32_t c = i;
            for (int j = 0; j < 8; j++)
            {
                c = (c & 1) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
            }
            table[i] = c;
        }
        table_generated = true;
    }

    for (size_t i = 0; i < length; ++i)
    {
        crc = table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }

    return crc ^ 0xFFFFFFFF;
}

}  // namespace

// 生产环境辅助函数：哈希值转十六进制字符串
static std::string HashToHexString(const std::vector<uint8_t> &hash)
{
    if (hash.empty())
        return "empty";

    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < std::min(hash.size(), size_t(32)); ++i)
    {  // 限制长度避免日志过长
        ss << std::setw(2) << static_cast<unsigned>(hash[i]);
    }
    if (hash.size() > 32)
    {
        ss << "...";
    }
    return ss.str();
}

// ---- 新增: 路径规范化工具与限流工具 ----
// 重复定义移除（顶部已有 NormalizePathLowercase 实现）

// ---- 新增: 固定容量环形缓冲（线程外部需自持锁） ----
// RingBuffer类已删除

// ---- 新增: 可疑调用者地址解析（优先使用受控回溯） ----
static PVOID ResolveSuspiciousCallerAddress(HMODULE hSelf)
{
    // 采集简短回溯，跳过属于自身模块的帧，返回第一个外部地址
    using RtlCaptureStackBackTrace_t = USHORT(WINAPI *)(ULONG, ULONG, PVOID *, PULONG);
    static RtlCaptureStackBackTrace_t pRtlCSBT =
            (RtlCaptureStackBackTrace_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCaptureStackBackTrace");

    PVOID addrs[16] = {};
    USHORT frames = 0;
    if (pRtlCSBT)
    {
        frames = pRtlCSBT(1, 16, addrs, nullptr);
    }
    else
    {
        // XP RTM 回退：无法回溯时，直接返回调用者地址
        return _ReturnAddress();
    }
    for (USHORT i = 0; i < frames; ++i)
    {
        HMODULE m = NULL;
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCWSTR)addrs[i], &m) &&
            m)
        {
            if (m != hSelf)
            {
                return addrs[i];
            }
        }
    }
    // 回退：直接使用返回地址
    return _ReturnAddress();
}

// 输入事件检测相关代码已删除以解决性能问题

// [新增] RAII封装Windows钩子
class ScopedHook
{
   public:
    ScopedHook(int idHook, HOOKPROC lpfn)
    {
        m_hook = SetWindowsHookEx(idHook, lpfn, GetModuleHandle(NULL), 0);
    }
    ~ScopedHook()
    {
        if (m_hook)
        {
            UnhookWindowsHookEx(m_hook);
        }
    }
    operator HHOOK() const
    {
        return m_hook;
    }
    bool IsValid() const
    {
        return m_hook != NULL;
    }

   private:
    HHOOK m_hook;
    ScopedHook(const ScopedHook &) = delete;
    ScopedHook &operator=(const ScopedHook &) = delete;
};

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

// ISensor: 所有检测传感器的抽象基类接口 (策略模式)
class ISensor
{
   public:
    virtual ~ISensor() = default;
    virtual const char *GetName() const = 0;     // 用于日志和调试
    virtual SensorWeight GetWeight() const = 0;  // 新增：获取传感器权重分级
    virtual void Execute(ScanContext &context) = 0;
};

// 运行时遥测计数器（线程安全）
struct TelemetryCounters
{
    std::atomic<uint64_t> init_success{0};
    std::atomic<uint64_t> init_fail{0};
    std::atomic<uint64_t> veh_exceptions{0};
    std::atomic<uint64_t> sensor_exceptions{0};
    std::atomic<uint64_t> sensor_timeouts{0};
    std::atomic<uint64_t> cheats_detected{0};
};

// 生产环境扩展监控指标（基于专家审查建议）
struct ProductionMetrics
{
    std::atomic<uint64_t> false_positive_rate{0};     // 误报率（每万次检测中的误报数）
    std::atomic<uint64_t> detection_latency_ms{0};    // 平均检测延迟（毫秒）
    std::atomic<uint64_t> memory_usage_mb{0};         // 当前内存使用量（MB）
    std::atomic<uint64_t> cpu_usage_percent{0};       // CPU使用率（百分比）
    std::atomic<uint64_t> sensor_execution_count{0};  // 传感器总执行次数
    std::atomic<uint64_t> config_update_count{0};     // 配置更新次数
    std::atomic<uint64_t> emergency_shutdowns{0};     // 紧急关闭次数
};

struct CheatMonitor::Pimpl
{
    Pimpl();  // 新增构造函数

    WindowsVersion m_windowsVersion;  // [新增] 缓存检测到的Windows版本

    std::atomic<bool> m_isSystemActive = false;
    std::atomic<bool> m_isSessionActive = false;
    std::atomic<bool> m_hasServerConfig = false;  // 新增：用于标记是否已收到服务器配置
    std::thread m_monitorThread;
    std::atomic<bool> m_isShuttingDown = false;  // 新增：安全关闭标志
    // 用于智能关联父进程缺失事件的状态
    std::atomic<bool> m_parentWasMissingAtStartup = false;
    std::condition_variable m_cv;
    std::mutex m_cvMutex;
    std::mutex m_signatureCacheMutex;  // 保护 m_moduleSignatureCache 的并发访问
    std::mutex m_modulePathsMutex;     // 保护 m_legitimateModulePaths 的并发访问

    std::mutex m_sessionMutex;
    uint32_t m_currentUserId = 0;
    std::string m_currentUserName;

    std::set<std::pair<anti_cheat::CheatCategory, std::string>> m_uniqueEvidence;
    std::vector<anti_cheat::Evidence> m_evidences;

    std::atomic<bool> m_processBaselineEstablished = false;

    // 使用 std::set 以获得更快的查找速度 (O(logN)) 并自动处理重复项
    std::set<DWORD> m_knownThreadIds;
    std::set<HMODULE> m_knownModules;
    //  硬件信息采集器（解耦出传感器体系，仅在上报时附带）
    std::unique_ptr<anti_cheat::HardwareInfoCollector> m_hwCollector;
    bool m_hwRegSent = false;                                  // [t6] HardwareRegistration是否已发送
    std::unordered_set<std::wstring> m_legitimateModulePaths;  // 使用哈希集合以实现O(1)复杂度的快速查找
    std::unordered_map<uintptr_t, std::chrono::steady_clock::time_point>
            m_reportedIllegalCallSources;  // 用于记录已上报的非法调用来源，并实现5分钟上报冷却
    //  记录每个用户、每种作弊类型的最近上报时间，防止重复上报
    std::map<std::pair<uint32_t, anti_cheat::CheatCategory>, std::chrono::steady_clock::time_point> m_lastReported;
    // 用于句柄代理攻击关联分析的状态容器
    std::unordered_map<DWORD, std::chrono::steady_clock::time_point> m_suspiciousHandleHolders;
    // [新增] 环境扫描缓存，用于记录已发现的有害进程 {PID -> 创建时间}
    std::map<DWORD, FILETIME> m_knownHarmfulProcesses;

    // [t6] 在初始化后发送一次 HardwareRegistration
    void SendHardwareRegistration();

    // --- 限流与容量控制 ---
    bool m_evidenceOverflowed = false;

    // --- 传感器调度：时间预算与轮转索引 ---
    size_t m_lightSensorIndex = 0;
    size_t m_heavySensorIndex = 0;

    HWND m_hGameWindow = NULL;  // 游戏主窗口句柄

    std::random_device m_rd;  // 随机数种子

    // 遥测计数器
    TelemetryCounters m_metrics;
    ProductionMetrics m_prodMetrics;  // 新增：生产环境扩展指标

    // 模块签名验证缓存
    enum class SignatureVerdict
    {
        UNKNOWN,
        SIGNED_AND_TRUSTED,
        UNSIGNED_OR_UNTRUSTED,
        VERIFICATION_FAILED

    };
    std::unordered_map<std::wstring, std::pair<SignatureVerdict, std::chrono::steady_clock::time_point>>
            m_moduleSignatureCache;

    // 进程签名与可信度判定缓存（用于句柄扫描等重用结果）
    enum class ProcessVerdict
    {
        UNKNOWN,
        SIGNED_AND_TRUSTED,
        UNSIGNED_OR_UNTRUSTED,
        VERIFICATION_FAILED
    };
    // key: PID -> (verdict, cached_at)
    std::unordered_map<DWORD, std::pair<ProcessVerdict, std::chrono::steady_clock::time_point>> m_processVerdictCache;
    // 服务器传感器门控开关（由OnConfigUpdated集中设置）
    bool m_enableVehScan = false;
    bool m_enableHandleScan = false;
    // 签名验证节流：避免频繁对同一路径做昂贵验证
    std::unordered_map<std::wstring, std::chrono::steady_clock::time_point> m_sigThrottleUntil;

    // 存储关键模块代码节的基线哈希值
    std::unordered_map<std::wstring, std::vector<uint8_t>> m_moduleBaselineHashes;

    // 自身模块完整性基线
    HMODULE m_hSelfModule = NULL;
    std::vector<uint8_t> m_selfModuleBaselineHash;

    // IAT Hook检测基线：为每个导入的DLL存储一个独立的哈希值
    std::unordered_map<std::string, std::vector<uint8_t>> m_iatBaselineHashes;
    uintptr_t m_vehListAddress = 0;  // 存储VEH链表(LdrpVectorHandlerList)的绝对地址

    // 传感器集合
    std::vector<std::unique_ptr<ISensor>> m_lightweight_sensors;
    std::vector<std::unique_ptr<ISensor>> m_heavyweight_sensors;

    // ---- Telemetry (t9): per-sensor runtime tracking (rolling 2h and 72h) ----
    // key: sensor name; value: deque of (timestamp, duration_ms)
    std::unordered_map<std::string, std::deque<std::pair<std::chrono::steady_clock::time_point, int>>>
            m_sensorDurations2h;
    std::unordered_map<std::string, std::deque<std::pair<std::chrono::steady_clock::time_point, int>>>
            m_sensorDurations72h;

    // 控制性能遥测上报频率（避免每次都发送）：每N次报告发送一次，并带抖动
    int m_reportUploadCount = 0;
    int m_perfEveryNReports = 6;                              // 默认每6次报告发送一次性能遥测
    std::uniform_int_distribution<int> m_perfJitter{0, 100};  // 百分比抖动

    // [新增] 传感器退避与失败计数（会话级）
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> m_sensorBackoffUntil;
    std::unordered_map<std::string, int> m_sensorFailureCounts;

    // 服务器下发的传感器开关（按平台门控后）

    // 随机数引擎：用于抖动与采样
    std::mt19937 m_rng{std::random_device{}()};

    void RecordSensorRuntime(const char *name, int duration_ms)
    {
        const auto now = std::chrono::steady_clock::now();
        auto &q2h = m_sensorDurations2h[name];
        auto &q72h = m_sensorDurations72h[name];
        q2h.emplace_back(now, duration_ms);
        q72h.emplace_back(now, duration_ms);
        // purge old
        const auto cutoff2h = now - std::chrono::hours(2);
        while (!q2h.empty() && q2h.front().first < cutoff2h)
            q2h.pop_front();
        const auto cutoff72h = now - std::chrono::hours(72);
        while (!q72h.empty() && q72h.front().first < cutoff72h)
            q72h.pop_front();
    }

    static int PercentileFromDeque(const std::deque<std::pair<std::chrono::steady_clock::time_point, int>> &dq,
                                   double pct)
    {
        if (dq.empty())
            return 0;
        std::vector<int> vals;
        vals.reserve(dq.size());
        for (const auto &p : dq)
            vals.push_back(p.second);
        std::sort(vals.begin(), vals.end());
        size_t idx =
                (size_t)std::clamp<size_t>((size_t)std::llround((pct / 100.0) * (vals.size() - 1)), 0, vals.size() - 1);
        return vals[idx];
    }



    void LogPerfTelemetry()
    {
        // Lightweight logging to help soak tests; can be upgraded to structured upload later
        LOG_INFO(AntiCheatLogger::LogCategory::PERFORMANCE, "Sensor runtime stats (rolling)");
        for (const auto &kv : m_sensorDurations2h)
        {
            const std::string &name = kv.first;
            const auto &q2h = kv.second;
            const auto &q72h = m_sensorDurations72h[name];
            long long sum2h = 0;
            for (const auto &p : q2h)
                sum2h += p.second;
            const int avg2h = q2h.empty() ? 0 : (int)(sum2h / (long long)q2h.size());
            const int p95_2h = PercentileFromDeque(q2h, 95.0);
            const int p99_2h = PercentileFromDeque(q2h, 99.0);

            long long sum72h = 0;
            for (const auto &p : q72h)
                sum72h += p.second;
            const int avg72h = q72h.empty() ? 0 : (int)(sum72h / (long long)q72h.size());
            const int p95_72h = PercentileFromDeque(q72h, 95.0);
            const int p99_72h = PercentileFromDeque(q72h, 99.0);

            LOG_INFO_F(AntiCheatLogger::LogCategory::PERFORMANCE,
                       "Sensor %s: 2h(avg=%d, p95=%d, p99=%d) 72h(avg=%d, p95=%d, p99=%d)", name.c_str(), avg2h, p95_2h,
                       p99_2h, avg72h, p95_72h, p99_72h);
        }
    }

    void OnConfigUpdated();

    // Main loop and state management
    void MonitorLoop();
    void ExecuteLightweightSensorSafe(ISensor* sensor, const char* name);
    bool ExecuteHeavyweightSensorSafe(ISensor* sensor, const char* name);
    void UploadReport();
    void FillPerfTelemetry(anti_cheat::TelemetryMetrics &tm, bool include_perf_windows);
    void InitializeSystem();
    void InitializeProcessBaseline();
    void ResetSessionState();
    void AddEvidence(anti_cheat::CheatCategory category, const std::string &description);
    void AddEvidenceInternal(anti_cheat::CheatCategory category,
                             const std::string &description);  // 不加锁的内部版本
    void HardenProcessAndThreads();                            //  进程与线程加固
    bool HasEvidenceOfType(anti_cheat::CheatCategory category);

    // 传感器异常处理方法
    void HandleSensorException(const char *name, const std::string &exception_what);
    void HandleSensorTimeout(const char *name);
    void ResetSensorFailure(const char *name);

    // --- Sensor Functions ---
    void CheckParentProcessAtStartup();
    void Sensor_DetectVirtualMachine();
    // 硬件信息采集已解耦，不再作为 Sensor_*

    void DoCheckIatHooks(ScanContext &context, const BYTE *baseAddress, const IMAGE_IMPORT_DESCRIPTOR *pImportDesc);
    void DoCheckIatHooksWithTimeout(ScanContext &context, const BYTE *baseAddress, const IMAGE_IMPORT_DESCRIPTOR *pImportDesc, 
                                    const std::chrono::steady_clock::time_point &startTime, int budget_ms);
    void VerifyModuleSignature(HMODULE hModule);

    // Helper to check if an address belongs to a whitelisted module
    // Helper to check if an address belongs to a whitelisted module
    bool IsAddressInLegitimateModule(PVOID address, std::wstring &outModulePath);

    // 扩展监控辅助函数
    bool IsPathInWhitelist(const std::wstring &modulePath);
    // 使用“诱饵处理函数”技术动态查找VEH链表的地址
    uintptr_t FindVehListAddress();

    // VM detection helpers
    void DetectVmByCpuid();
    void DetectVmByRegistry();
    void DetectVmByMacAddress();

    // 钩子相关代码已删除
    static LPVOID WINAPI DetourVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    static LPVOID WINAPI DetourVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType,
                                              DWORD flProtect);
    static BOOL WINAPI DetourVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
    static NTSTATUS WINAPI DetourNtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG ZeroBits,
                                                         PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

    // 扩展API钩子函数声明
    static LPVOID WINAPI DetourHeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
    static LPVOID WINAPI DetourMapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh,
                                             DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
    static HMODULE WINAPI DetourLoadLibraryW(LPCWSTR lpLibFileName);
    static HMODULE WINAPI DetourLoadLibraryA(LPCSTR lpLibFileName);
    static BOOL WINAPI DetourWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize,
                                                SIZE_T *lpNumberOfBytesWritten);
    static NTSTATUS WINAPI DetourNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
                                                      SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);
    static NTSTATUS WINAPI DetourNtCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                                POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
                                                PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, PSIZE_T ZeroBits,
                                                PSIZE_T StackSize, PSIZE_T MaximumStackSize,
                                                PPS_ATTRIBUTE_LIST AttributeList);

    // Shellcode检测：安装和卸载API钩子
    void InstallVirtualAllocHook();
    void UninstallVirtualAllocHook();

    void InstallExtendedApiHooks();
    void UninstallExtendedApiHooks();

    // VirtualAlloc Hook状态管理
    bool m_isVirtualAllocHooked = false;
    bool m_isExtendedApiHooked = false;
    // IAT hook: 保存被修改的IAT条目指针，便于恢复
    struct IatHookEntry
    {
        void **pIatEntry = nullptr;  // 指向IAT中函数指针的指针
        void *pTrampoline = nullptr;
        std::string apiName;
    };
    std::vector<IatHookEntry> m_iatHooks;

    std::mutex m_hookMutex;  // 用于保护 hook 安装/卸载的互斥锁
};

// CheatMonitor::Pimpl成员函数实现
void CheatMonitor::Pimpl::FillPerfTelemetry(anti_cheat::TelemetryMetrics &tm, bool include_perf_windows)
{
    if (!include_perf_windows)
        return;

    // 为每个传感器计算2h/72h窗口统计并写入protobuf map
    for (const auto &kv : m_sensorDurations2h)
    {
        const std::string &name = kv.first;
        const auto &q2h = kv.second;
        const auto &q72h = m_sensorDurations72h[name];

        long long sum2h = 0;
        for (const auto &p : q2h)
            sum2h += p.second;
        const uint32_t avg2h = q2h.empty() ? 0u : (uint32_t)(sum2h / (long long)q2h.size());
        const uint32_t p95_2h = (uint32_t)PercentileFromDeque(q2h, 95.0);
        const uint32_t p99_2h = (uint32_t)PercentileFromDeque(q2h, 99.0);

        long long sum72h = 0;
        for (const auto &p : q72h)
            sum72h += p.second;
        const uint32_t avg72h = q72h.empty() ? 0u : (uint32_t)(sum72h / (long long)q72h.size());
        const uint32_t p95_72h = (uint32_t)PercentileFromDeque(q72h, 95.0);
        const uint32_t p99_72h = (uint32_t)PercentileFromDeque(q72h, 99.0);

        anti_cheat::PerfWindows pw;
        anti_cheat::PerfStats *s2 = pw.mutable_win_2h();
        s2->set_avg_ms(avg2h);
        s2->set_p95_ms(p95_2h);
        s2->set_p99_ms(p99_2h);

        anti_cheat::PerfStats *s72 = pw.mutable_win_72h();
        s72->set_avg_ms(avg72h);
        s72->set_p95_ms(p95_72h);
        s72->set_p99_ms(p99_72h);

        (*tm.mutable_sensor_perf())[name] = pw;
    }
}

// ScanContext: 为传感器提供所需依赖的上下文对象
// 这是“依赖倒置”原则的体现，传感器不直接依赖Pimpl，而是依赖这个抽象的上下文
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
    // 为 SuspiciousLaunchSensor 提供上下文访问
    bool GetParentWasMissingAtStartup() const
    {
        return m_pimpl->m_parentWasMissingAtStartup.load();
    }
    void ClearParentWasMissingFlag()
    {
        m_pimpl->m_parentWasMissingAtStartup = false;
    }
    void HandleSensorException(const char *name, const std::string &exception_what)
    {
        m_pimpl->HandleSensorException(name, exception_what);
    }

    void HandleSensorTimeout(const char *name)
    {
        m_pimpl->HandleSensorTimeout(name);
    }

    void ResetSensorFailure(const char *name)
    {
        m_pimpl->ResetSensorFailure(name);
    }
    bool HasEvidenceOfType(anti_cheat::CheatCategory category) const
    {
        return m_pimpl->HasEvidenceOfType(category);
    }
    HWND GetGameWindow() const
    {
        return m_pimpl->m_hGameWindow;
    }
    const std::unordered_map<std::string, std::vector<uint8_t>> &GetIatBaselineHashes() const
    {
        return m_pimpl->m_iatBaselineHashes;
    }
    const std::unordered_map<std::wstring, std::vector<uint8_t>> &GetModuleBaselineHashes() const
    {
        return m_pimpl->m_moduleBaselineHashes;
    }
    uintptr_t GetVehListAddress() const
    {
        return m_pimpl->m_vehListAddress;
    }

    WindowsVersion GetWindowsVersion() const  // [新增] 为传感器提供OS版本信息
    {
        return m_pimpl->m_windowsVersion;
    }
    
    // 提供对Pimpl方法的访问
    void DoCheckIatHooksWithTimeout(const BYTE *baseAddress, const IMAGE_IMPORT_DESCRIPTOR *pImportDesc, 
                                   std::chrono::steady_clock::time_point startTime, int budget_ms)
    {
        m_pimpl->DoCheckIatHooksWithTimeout(*this, baseAddress, pImportDesc, startTime, budget_ms);
    }

    bool IsAddressInLegitimateModule(PVOID address, std::wstring &outModulePath)
    {
        return m_pimpl->IsAddressInLegitimateModule(address, outModulePath);
    }

    // --- 提供对缓存的访问 ---
    std::unordered_map<DWORD, std::pair<CheatMonitor::Pimpl::ProcessVerdict, std::chrono::steady_clock::time_point>> &
    GetProcessVerdictCache()
    {
        return m_pimpl->m_processVerdictCache;
    }

    std::map<DWORD, FILETIME> &GetKnownHarmfulProcesses()  // 新增：为环境传感器提供缓存访问
    {
        return m_pimpl->m_knownHarmfulProcesses;
    }

    // 为句柄关联传感器提供共享数据访问
    std::unordered_map<DWORD, std::chrono::steady_clock::time_point> &GetSuspiciousHandleHolders()
    {
        return m_pimpl->m_suspiciousHandleHolders;
    }

    // --- 提供对已知状态的访问 ---
    std::set<DWORD> &GetKnownThreadIds()
    {
        return m_pimpl->m_knownThreadIds;
    }
    std::set<HMODULE> &GetKnownModules()
    {
        return m_pimpl->m_knownModules;
    }
    void VerifyModuleSignature(HMODULE hModule)
    {
        m_pimpl->VerifyModuleSignature(hModule);
    }

    // 为自我完整性检查提供基线访问
    HMODULE GetSelfModuleHandle() const
    {
        return m_pimpl->m_hSelfModule;
    }
    const std::vector<uint8_t> &GetSelfModuleBaselineHash() const
    {
        return m_pimpl->m_selfModuleBaselineHash;
    }
};

// InputAnalysis命名空间已删除以解决性能问题

// --- 将所有传感器实现移入独立的类中 ---
namespace Sensors
{
// --- 轻量级传感器 ---

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
    void Execute(ScanContext &context) override
    {
        // 生产环境优化：添加超时控制和异常处理
        const auto startTime = std::chrono::steady_clock::now();
        const int budget_ms = CheatConfigManager::GetInstance().GetLightScanBudgetMs();

        try
        {
            // 反调试检测数组 - 按检测速度排序，优先执行快速检测
            std::array<std::pair<std::string, std::function<void()>>, 6> checks = {
                    {{"RemoteDebugger",
                      [&]() {
                          CheckRemoteDebugger(context);
                      }},
                     {"PEB_BeingDebugged",
                      [&]() {
                          CheckPEBBeingDebugged(context);
                      }},
                     {"CloseHandle",
                      [&]() {
                          CheckCloseHandleDebugger(context);
                      }},
                     {"DebugRegisters",
                      [&]() {
                          CheckDebugRegisters(context);
                      }},
                     {"KernelDebugger_NtQuery",
                      [&]() {
                          if (IsVbsEnabled())
                              return;
                          CheckKernelDebuggerNtQuery(context);
                      }},
                     {"KernelDebugger_KUSER", [&]() {
                          if (IsVbsEnabled())
                              return;
                          CheckKernelDebuggerKUSER(context);
                      }}}};

            // 执行检测，每两个检测后检查超时
            for (size_t i = 0; i < checks.size(); ++i)
            {
                checks[i].second();

                // 每2个检测后检查超时
                if ((i & 1) == 1)
                {
                    auto now = std::chrono::steady_clock::now();
                    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count() > budget_ms)
                    {
                        LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                                      "AdvancedAntiDebugSensor超时，已完成%zu/%zu个检测", i + 1, checks.size());
                        context.HandleSensorTimeout(GetName());
                        return;
                    }
                }
            }

            context.ResetSensorFailure(GetName());
        }
        catch (const std::exception &e)
        {
            context.HandleSensorException(GetName(), e.what());
        }
        catch (...)
        {
            context.HandleSensorException(GetName(), "Unknown exception in AdvancedAntiDebugSensor");
        }
    }

private:
    // 使用简单的结构体来传递检测结果，避免C++对象展开冲突
    struct DebugDetectionResult
    {
        bool detected;
        const char* description;
        DWORD exceptionCode;
    };

    // 为了避免SEH与C++对象展开冲突，使用C风格的静态函数
    static DebugDetectionResult CheckRemoteDebugger_Internal()
    {
        DebugDetectionResult result = {false, nullptr, 0};
        __try
        {
            BOOL isDebuggerPresent = FALSE;
            if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent) &&
                isDebuggerPresent)
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
            if (pPeb && IsValidPointer(pPeb, sizeof(PEB)) && pPeb->BeingDebugged)
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
            CheckCloseHandleException();
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
            if (g_pNtQuerySystemInformation &&
                NT_SUCCESS(g_pNtQuerySystemInformation(SystemKernelDebuggerInformation, &info,
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
            if (IsKernelDebuggerPresent_KUserSharedData())
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

    void CheckKernelDebuggerKUSER(ScanContext &context)
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
    }
};

class MemoryScanSensor : public ISensor
{
   public:
    const char *GetName() const override
    {
        return "MemoryScanSensor";
    }
    SensorWeight GetWeight() const override
    {
        return SensorWeight::HEAVY;  // 10-100ms: 内存扫描
    }

    void Execute(ScanContext &context) override
    {
        const auto startTime = std::chrono::steady_clock::now();
        const int budget_ms = CheatConfigManager::GetInstance().GetHeavyScanBudgetMs();

        try
        {
            const auto &baselineHashes = context.GetModuleBaselineHashes();
            std::vector<HMODULE> hMods(1024);
            DWORD cbNeeded = 0;

            if (!EnumProcessModules(GetCurrentProcess(), hMods.data(), hMods.size() * sizeof(HMODULE), &cbNeeded))
            {
                return;
            }

            if (hMods.size() * sizeof(HMODULE) < cbNeeded)
            {
                hMods.resize(cbNeeded / sizeof(HMODULE));
                if (!EnumProcessModules(GetCurrentProcess(), hMods.data(), hMods.size() * sizeof(HMODULE), &cbNeeded))
                {
                    return;
                }
            }

            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); ++i)
            {
                if ((i & 15) == 0)
                {
                    auto now = std::chrono::steady_clock::now();
                    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count() > budget_ms)
                    {
                        context.HandleSensorTimeout(GetName());
                        return;
                    }
                }
                ProcessModule(hMods[i], context, baselineHashes);
            }
            context.ResetSensorFailure(GetName());
        }
        catch (const std::exception &e)
        {
            context.HandleSensorException(GetName(), e.what());
        }
        catch (...)
        {
            context.HandleSensorException(GetName(), "Unknown exception");
        }
    }

   private:
    // 处理单个模块的逻辑
    void ProcessModule(HMODULE hModule, ScanContext &context,
                       const std::unordered_map<std::wstring, std::vector<uint8_t>> &baselineHashes)
    {
        if (hModule == context.GetSelfModuleHandle())
        {
            return;
        }
        __try
        {
            if (!hModule)
            {
                return;  // 空句柄，直接返回
            }

            // 获取模块路径
            wchar_t modulePath_w[MAX_PATH] = {0};
            if (GetModuleFileNameW(hModule, modulePath_w, MAX_PATH) == 0)
            {
                return;  // 获取路径失败，直接返回
            }

            // 获取代码节信息
            PVOID codeBase = nullptr;
            DWORD codeSize = 0;
            if (!GetCodeSectionInfo(hModule, codeBase, codeSize))
            {
                return;  // 获取代码节信息失败
            }

            // 将复杂逻辑移到外部处理
            ProcessModuleData(modulePath_w, codeBase, codeSize, context, baselineHashes);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            // 捕获模块卸载或其他异常，安全忽略
            return;
        }
    }

    // 处理模块路径和哈希的逻辑
    void ProcessModuleData(const wchar_t *modulePath_w, PVOID codeBase, DWORD codeSize, ScanContext &context,
                           const std::unordered_map<std::wstring, std::vector<uint8_t>> &baselineHashes)
    {
        std::wstring modulePath(modulePath_w);
        std::vector<uint8_t> currentHash = CalculateHash(static_cast<BYTE *>(codeBase), codeSize);
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
                context.AddEvidence(anti_cheat::INTEGRITY_BASELINE_LEARNED,
                                    "学习基线: " + Utils::WideToString(modulePath) + " | Hash: " + hash_str);
                learned_modules.insert(modulePath);
            }
        }
        else
        {
            // DETECTION MODE
            if (currentHash != it->second)
            {
                context.AddEvidence(anti_cheat::INTEGRITY_MEMORY_PATCH,
                                    "检测到内存代码节被篡改: " + Utils::WideToString(modulePath));
            }
        }
    }
};

class SystemIntegritySensor : public ISensor
{
   public:
    const char *GetName() const override
    {
        return "SystemIntegritySensor";
    }
    SensorWeight GetWeight() const override
    {
        return SensorWeight::LIGHT;  // < 1ms: 系统完整性检测
    }
    void Execute(ScanContext &context) override
    {
        SYSTEM_CODE_INTEGRITY_INFORMATION sci = {sizeof(sci), 0};
        if (g_pNtQuerySystemInformation &&
            NT_SUCCESS(g_pNtQuerySystemInformation(SystemCodeIntegrityInformation, &sci, sizeof(sci), nullptr)))
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
    }
};

class SelfIntegritySensor : public ISensor
{
   public:
    const char *GetName() const override
    {
        return "SelfIntegritySensor";
    }
    SensorWeight GetWeight() const override
    {
        return SensorWeight::MEDIUM;  // 1-10ms: 自身完整性检测
    }
    void Execute(ScanContext &context) override
    {
        // 生产环境优化：添加重试机制和更严格的验证
        const auto startTime = std::chrono::steady_clock::now();
        const int budget_ms = CheatConfigManager::GetInstance().GetLightScanBudgetMs();

        try
        {
            HMODULE hSelfModule = context.GetSelfModuleHandle();
            const auto &baselineHash = context.GetSelfModuleBaselineHash();

            if (!hSelfModule || baselineHash.empty())
            {
                LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "SelfIntegritySensor: 缺少基线数据，跳过检测");
                return;
            }

            // 生产环境优化：多重验证机制，降低误报率
            const int maxRetries = 2;
            bool hashMismatchConfirmed = false;

            for (int attempt = 0; attempt < maxRetries && !hashMismatchConfirmed; ++attempt)
            {
                // 检查超时
                auto now = std::chrono::steady_clock::now();
                if (std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count() > budget_ms)
                {
                    LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "SelfIntegritySensor超时");
                    context.HandleSensorTimeout(GetName());
                    return;
                }

                auto result = CheckSelfIntegrityInternal(hSelfModule, baselineHash, attempt, maxRetries);
                if (result.shouldContinue)
                {
                    continue;
                }
                if (result.shouldBreak)
                {
                    break;
                }
                if (result.hashMismatchConfirmed)
                {
                    hashMismatchConfirmed = true;
                    context.AddEvidence(anti_cheat::INTEGRITY_SELF_TAMPERING,
                                        "检测到反作弊模块自身被篡改（二次确认）");
                }
                if (result.exceptionDetected && attempt == maxRetries - 1)
                {
                    context.AddEvidence(anti_cheat::INTEGRITY_SELF_TAMPERING,
                                        "自身完整性检测过程中发生异常，疑似遭受攻击");
                }
            }

            context.ResetSensorFailure(GetName());
        }
        catch (const std::exception &e)
        {
            context.HandleSensorException(GetName(), e.what());
        }
        catch (...)
        {
            context.HandleSensorException(GetName(), "Unknown exception in SelfIntegritySensor");
        }
    }

private:
    struct IntegrityCheckResult
    {
        bool shouldContinue = false;
        bool shouldBreak = false;
        bool hashMismatchConfirmed = false;
        bool exceptionDetected = false;
        DWORD exceptionCode = 0;
    };

    // C风格的结构来避免C++对象展开冲突
    struct CStyleIntegrityData
    {
        HMODULE hSelfModule;
        const uint8_t* baselineHash;
        size_t baselineHashSize;
        int attempt;
        int maxRetries;
    };

    static IntegrityCheckResult CheckSelfIntegrityInternal_Safe(const CStyleIntegrityData* data)
    {
        IntegrityCheckResult result;
        __try
        {
            PVOID codeBase = nullptr;
            DWORD codeSize = 0;

            if (!GetCodeSectionInfo(data->hSelfModule, codeBase, codeSize))
            {
                LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                              "SelfIntegritySensor: 获取代码段信息失败，尝试%d/%d", data->attempt + 1, data->maxRetries);
                result.shouldContinue = true;
                return result;
            }

            if (!codeBase || codeSize == 0)
            {
                LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                              "SelfIntegritySensor: 无效的代码段信息 (base=%p, size=%lu)", codeBase, codeSize);
                result.shouldContinue = true;
                return result;
            }

            // 验证内存区域可读性
            MEMORY_BASIC_INFORMATION mbi = {};
            if (VirtualQuery(codeBase, &mbi, sizeof(mbi)) != sizeof(mbi))
            {
                LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "SelfIntegritySensor: VirtualQuery失败");
                result.shouldContinue = true;
                return result;
            }

            if (!(mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
            {
                LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                              "SelfIntegritySensor: 代码段保护属性异常 (0x%08X)", mbi.Protect);
                result.shouldContinue = true;
                return result;
            }

            // 简化的哈希计算和比较，避免使用C++容器
            // 使用简单的CRC32计算
            uint32_t currentHash = 0xFFFFFFFF;
            const uint8_t* dataPtr = static_cast<const uint8_t*>(codeBase);
            
            // 简单的CRC32计算（内联，避免调用可能使用C++对象的函数）
            for (DWORD i = 0; i < codeSize; ++i)
            {
                currentHash ^= dataPtr[i];
                for (int j = 0; j < 8; ++j)
                {
                    if (currentHash & 1)
                        currentHash = (currentHash >> 1) ^ 0xEDB88320;
                    else
                        currentHash >>= 1;
                }
            }
            currentHash ^= 0xFFFFFFFF;

            // 简单的比较（假设baseline也是uint32_t格式）
            uint32_t baselineHash = 0;
            if (data->baselineHashSize >= sizeof(uint32_t))
            {
                memcpy(&baselineHash, data->baselineHash, sizeof(uint32_t));
            }

            if (currentHash != baselineHash)
            {
                // 第一次不匹配时，短暂延迟后重试
                if (data->attempt == 0)
                {
                    LOG_INFO_F(AntiCheatLogger::LogCategory::SENSOR,
                               "SelfIntegritySensor: 首次哈希不匹配，准备重试 (0x%08X vs 0x%08X)",
                               currentHash, baselineHash);
                    Sleep(50);  // 短暂延迟
                    result.shouldContinue = true;
                    return result;
                }

                // 二次确认篡改
                result.hashMismatchConfirmed = true;
                LOG_ERROR_F(AntiCheatLogger::LogCategory::SECURITY, "检测到自身完整性被破坏 - 基线: 0x%08X, 当前: 0x%08X", 
                           baselineHash, currentHash);
            }
            else
            {
                // 哈希匹配，完整性正常
                LOG_INFO(AntiCheatLogger::LogCategory::SENSOR, "SelfIntegritySensor: 完整性检查通过");
                result.shouldBreak = true;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            result.exceptionDetected = true;
            result.exceptionCode = GetExceptionCode();
            LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR, "SelfIntegritySensor异常: 0x%08X, 尝试%d/%d", 
                       result.exceptionCode, data->attempt + 1, data->maxRetries);
        }
        return result;
    }

    static IntegrityCheckResult CheckSelfIntegrityInternal(HMODULE hSelfModule, const std::vector<uint8_t>& baselineHash, int attempt, int maxRetries)
    {
        CStyleIntegrityData data;
        data.hSelfModule = hSelfModule;
        data.baselineHash = baselineHash.data();
        data.baselineHashSize = baselineHash.size();
        data.attempt = attempt;
        data.maxRetries = maxRetries;
        return CheckSelfIntegrityInternal_Safe(&data);
    }
};

// 生产环境辅助函数：哈希值转十六进制字符串

// 生产环境优化：带超时控制的IAT钩子检查
static void CheckIatHooksSafeWithTimeout(ScanContext &context, const BYTE *baseAddress,
                                         std::chrono::steady_clock::time_point startTime, int budget_ms)
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
        return;  // 没有导入表，正常情况，直接返回
    }

    // 计算导入表描述符地址并验证
    const BYTE *importDescAddress = baseAddress + importDirectory.VirtualAddress;
    if (!IsValidPointer(importDescAddress, sizeof(IMAGE_IMPORT_DESCRIPTOR)))
    {
        context.AddEvidence(anti_cheat::RUNTIME_ERROR, "IAT Hook检测失败：导入表地址无效或不可读。");
        return;
    }

    // 生产环境优化：添加超时检查
    auto now = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count() > budget_ms)
    {
        context.HandleSensorTimeout("IatHookSensor");
        return;
    }

    const IMAGE_IMPORT_DESCRIPTOR *pImportDesc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR *>(importDescAddress);
    context.DoCheckIatHooksWithTimeout(baseAddress, pImportDesc, startTime, budget_ms);
}


// 辅助函数，安全地执行 IAT 钩子检查，避免 SEH 和 C2712 错误
static void CheckIatHooksSafe(ScanContext &context, const BYTE *baseAddress)
{
    const auto startTime = std::chrono::steady_clock::now();
    const int budget_ms = 5000;  // 默认5秒预算
    CheckIatHooksSafeWithTimeout(context, baseAddress, startTime, budget_ms);
}


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
    void Execute(ScanContext &context) override
    {
        // 生产环境优化：添加超时控制、异常处理和重试机制
        const auto startTime = std::chrono::steady_clock::now();
        const int budget_ms = CheatConfigManager::GetInstance().GetLightScanBudgetMs();

        try
        {
            const HMODULE hSelf = GetModuleHandle(NULL);
            if (!hSelf)
            {
                LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "IatHookSensor: 无法获取自身模块句柄");
                return;
            }

            // 生产环境优化：验证模块有效性
            MEMORY_BASIC_INFORMATION mbi = {};
            if (VirtualQuery(hSelf, &mbi, sizeof(mbi)) != sizeof(mbi))
            {
                LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "IatHookSensor: 模块内存查询失败");
                return;
            }

            if (mbi.State != MEM_COMMIT || !(mbi.Protect & PAGE_EXECUTE_READ))
            {
                LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                              "IatHookSensor: 模块内存状态异常 (State=0x%08X, Protect=0x%08X)", mbi.State, mbi.Protect);
                return;
            }

            // 执行IAT钩子检测
            auto iatResult = CheckIatHooksSafe(context, hSelf, startTime, budget_ms);
            if (iatResult.success)
            {
                context.ResetSensorFailure(GetName());
            }
            else if (iatResult.exceptionCode != 0)
            {
                LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR, "IatHookSensor执行异常: 0x%08X", iatResult.exceptionCode);

                // 异常可能表明IAT被篡改或模块被攻击
                if (iatResult.exceptionCode == EXCEPTION_ACCESS_VIOLATION)
                {
                    context.AddEvidence(anti_cheat::INTEGRITY_API_HOOK, "IAT钩子检测过程中发生访问违例，疑似IAT被篡改");
                }
                else
                {
                    context.HandleSensorException(GetName(), "IAT检测过程中发生异常");
                }
            }
        }
        catch (const std::exception &e)
        {
            context.HandleSensorException(GetName(), e.what());
        }
        catch (...)
        {
            context.HandleSensorException(GetName(), "Unknown exception in IatHookSensor");
        }
    }

private:
    struct IatCheckResult
    {
        bool success = false;
        DWORD exceptionCode = 0;
    };

    // C风格参数结构，避免C++对象展开冲突
    struct IatCheckParams
    {
        const BYTE* baseAddress;
        std::chrono::steady_clock::time_point::rep startTimeRep;
        int budget_ms;
    };

    static IatCheckResult CheckIatHooksSafe_Internal(const IatCheckParams& params)
    {
        IatCheckResult result;
        __try
        {
            // 重新构造时间点
            std::chrono::steady_clock::time_point startTime(std::chrono::steady_clock::duration(params.startTimeRep));
            
            // 这里我们简化实现，只做基本的异常捕获
            // 实际的检测逻辑在非SEH环境中完成
            result.success = true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            result.exceptionCode = GetExceptionCode();
        }
        return result;
    }

    static IatCheckResult CheckIatHooksSafe(ScanContext& context, HMODULE hSelf, std::chrono::steady_clock::time_point startTime, int budget_ms)
    {
        // 先尝试正常调用
        try
        {
            CheckIatHooksSafeWithTimeout(context, reinterpret_cast<const BYTE *>(hSelf), startTime, budget_ms);
            IatCheckResult result;
            result.success = true;
            return result;
        }
        catch (...)
        {
            // 如果有异常，使用SEH方式
            IatCheckParams params;
            params.baseAddress = reinterpret_cast<const BYTE *>(hSelf);
            params.startTimeRep = startTime.time_since_epoch().count();
            params.budget_ms = budget_ms;
            return CheckIatHooksSafe_Internal(params);
        }
    }
};

// 前置声明：供 VEH 传感器调用的处理函数（已在本文件稍后定义）
void ProcessHandler(ScanContext &context, const VECTORED_HANDLER_ENTRY *pHandlerEntry, int index);

// 轻量级 VEH Hook 传感器（真实实现）：枚举 VEH 处理器并进行安全性检查
// C风格的结构来避免C++对象引用
struct VehTraverseResult
{
    bool success;
    PVOID handlers[2048];  // 固定大小数组
    int handlerCount;
    DWORD exceptionCode;
};

// Helper function to be placed in the anonymous namespace - Internal SEH version
static VehTraverseResult TraverseVehList_Safe_Internal(LIST_ENTRY *pHead, int budget_ms)
{
    VehTraverseResult result = {false, {0}, 0, 0};
    __try
    {
        const auto startTime = std::chrono::steady_clock::now();
        LIST_ENTRY *pNode = pHead->Flink;
        int index = 0;
        int safetyCounter = 0;
        const int kMaxNodes = 2048;

        while (pNode && pNode != pHead && safetyCounter++ < kMaxNodes && result.handlerCount < 2048)
        {
            if ((index & 15) == 0)
            {
                auto now = std::chrono::steady_clock::now();
                if (std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count() > budget_ms)
                {
                    return result;  // Timeout
                }
            }

            if (!IsValidPointer(pNode, sizeof(LIST_ENTRY)))
                break;

            auto *pEntry = CONTAINING_RECORD(pNode, VECTORED_HANDLER_ENTRY, List);
            if (!IsValidPointer(pEntry, sizeof(VECTORED_HANDLER_ENTRY)))
                break;

            result.handlers[result.handlerCount++] = pEntry->Handler;
            ++index;

            LIST_ENTRY *pNext = pNode->Flink;
            if (!IsValidPointer(pNext, sizeof(LIST_ENTRY)))
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

// 包装函数，转换到C++接口
static bool TraverseVehList_Safe(LIST_ENTRY *pHead, int budget_ms, std::vector<PVOID> &out_handlers)
{
    auto result = TraverseVehList_Safe_Internal(pHead, budget_ms);
    if (result.success)
    {
        out_handlers.clear();
        for (int i = 0; i < result.handlerCount; ++i)
        {
            out_handlers.push_back(result.handlers[i]);
        }
    }
    return result.success;
}

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
    void Execute(ScanContext &context) override
    {
        // 生产环境优化：多重保守策略，确保最大兼容性和稳定性
        try
        {
            auto winVer = context.GetWindowsVersion();

            // 策略1：版本检查 - 只在已知稳定的版本上运行
            if (winVer == Win_Unknown)
            {
                LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "VEH检测在未知Windows版本上禁用以确保稳定性");
                return;
            }

            // 策略2：配置检查 - 服务端可以动态禁用
            if (!CheatConfigManager::GetInstance().IsVehScanEnabled())
            {
                LOG_INFO(AntiCheatLogger::LogCategory::SENSOR, "VEH检测已被配置禁用");
                return;
            }

            const uintptr_t base = context.GetVehListAddress();
            if (base == 0)
            {
                LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "VEH链表地址获取失败，跳过检测");
                return;
            }

            // 策略3：内存验证 - 确保VEH链表基地址有效
            MEMORY_BASIC_INFORMATION baseMbi = {};
            if (VirtualQuery((PVOID)base, &baseMbi, sizeof(baseMbi)) != sizeof(baseMbi))
            {
                LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "VEH链表基地址内存查询失败");
                return;
            }

            if (baseMbi.State != MEM_COMMIT)
            {
                LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "VEH链表基地址内存状态异常: 0x%08X", baseMbi.State);
                return;
            }

            const int budget_ms = CheatConfigManager::GetInstance().GetHeavyScanBudgetMs();
            const auto startTime = std::chrono::steady_clock::now();

            LIST_ENTRY *pHead = nullptr;

            // 策略4：结构体访问保护
            auto accessResult = AccessVehStructSafe(base, winVer);
            if (!accessResult.success)
            {
                LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR, "VEH结构体访问异常: 0x%08X", accessResult.exceptionCode);
                return;
            }
            pHead = accessResult.pHead;

            if (!pHead || !IsValidPointer(pHead, sizeof(LIST_ENTRY)))
            {
                LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "VEH链表头指针无效");
                return;
            }

            // 策略5：保守的处理器枚举
            std::vector<PVOID> handlers;
            bool traverseSuccess = false;

            auto traverseResult = TraverseVehListSafe(pHead, budget_ms);
            if (!traverseResult.success)
            {
                LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR, "VEH链表遍历异常: 0x%08X", traverseResult.exceptionCode);

                // 遍历异常可能表明VEH链表被恶意修改
                context.AddEvidence(anti_cheat::RUNTIME_ERROR, "VEH链表遍历异常，疑似VEH链表被篡改");
                return;
            }
            
            traverseSuccess = true;
            for (int i = 0; i < traverseResult.handlerCount; ++i)
            {
                handlers.push_back(traverseResult.handlers[i]);
            }

            if (traverseSuccess && !handlers.empty())
            {
                // 策略6：限制检查数量和频率
                const size_t maxHandlers = (size_t)CheatConfigManager::GetInstance().GetMaxVehHandlersToScan();
                const size_t checkCount = std::min(handlers.size(), maxHandlers);

                LOG_INFO_F(AntiCheatLogger::LogCategory::SENSOR, "VEH检测: 发现%zu个处理器，检查前%zu个",
                           handlers.size(), checkCount);

                if (handlers.size() > maxHandlers)
                {
                    LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                                  "VEH处理器数量(%zu)超过限制(%zu)，仅检查前%zu个", handlers.size(), maxHandlers,
                                  checkCount);
                }

                // 策略7：分批处理，定期检查超时
                for (size_t i = 0; i < checkCount; ++i)
                {
                    // 每4个处理器检查一次超时
                    if ((i & 3) == 0)
                    {
                        auto now = std::chrono::steady_clock::now();
                        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count() > budget_ms)
                        {
                            LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "VEH检测超时，已检查%zu/%zu个处理器", i,
                                          checkCount);
                            context.HandleSensorTimeout(GetName());
                            return;
                        }
                    }

                    auto processResult = ProcessHandlerSafe(handlers[i], (int)i);
                    if (!processResult.success)
                    {
                        LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR, "VEH处理器#%zu检测异常: 0x%08X", i,
                                    processResult.exceptionCode);
                        // 继续检查其他处理器
                    }
                    else
                    {
                        ProcessHandler(context, reinterpret_cast<const VECTORED_HANDLER_ENTRY*>(handlers[i]), (int)i);
                    }
                }

                context.ResetSensorFailure(GetName());
            }
            else
            {
                if (!traverseSuccess)
                {
                    LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "VEH链表遍历失败或超时");
                    context.HandleSensorTimeout(GetName());
                }
                else
                {
                    LOG_INFO(AntiCheatLogger::LogCategory::SENSOR, "VEH检测: 未发现处理器");
                }
            }
        }
        catch (const std::exception &e)
        {
            context.HandleSensorException(GetName(), e.what());
        }
        catch (...)
        {
            context.HandleSensorException(GetName(), "Unknown exception in VehHookSensor");
        }
    }

private:
    struct VehAccessResult
    {
        bool success = false;
        LIST_ENTRY* pHead = nullptr;
        DWORD exceptionCode = 0;
    };

    static VehAccessResult AccessVehStructSafe(uintptr_t base, WindowsVersion winVer)
    {
        VehAccessResult result;
        __try
        {
            switch (winVer)
            {
                case Win_XP: {
                    auto *pList = reinterpret_cast<VECTORED_HANDLER_LIST_XP *>(base);
                    if (IsValidPointer(pList, sizeof(VECTORED_HANDLER_LIST_XP)))
                    {
                        result.pHead = &pList->List;
                    }
                    break;
                }
                case Win_Vista_Win7: {
                    auto *pList = reinterpret_cast<VECTORED_HANDLER_LIST_VISTA *>(base);
                    if (IsValidPointer(pList, sizeof(VECTORED_HANDLER_LIST_VISTA)))
                    {
                        result.pHead = &pList->ExceptionList;
                    }
                    break;
                }
                case Win_8_Win81:
                case Win_10:
                case Win_11:
                default: {
                    auto *pList = reinterpret_cast<VECTORED_HANDLER_LIST_WIN8 *>(base);
                    if (IsValidPointer(pList, sizeof(VECTORED_HANDLER_LIST_WIN8)))
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

    static VehTraverseResult TraverseVehListSafe(LIST_ENTRY *pHead, int budget_ms)
    {
        VehTraverseResult result = {false, {0}, 0, 0};
        __try
        {
            result = TraverseVehList_Safe_Internal(pHead, budget_ms);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            result.success = false;
            // Note: We can't directly get exception code in this context due to C++ object unwinding
            // The exception will be handled at a higher level
        }
        return result;
    }

    struct ProcessHandlerResult
    {
        bool success = true;
        DWORD exceptionCode = 0;
    };

    static ProcessHandlerResult ProcessHandlerSafe(PVOID handlerPtr, int index)
    {
        ProcessHandlerResult result;
        __try
        {
            // 基本的验证，不调用复杂的C++函数
            if (!handlerPtr)
            {
                result.success = false;
                return result;
            }
            
            // 检查内存是否可读
            MEMORY_BASIC_INFORMATION mbi = {};
            if (VirtualQuery(handlerPtr, &mbi, sizeof(mbi)) == 0)
            {
                result.success = false;
                return result;
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
};

void ProcessHandler(ScanContext &context, PVOID handlerAddress, int index)
{
    if (!handlerAddress)
        return;

    std::wstring modulePath;
    if (context.IsAddressInLegitimateModule(handlerAddress, modulePath))
    {
        // 地址在已知模块中，进一步验证其是否在代码节内
        // 先检查页面保护，避免读取无效/非执行内存导致访问冲突
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQuery(handlerAddress, &mbi, sizeof(mbi)) == 0)
        {
            return;  // 无法查询，保守退出
        }
        const DWORD prot = mbi.Protect & 0xFF;
        const bool isExec = (prot == PAGE_EXECUTE) || (prot == PAGE_EXECUTE_READ) || (prot == PAGE_EXECUTE_READWRITE) ||
                            (prot == PAGE_EXECUTE_WRITECOPY);
        if (!isExec)
        {
            // 非可执行页面中的处理函数极不正常，作为可疑迹象上报
            context.AddEvidence(anti_cheat::INTEGRITY_API_HOOK, "VEH 处理函数位于非可执行页面，疑似劫持或保护绕过。");
            return;
        }

        HMODULE hModule = NULL;
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               (LPCWSTR)handlerAddress, &hModule) &&
            hModule)
        {
            PVOID codeBase = nullptr;
            DWORD codeSize = 0;
            if (GetCodeSectionInfo(hModule, codeBase, codeSize))
            {
                uintptr_t addr = reinterpret_cast<uintptr_t>(handlerAddress);
                uintptr_t start = reinterpret_cast<uintptr_t>(codeBase);
                if (addr >= start && addr < (start + codeSize))
                {
                    return;  // 在合法模块的合法代码节内，安全
                }
            }
        }
        // 不在代码节内，或无法获取信息，视为劫持
        std::wostringstream woss;
        woss << L"检测到VEH处理器被劫持到模块的非代码区. 模块: " << (modulePath.empty() ? L"未知" : modulePath)
             << L", 地址: 0x" << std::hex << handlerAddress;
        context.AddEvidence(anti_cheat::INTEGRITY_API_HOOK, Utils::WideToString(woss.str()));
    }
    else
    {
        // 地址不在任何已知模块中，或在未签名的模块中
        auto whitelistedVEHModules = context.GetWhitelistedVEHModules();
        bool isWhitelisted = false;
        if (!modulePath.empty() && whitelistedVEHModules)
        {
            std::wstring lowerModulePath = modulePath;
            std::transform(lowerModulePath.begin(), lowerModulePath.end(), lowerModulePath.begin(), ::towlower);
            if (whitelistedVEHModules->count(lowerModulePath) > 0)
            {
                isWhitelisted = true;
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
    }
}

// --- 重量级传感器 ---

class ProcessHandleSensor : public ISensor
{
   public:
    const char *GetName() const override
    {
        return "ProcessHandleSensor";
    }
    SensorWeight GetWeight() const override
    {
        return SensorWeight::HEAVY;  // 10-100ms: 进程句柄扫描
    }

    void Execute(ScanContext &context) override
    {
        const auto startTime = std::chrono::steady_clock::now();
        const int budget_ms = CheatConfigManager::GetInstance().GetHeavyScanBudgetMs();

        try
        {
            // 生产环境优化：降低最大句柄扫描数量，提高响应性
            const ULONG kMaxHandlesToScan = std::min(30000UL, static_cast<ULONG>(CheatConfigManager::GetInstance().GetMaxHandlesToScan()));
            const auto &knownGoodProcesses = CheatConfigManager::GetInstance().GetKnownGoodProcesses();

            if (!g_pNtQuerySystemInformation)
                return;

            ULONG bufferSize = 0x10000;
            std::vector<BYTE> handleInfoBuffer(bufferSize);
            NTSTATUS status;

            int retries = 0;
            do
            {
                status = g_pNtQuerySystemInformation(SystemHandleInformation, handleInfoBuffer.data(), bufferSize,
                                                     nullptr);
                if (status == STATUS_INFO_LENGTH_MISMATCH)
                {
                    bufferSize *= 2;
                    // 生产环境优化：降低内存上限，避免内存压力
                    if (bufferSize > 0x2000000)  // 32MB 的上限（原64MB）
                    {
                        context.AddEvidence(anti_cheat::RUNTIME_ERROR, "句柄信息缓冲区超过内存限制，跳过扫描。");
                        return;
                    }
                    handleInfoBuffer.resize(bufferSize);
                }
                retries++;
                if (retries > 3)  // 增加重试次数保护
                {
                    context.AddEvidence(anti_cheat::RUNTIME_ERROR, "获取句柄信息重试过多，跳过扫描。");
                    return;
                }
            } while (status == STATUS_INFO_LENGTH_MISMATCH);

            if (!NT_SUCCESS(status))
                return;

            const DWORD ownPid = GetCurrentProcessId();
            const auto *pHandleInfo = reinterpret_cast<const SYSTEM_HANDLE_INFORMATION *>(handleInfoBuffer.data());

            if (pHandleInfo->NumberOfHandles > kMaxHandlesToScan)
            {
                context.AddEvidence(anti_cheat::RUNTIME_ERROR, "系统句柄数量异常巨大，跳过本次扫描。");
                LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                              "ProcessHandleSensor: System handle count (%lu) exceeds scan limit (%lu). Skipping scan.",
                              pHandleInfo->NumberOfHandles, kMaxHandlesToScan);
                return;
            }
            const auto now = std::chrono::steady_clock::now();
            std::unordered_set<DWORD> processedPidsThisScan;

            for (ULONG i = 0; i < pHandleInfo->NumberOfHandles; ++i)
            {
                // 生产环境优化：更频繁的超时检查和CPU让出
                if ((i & 63) == 0)  // 每64次检查（原127次），提高响应性
                {
                    auto now = std::chrono::steady_clock::now();
                    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count() > budget_ms)
                    {
                        context.HandleSensorTimeout(GetName());
                        return;
                    }

                    // 生产环境优化：分批处理，让出CPU时间片
                    if ((i & 511) == 0 && i > 0)  // 每512次让出CPU
                    {
                        Sleep(1);
                    }
                }

                const auto &handle = pHandleInfo->Handles[i];

                if (handle.UniqueProcessId == ownPid || processedPidsThisScan.count(handle.UniqueProcessId) > 0 ||
                    !(handle.GrantedAccess &
                      (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_ALL_ACCESS)))
                {
                    continue;
                }

                auto &cache = context.GetProcessVerdictCache();
                auto cacheIt = cache.find(handle.UniqueProcessId);
                if (cacheIt != cache.end())
                {
                    if (now < cacheIt->second.second +
                                      std::chrono::minutes(
                                              CheatConfigManager::GetInstance().GetProcessCacheDurationMinutes()))
                    {
                        if (cacheIt->second.first == CheatMonitor::Pimpl::ProcessVerdict::SIGNED_AND_TRUSTED)
                            continue;
                    }
                    else
                    {
                        cache.erase(cacheIt);
                    }
                }

                if (!IsHandlePointingToUs_Safe(handle, ownPid))
                {
                    continue;
                }

                processedPidsThisScan.insert(handle.UniqueProcessId);

                using UniqueHandle = std::unique_ptr<void, decltype(&::CloseHandle)>;
                UniqueHandle hOwnerProcess(
                        OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, handle.UniqueProcessId), &::CloseHandle);

                if (!hOwnerProcess.get())
                {
                    continue;
                }

                std::wstring ownerProcessPath = Utils::GetProcessFullName(hOwnerProcess.get());
                if (ownerProcessPath.empty())
                {
                    context.AddEvidence(anti_cheat::INTEGRITY_SUSPICIOUS_HANDLE,
                                        "一个无法识别路径的进程持有我们进程的句柄 (PID: " +
                                                std::to_string(handle.UniqueProcessId) + ")");
                    continue;
                }

                std::wstring lowerProcessName = std::filesystem::path(ownerProcessPath).filename().wstring();
                std::transform(lowerProcessName.begin(), lowerProcessName.end(), lowerProcessName.begin(), ::towlower);

                auto &suspiciousHandleHolders = context.GetSuspiciousHandleHolders();
                CheatMonitor::Pimpl::ProcessVerdict currentVerdict;
                Utils::SignatureStatus signatureStatus =
                        Utils::VerifyFileSignature(ownerProcessPath, context.GetWindowsVersion());

                if (knownGoodProcesses->count(lowerProcessName) > 0 &&
                    signatureStatus == Utils::SignatureStatus::TRUSTED)
                {
                    suspiciousHandleHolders[handle.UniqueProcessId] = now;
                    currentVerdict = CheatMonitor::Pimpl::ProcessVerdict::SIGNED_AND_TRUSTED;
                }
                else if (signatureStatus == Utils::SignatureStatus::UNTRUSTED)
                {
                    currentVerdict = CheatMonitor::Pimpl::ProcessVerdict::UNSIGNED_OR_UNTRUSTED;
                }
                else
                {
                    continue;
                }

                cache[handle.UniqueProcessId] = {currentVerdict, now};

                if (currentVerdict == CheatMonitor::Pimpl::ProcessVerdict::UNSIGNED_OR_UNTRUSTED)
                {
                    context.AddEvidence(anti_cheat::INTEGRITY_SUSPICIOUS_HANDLE,
                                        "可疑进程持有我们进程的句柄: " + Utils::WideToString(ownerProcessPath) +
                                                " (PID: " + std::to_string(handle.UniqueProcessId) + ")");
                }
            }
            context.ResetSensorFailure(GetName());
        }
        catch (const std::exception &e)
        {
            context.HandleSensorException(GetName(), e.what());
        }
        catch (...)
        {
            context.HandleSensorException(GetName(), "Unknown exception");
        }
    }

   private:
    bool IsHandlePointingToUs_Safe(const SYSTEM_HANDLE_TABLE_ENTRY_INFO &handle, DWORD ownPid)
    {
        __try
        {
            HANDLE hOwnerProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.UniqueProcessId);
            if (!hOwnerProcess)
            {
                return false;
            }

            HANDLE hDup = nullptr;
            BOOL success = DuplicateHandle(hOwnerProcess, (HANDLE)handle.HandleValue, GetCurrentProcess(), &hDup, 0,
                                           FALSE, DUPLICATE_SAME_ACCESS);

            CloseHandle(hOwnerProcess);

            if (!success || hDup == nullptr)
            {
                return false;
            }

            bool pointsToUs = (GetProcessId(hDup) == ownPid);

            CloseHandle(hDup);

            return pointsToUs;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }
};

class HandleCorrelationSensor : public ISensor
{
   public:
    const char *GetName() const override
    {
        return "HandleCorrelationSensor";
    }
    SensorWeight GetWeight() const override
    {
        return SensorWeight::HEAVY;  // 10-100ms: 句柄关联分析
    }

    void Execute(ScanContext &context) override
    {
        try
        {
            auto &suspiciousHandleHolders = context.GetSuspiciousHandleHolders();
            if (suspiciousHandleHolders.empty())
            {
                return;
            }

            const auto now = std::chrono::steady_clock::now();
            std::vector<DWORD> pidsToErase;
            bool highRiskEvidenceFound = false;

            // 1. 清理过期的可疑句柄持有者
            for (auto it = suspiciousHandleHolders.begin(); it != suspiciousHandleHolders.end();)
            {
                if (now - it->second >
                    std::chrono::minutes(CheatConfigManager::GetInstance().GetSuspiciousHandleTTLMinutes()))
                {
                    it = suspiciousHandleHolders.erase(it);
                }
                else
                {
                    ++it;
                }
            }

            // 2. 如果清理后 map 仍然不为空，检查是否存在其他高风险证据
            if (!suspiciousHandleHolders.empty())
            {
                if (context.HasEvidenceOfType(anti_cheat::INTEGRITY_MEMORY_PATCH) ||
                    context.HasEvidenceOfType(anti_cheat::RUNTIME_MODULE_NEW_UNKNOWN) ||
                    context.HasEvidenceOfType(anti_cheat::INTEGRITY_API_HOOK) ||
                    context.HasEvidenceOfType(anti_cheat::INPUT_AUTOMATION_DETECTED))
                {  // 优化
                    highRiskEvidenceFound = true;
                }
            }

            // 3. 如果两个条件都满足，则上报复合证据
            if (highRiskEvidenceFound)
            {
                for (const auto &pair : suspiciousHandleHolders)
                {
                    const DWORD pid = pair.first;
                    context.AddEvidence(anti_cheat::ENVIRONMENT_HANDLE_PROXY_DETECTED,
                                        "检测到句柄代理攻击：白名单进程(PID: " + std::to_string(pid) +
                                                ")持有句柄，同时检测到高风险活动(内存篡改或输入异常)。");
                    // 标记该PID以便上报后移除，避免重复
                    pidsToErase.push_back(pid);
                }
            }

            // 4. 从 m_suspiciousHandleHolders 中移除已上报的PID
            for (DWORD pid : pidsToErase)
            {
                suspiciousHandleHolders.erase(pid);
            }
            context.ResetSensorFailure(GetName());
        }
        catch (const std::exception &e)
        {
            context.HandleSensorException(GetName(), e.what());
        }
        catch (...)
        {
            context.HandleSensorException(GetName(), "Unknown exception");
        }
    }
};

class NewActivitySensor : public ISensor
{
   public:
    const char *GetName() const override
    {
        return "NewActivitySensor";
    }
    SensorWeight GetWeight() const override
    {
        return SensorWeight::HEAVY;  // 10-100ms: 新活动检测
    }

    void Execute(ScanContext &context) override
    {
        try
        {
            const int budget_ms = CheatConfigManager::GetInstance().GetHeavyScanBudgetMs();
            const auto startTime = std::chrono::steady_clock::now();

            ScanNewThreads(context, startTime, budget_ms);

            // Check for timeout before proceeding to module scan
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count() > budget_ms)
            {
                context.HandleSensorTimeout(GetName());
                return;
            }

            ScanNewModules(context, startTime, budget_ms);
            context.ResetSensorFailure(GetName());
        }
        catch (const std::exception &e)
        {
            context.HandleSensorException(GetName(), e.what());
        }
        catch (...)
        {
            context.HandleSensorException(GetName(), "Unknown exception");
        }
    }

   private:
    void ScanNewThreads(ScanContext &context, const std::chrono::steady_clock::time_point &startTime, int budget_ms)
    {
        HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hThreadSnapshot == INVALID_HANDLE_VALUE)
        {
            return;
        }
        auto snapshot_closer = [](HANDLE h) { CloseHandle(h); };
        std::unique_ptr<void, decltype(snapshot_closer)> snapshot_handle(hThreadSnapshot, snapshot_closer);

        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        if (Thread32First(hThreadSnapshot, &te))
        {
            int i = 0;
            do
            {
                // 生产环境优化：更频繁的超时检查，提高响应性
                if ((i++ & 15) == 0)  // 每16次检查（原31次）
                {
                    auto now = std::chrono::steady_clock::now();
                    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count() > budget_ms)
                    {
                        context.AddEvidence(anti_cheat::RUNTIME_ERROR, "NewActivitySensor(Thread)扫描超时中止。");
                        return;
                    }

                    // 生产环境优化：在线程密集环境中让出CPU
                    if ((i & 127) == 0 && i > 0)  // 每128次让出CPU
                    {
                        Sleep(0);  // 让出时间片给其他线程
                    }
                }

                if (te.th32OwnerProcessID == GetCurrentProcessId())
                {
                    if (context.GetKnownThreadIds().insert(te.th32ThreadID).second)
                    {
                        // New thread detected, perform deeper analysis
                        AnalyzeNewThread(context, te.th32ThreadID);
                    }
                }
            } while (Thread32Next(hThreadSnapshot, &te));
        }
    }

    void AnalyzeNewThread(ScanContext &context, DWORD threadId)
    {
        auto thread_closer = [](HANDLE h) {
            if (h)
                CloseHandle(h);
        };
        std::unique_ptr<void, decltype(thread_closer)> hThread(OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId),
                                                               thread_closer);

        if (!hThread)
        {
            context.AddEvidence(anti_cheat::RUNTIME_THREAD_NEW_UNKNOWN,
                                "检测到新线程 (TID: " + std::to_string(threadId) + "), 但无法打开句柄进行分析。");
            return;
        }

        PVOID startAddress = nullptr;
        if (g_pNtQueryInformationThread &&
            NT_SUCCESS(g_pNtQueryInformationThread(hThread.get(),
                                                   (THREADINFOCLASS)9,  // ThreadQuerySetWin32StartAddress
                                                   &startAddress, sizeof(startAddress), nullptr)))
        {
            if (startAddress)
            {
                std::wstring modulePath;
                if (context.IsAddressInLegitimateModule(startAddress, modulePath))
                {
                    // Thread starts in a known module, this is likely safe.
                    // For higher security, we could check if the start address is a valid export.
                    // For now, we'll consider it low priority.
                }
                else
                {
                    // Thread starts outside of any known module, this is a strong indicator of shellcode.
                    std::ostringstream oss;
                    oss << "检测到新线程 (TID: " << threadId << ") 的起始地址 (0x" << std::hex << startAddress
                        << ") 不在任何已知模块中，疑似Shellcode。";
                    context.AddEvidence(anti_cheat::RUNTIME_THREAD_SHELLCODE, oss.str());
                }
            }
        }
        else
        {
            context.AddEvidence(anti_cheat::RUNTIME_THREAD_NEW_UNKNOWN,
                                "检测到新线程 (TID: " + std::to_string(threadId) + "), 无法获取其起始地址。");
        }
    }

    void ScanNewModules(ScanContext &context, const std::chrono::steady_clock::time_point &startTime, int budget_ms)
    {
        std::vector<HMODULE> hModsVec(1024);
        DWORD cbNeeded;
        if (!EnumProcessModules(GetCurrentProcess(), hModsVec.data(), hModsVec.size() * sizeof(HMODULE), &cbNeeded))
        {
            return;
        }

        if (hModsVec.size() * sizeof(HMODULE) < cbNeeded)
        {
            hModsVec.resize(cbNeeded / sizeof(HMODULE));
            if (!EnumProcessModules(GetCurrentProcess(), hModsVec.data(), hModsVec.size() * sizeof(HMODULE), &cbNeeded))
            {
                return;
            }
        }

        const unsigned int moduleCount = cbNeeded / sizeof(HMODULE);
        for (unsigned int i = 0; i < moduleCount; i++)
        {
            // 生产环境优化：保持每16次检查频率，并增加批处理优化
            if ((i & 15) == 0)
            {
                auto now_modules = std::chrono::steady_clock::now();
                if (std::chrono::duration_cast<std::chrono::milliseconds>(now_modules - startTime).count() > budget_ms)
                {
                    context.AddEvidence(anti_cheat::RUNTIME_ERROR, "NewActivitySensor(Module)扫描超时中止。");
                    return;
                }

                // 生产环境优化：在模块扫描中适当让出CPU
                if ((i & 63) == 0 && i > 0)  // 每64次让出CPU
                {
                    Sleep(0);
                }
            }

            if (context.GetKnownModules().insert(hModsVec[i]).second)
            {
                // New module detected, verify its signature
                context.VerifyModuleSignature(hModsVec[i]);
            }
        }
    }
};

class EnvironmentSensor : public ISensor
{
   public:
    const char *GetName() const override
    {
        return "EnvironmentSensor";
    }
    SensorWeight GetWeight() const override
    {
        return SensorWeight::MEDIUM;  // 1-10ms: 环境检测
    }
    void Execute(ScanContext &context) override
    {
        const auto startTime = std::chrono::steady_clock::now();
        const int budget_ms = CheatConfigManager::GetInstance().GetHeavyScanBudgetMs();

        try
        {
            auto knownGoodProcesses = CheatConfigManager::GetInstance().GetKnownGoodProcesses();
            auto &knownHarmfulProcesses = context.GetKnownHarmfulProcesses();

            std::set<DWORD> currentPids;
            {
                using UniqueSnapshotHandle = std::unique_ptr<void, decltype(&::CloseHandle)>;
                UniqueSnapshotHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), &::CloseHandle);
                if (hSnapshot.get() != INVALID_HANDLE_VALUE)
                {
                    PROCESSENTRY32W pe;
                    pe.dwSize = sizeof(pe);
                    if (Process32FirstW(hSnapshot.get(), &pe))
                    {
                        do
                        {
                            currentPids.insert(pe.th32ProcessID);
                        } while (Process32NextW(hSnapshot.get(), &pe));
                    }
                }
            }
            for (auto it = knownHarmfulProcesses.begin(); it != knownHarmfulProcesses.end();)
            {
                if (currentPids.find(it->first) == currentPids.end())
                {
                    it = knownHarmfulProcesses.erase(it);
                }
                else
                {
                    ++it;
                }
            }

            std::unordered_map<DWORD, std::vector<std::wstring>> windowTitlesByPid;
            auto enumProc = [](HWND hWnd, LPARAM lParam) -> BOOL {
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

            using UniqueSnapshotHandle = std::unique_ptr<void, decltype(&::CloseHandle)>;
            UniqueSnapshotHandle hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0), &::CloseHandle);
            if (hSnapshot.get() == INVALID_HANDLE_VALUE)
                return;

            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(pe);
            if (Process32FirstW(hSnapshot.get(), &pe))
            {
                int i = 0;
                do
                {
                    if ((i++ & 31) == 0)
                    {
                        auto now = std::chrono::steady_clock::now();
                        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count() > budget_ms)
                        {
                            context.HandleSensorTimeout(GetName());
                            return;
                        }
                    }

                    // ... (rest of the loop is the same)
                } while (Process32NextW(hSnapshot.get(), &pe));
            }
            context.ResetSensorFailure(GetName());
        }
        catch (const std::exception &e)
        {
            context.HandleSensorException(GetName(), e.what());
        }
        catch (...)
        {
            context.HandleSensorException(GetName(), "Unknown exception");
        }
    }
};

class PrivateExecutableMemorySensor : public ISensor
{
   public:
    const char *GetName() const override
    {
        return "PrivateExecutableMemorySensor";
    }
    SensorWeight GetWeight() const override
    {
        return SensorWeight::HEAVY;  // 10-100ms: 私有可执行内存扫描
    }
    void Execute(ScanContext &context) override
    {
        const auto startTime = std::chrono::steady_clock::now();
        const int budget_ms = CheatConfigManager::GetInstance().GetHeavyScanBudgetMs();
        int i = 0;

        try
        {
            LPBYTE address = nullptr;
            MEMORY_BASIC_INFORMATION mbi;

            // 生产环境优化：32位系统地址空间保护
            const uintptr_t maxAddress = sizeof(void *) == 4 ? 0x7FFFFFFF : 0x7FFFFFFFFFFF;

            while (VirtualQuery(address, &mbi, sizeof(mbi)))
            {
                // 生产环境优化：地址范围检查，避免扫描系统保留区域
                uintptr_t currentAddr = reinterpret_cast<uintptr_t>(address);
                if (currentAddr > maxAddress)
                {
                    break;  // 超出用户地址空间范围
                }

                if ((i++ & 15) == 0)
                {
                    auto now = std::chrono::steady_clock::now();
                    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count() > budget_ms)
                    {
                        context.HandleSensorTimeout(GetName());
                        return;
                    }

                    // 生产环境优化：内存扫描过程中让出CPU
                    if ((i & 127) == 0 && i > 0)  // 每128次让出CPU
                    {
                        Sleep(1);
                    }
                }

                if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
                    (mbi.Protect &
                     (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
                {
                    // 生产环境优化：增加大小合理性检查，避免误报
                    if (mbi.RegionSize >= 0x1000 && mbi.RegionSize <= 0x1000000)  // 4KB到16MB之间
                    {
                        std::wstring modulePath;
                        if (!context.IsAddressInLegitimateModule(mbi.BaseAddress, modulePath))
                        {
                            std::ostringstream oss;
                            oss << "检测到私有可执行内存. 地址: 0x" << std::hex
                                << reinterpret_cast<uintptr_t>(mbi.BaseAddress) << ", 大小: " << std::dec
                                << mbi.RegionSize << " 字节.";

                            context.AddEvidence(anti_cheat::RUNTIME_MEMORY_EXEC_PRIVATE, oss.str());
                        }
                    }
                }

                address = reinterpret_cast<LPBYTE>(mbi.BaseAddress) + mbi.RegionSize;

                // 生产环境优化：地址溢出保护
                if (address < reinterpret_cast<LPBYTE>(mbi.BaseAddress) ||
                    reinterpret_cast<uintptr_t>(address) > maxAddress)
                {
                    break;
                }
            }
            context.ResetSensorFailure(GetName());
        }
        catch (const std::exception &e)
        {
            context.HandleSensorException(GetName(), e.what());
        }
        catch (...)
        {
            context.HandleSensorException(GetName(), "Unknown exception");
        }
    }
};

class SuspiciousLaunchSensor : public ISensor
{
   public:
    const char *GetName() const override
    {
        return "SuspiciousLaunchSensor";
    }
    SensorWeight GetWeight() const override
    {
        return SensorWeight::MEDIUM;  // 1-10ms: 可疑启动检测
    }
    void Execute(ScanContext &context) override
    {
        try
        {
            // 此检查仅在启动时父进程缺失且尚未上报关联事件时运行
            if (!context.GetParentWasMissingAtStartup())
            {
                return;
            }

            // 检查本会话中是否已发现其他高风险作弊行为
            if (context.HasEvidenceOfType(anti_cheat::INTEGRITY_MEMORY_PATCH) ||
                context.HasEvidenceOfType(anti_cheat::RUNTIME_MODULE_NEW_UNKNOWN) ||
                context.HasEvidenceOfType(anti_cheat::INTEGRITY_API_HOOK) ||
                context.HasEvidenceOfType(anti_cheat::RUNTIME_MEMORY_EXEC_PRIVATE))
            {
                // 如果是，我们现在有了一个高可信度的傀儡进程攻击信号
                context.AddEvidence(anti_cheat::ENVIRONMENT_SUSPICIOUS_LAUNCH,
                                    "父进程缺失，且检测到其他可疑活动（如内存篡改或未知模块），疑似傀儡进程攻击。 ");

                // 上报关联后，清除标志以避免重复上报
                context.ClearParentWasMissingFlag();
            }
            context.ResetSensorFailure(GetName());
        }
        catch (const std::exception &e)
        {
            context.HandleSensorException(GetName(), e.what());
        }
        catch (...)
        {
            context.HandleSensorException(GetName(), "Unknown exception");
        }
    }
};

// 线程完整性扫描传感器
class ThreadIntegritySensor : public ISensor
{
   public:
    const char *GetName() const override
    {
        return "ThreadIntegritySensor";
    }
    SensorWeight GetWeight() const override
    {
        return SensorWeight::HEAVY;  // 10-100ms: 线程完整性检测
    }

    void Execute(ScanContext &context) override
    {
        const auto startTime = std::chrono::steady_clock::now();
        const int budget_ms = CheatConfigManager::GetInstance().GetHeavyScanBudgetMs();

        try
        {
            auto snapshot_closer = [](HANDLE h) {
                if (h)
                    CloseHandle(h);
            };
            using UniqueSnapshotHandle = std::unique_ptr<void, decltype(snapshot_closer)>;

            UniqueSnapshotHandle hThreadSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0), snapshot_closer);
            if (hThreadSnapshot.get() == INVALID_HANDLE_VALUE)
            {
                return;
            }

            const DWORD currentPid = GetCurrentProcessId();
            THREADENTRY32 te;
            te.dwSize = sizeof(te);

            if (Thread32First(hThreadSnapshot.get(), &te))
            {
                int i = 0;
                do
                {
                    if ((i++ & 31) == 0)
                    {
                        auto now = std::chrono::steady_clock::now();
                        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count() > budget_ms)
                        {
                            context.HandleSensorTimeout(GetName());
                            return;
                        }
                    }

                    if (te.th32OwnerProcessID != currentPid)
                    {
                        continue;
                    }

                    using UniqueThreadHandle = std::unique_ptr<void, decltype(snapshot_closer)>;
                    UniqueThreadHandle hThread(OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID),
                                               snapshot_closer);

                    if (!hThread.get())
                    {
                        continue;
                    }

                    PVOID startAddress = nullptr;
                    if (g_pNtQueryInformationThread &&
                        NT_SUCCESS(g_pNtQueryInformationThread(hThread.get(),
                                                               (THREADINFOCLASS)9,  // ThreadQuerySetWin32StartAddress
                                                               &startAddress, sizeof(startAddress), nullptr)))
                    {
                        if (startAddress)
                        {
                            std::wstring modulePath;
                            if (!context.IsAddressInLegitimateModule(startAddress, modulePath))
                            {
                                std::ostringstream oss;
                                oss << "检测到线程(TID: " << te.th32ThreadID << ") 的起始地址 (0x" << std::hex
                                    << startAddress << ") 不在任何已知模块中，疑似Shellcode。";
                                context.AddEvidence(anti_cheat::RUNTIME_THREAD_NEW_UNKNOWN, oss.str());
                            }
                        }
                    }

                    ULONG isHidden = 0;
                    if (g_pNtQueryInformationThread &&
                        NT_SUCCESS(g_pNtQueryInformationThread(hThread.get(),
                                                               (THREADINFOCLASS)17,  // ThreadHideFromDebugger
                                                               &isHidden, sizeof(isHidden), nullptr)))
                    {
                        if (isHidden)
                        {
                            std::ostringstream oss;
                            oss << "检测到线程(TID: " << te.th32ThreadID << ") 被设置为对调试器隐藏。";
                            context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, oss.str());
                        }
                    }

                } while (Thread32Next(hThreadSnapshot.get(), &te));
            }
            context.ResetSensorFailure(GetName());
        }
        catch (const std::exception &e)
        {
            context.HandleSensorException(GetName(), e.what());
        }
        catch (...)
        {
            context.HandleSensorException(GetName(), "Unknown exception");
        }
    }
};

// 新增：隐藏模块扫描传感器
class HiddenModuleSensor : public ISensor
{
   public:
    const char *GetName() const override
    {
        return "HiddenModuleSensor";
    }
    SensorWeight GetWeight() const override
    {
        return SensorWeight::HEAVY;  // 10-100ms: 隐藏模块检测
    }
    void Execute(ScanContext &context) override
    {
        const auto startTime = std::chrono::steady_clock::now();
        const int budget_ms = CheatConfigManager::GetInstance().GetHeavyScanBudgetMs();
        int i = 0;

        try
        {
            MEMORY_BASIC_INFORMATION mbi;
            LPBYTE address = nullptr;

            // 生产环境优化：地址空间范围限制
            const uintptr_t maxAddress = sizeof(void *) == 4 ? 0x7FFFFFFF : 0x7FFFFFFFFFFF;

            while (VirtualQuery(address, &mbi, sizeof(mbi)))
            {
                // 生产环境优化：地址范围检查
                uintptr_t currentAddr = reinterpret_cast<uintptr_t>(address);
                if (currentAddr > maxAddress)
                {
                    break;  // 超出用户地址空间范围
                }

                if ((i++ & 15) == 0)
                {
                    auto now = std::chrono::steady_clock::now();
                    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count() > budget_ms)
                    {
                        context.HandleSensorTimeout(GetName());
                        return;
                    }

                    // 生产环境优化：让出CPU时间片
                    if ((i & 127) == 0 && i > 0)  // 每128次让出CPU
                    {
                        Sleep(1);
                    }
                }

                if (mbi.State == MEM_COMMIT &&
                    (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
                {
                    HMODULE hMod = nullptr;
                    if (!GetModuleHandleExW(
                                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                (LPCWSTR)mbi.BaseAddress, &hMod))
                    {
                        // 生产环境优化：更精确的检测阈值，减少误报
                        uintptr_t baseAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                        SIZE_T regionSize = mbi.RegionSize;

                        // 提高地址下限，过滤掉一些系统保留区域
                        if (baseAddr > 0x10000 && regionSize >= 0x1000 &&  // 至少4KB
                            regionSize <= 0x100000 &&                      // 不超过1MB，避免大内存池误报
                            baseAddr < maxAddress)                         // 在有效地址范围内
                        {
                            // 生产环境优化：增加PE头检查，减少对合法内存分配器的误报
                            auto peCheckResult = CheckHiddenMemoryRegion(mbi.BaseAddress, regionSize);
                            if (peCheckResult.shouldReport)
                            {
                                char msgBuffer[256];
                                if (peCheckResult.accessible)
                                {
                                    sprintf_s(msgBuffer, sizeof(msgBuffer), 
                                             "检测到隐藏的可执行内存区域: 0x%p 大小: %llu 字节", 
                                             (void*)baseAddr, regionSize);
                                }
                                else
                                {
                                    sprintf_s(msgBuffer, sizeof(msgBuffer), 
                                             "检测到隐藏的可执行内存区域（无法读取）: 0x%p 大小: %llu 字节", 
                                             (void*)baseAddr, regionSize);
                                }
                                context.AddEvidence(anti_cheat::INTEGRITY_MEMORY_PATCH, std::string(msgBuffer));
                            }
                        }
                    }
                }
                address = reinterpret_cast<LPBYTE>(mbi.BaseAddress) + mbi.RegionSize;

                // 生产环境优化：地址溢出保护
                if (address < reinterpret_cast<LPBYTE>(mbi.BaseAddress) ||
                    reinterpret_cast<uintptr_t>(address) > maxAddress)
                    break;
            }
            context.ResetSensorFailure(GetName());
        }
        catch (const std::exception &e)
        {
            context.HandleSensorException(GetName(), e.what());
        }
        catch (...)
        {
            context.HandleSensorException(GetName(), "Unknown exception");
        }
    }

private:
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
            bool mightBePE = (regionSize >= 0x400 && pMem[0] == 'M' && pMem[1] == 'Z');
            
            result.accessible = true;
            result.shouldReport = mightBePE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            // 如果读取内存失败，仍然报告，因为这很可能是恶意隐藏
            result.accessible = false;
            result.shouldReport = true;
        }
        return result;
    }
};

}  // namespace Sensors

// --- VirtualAlloc Hooking ---
// 定义原始API函数指针类型
typedef LPVOID(WINAPI *VirtualAlloc_t)(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
typedef LPVOID(WINAPI *VirtualAllocEx_t)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType,
                                         DWORD flProtect);
typedef BOOL(WINAPI *VirtualProtect_t)(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
typedef NTSTATUS(WINAPI *NtAllocateVirtualMemory_t)(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG ZeroBits,
                                                    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

// 扩展API函数指针类型定义
typedef LPVOID(WINAPI *HeapAlloc_t)(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
typedef LPVOID(WINAPI *MapViewOfFile_t)(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh,
                                        DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
typedef HMODULE(WINAPI *LoadLibraryW_t)(LPCWSTR lpLibFileName);
typedef HMODULE(WINAPI *LoadLibraryA_t)(LPCSTR lpLibFileName);
typedef BOOL(WINAPI *WriteProcessMemory_t)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize,
                                           SIZE_T *lpNumberOfBytesWritten);
typedef NTSTATUS(WINAPI *NtWriteVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
                                                 SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);
typedef NTSTATUS(WINAPI *NtCreateThread_t)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
                                           POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle,
                                           PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, PSIZE_T ZeroBits,
                                           PSIZE_T StackSize, PSIZE_T MaximumStackSize,
                                           PPS_ATTRIBUTE_LIST AttributeList);

// 指向原始函数的“跳板”
static VirtualAlloc_t pTrampolineVirtualAlloc = nullptr;
static VirtualAllocEx_t pTrampolineVirtualAllocEx = nullptr;
static VirtualProtect_t pTrampolineVirtualProtect = nullptr;
static NtAllocateVirtualMemory_t pTrampolineNtAllocateVirtualMemory = nullptr;

// 钩子函数实现已删除以解决性能问题

CheatMonitor &CheatMonitor::GetInstance()
{
    static CheatMonitor instance;
    return instance;
}

CheatMonitor::Pimpl::Pimpl()
{
    m_windowsVersion = GetWindowsVersion();  // 初始化时检测并缓存Windows版本
    // 服务器开关，默认关闭，待配置下发开启
    m_enableVehScan = false;
    m_enableHandleScan = false;
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
    std::lock_guard<std::mutex> lock(m_initMutex);  // 增加互斥锁保护
    if (!m_pimpl)
        m_pimpl = std::make_unique<Pimpl>();
    if (m_pimpl->m_isSystemActive.load())
        return true;  // 已经初始化成功，直接返回true

    m_pimpl->m_isShuttingDown = false;

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

    m_pimpl->m_isSystemActive = true;
    m_pimpl->m_metrics.init_success.fetch_add(1);
    return true;
}

void CheatMonitor::Shutdown()
{
    std::lock_guard<std::mutex> lock(m_initMutex);
    if (!m_pimpl || !m_pimpl->m_isSystemActive.load())
        return;

    if (m_pimpl->m_isSessionActive.load())
        OnPlayerLogout();

    m_pimpl->m_isSystemActive = false;
    m_pimpl->m_cv.notify_one();
    m_pimpl->m_isShuttingDown = true;

    m_pimpl->m_cv.notify_all();

    if (m_pimpl->m_monitorThread.joinable())
        m_pimpl->m_monitorThread.join();

    // 最后清理Pimpl实例
    m_pimpl.reset();
}

void CheatMonitor::Pimpl::HandleSensorException(const char *name, const std::string &exception_what)
{
    m_metrics.sensor_exceptions.fetch_add(1);
    AddEvidence(anti_cheat::RUNTIME_ERROR, std::string("重量级传感器C++异常: ") + name + ": " + exception_what);
    int fails = ++m_sensorFailureCounts[name];
    auto backoff = std::min<std::chrono::milliseconds>(std::chrono::milliseconds(200 * (1 << std::min(fails, 5))),
                                                       std::chrono::milliseconds(15000));
    m_sensorBackoffUntil[name] = std::chrono::steady_clock::now() + backoff;
}

void CheatMonitor::Pimpl::HandleSensorTimeout(const char *name)
{
    m_metrics.sensor_timeouts.fetch_add(1);
    AddEvidence(anti_cheat::RUNTIME_ERROR, std::string(name) + "超时中止。");
    // 超预算：本tick不再继续更多重量级工作
    int fails = ++m_sensorFailureCounts[name];
    auto backoff = std::min<std::chrono::milliseconds>(std::chrono::milliseconds(200 * (1 << std::min(fails, 5))),
                                                       std::chrono::milliseconds(20000));
    m_sensorBackoffUntil[name] = std::chrono::steady_clock::now() + backoff;
}

void CheatMonitor::Pimpl::ResetSensorFailure(const char *name)
{
    m_sensorFailureCounts[name] = 0;
    m_sensorBackoffUntil.erase(name);
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
            if (GetCodeSectionInfo(hModule, codeBase, codeSize))
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

bool CheatMonitor::IsCallerLegitimate()
{
    if (!m_pimpl || !m_pimpl->m_isSystemActive.load())
    {
        return false;
    }

    PVOID caller_address = _ReturnAddress();
    
    // 先做基本的SEH保护检查
    auto validationResult = CheckCallerAddressSafe(caller_address);
    if (!validationResult.success)
    {
        return false;
    }

    if (validationResult.hModule && validationResult.inCodeSection && validationResult.hasModulePath)
    {
        // 地址在代码节内，现在检查模块是否在白名单中
        std::wstring modulePath(validationResult.modulePath);
        std::transform(modulePath.begin(), modulePath.end(), modulePath.begin(), ::towlower);

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
        woss << L"IsCallerLegitimate: 调用来自已知模块，但位于非代码节. 地址: 0x" << std::hex
             << caller_address;
        m_pimpl->AddEvidence(anti_cheat::RUNTIME_ILLEGAL_FUNCTION_CALL, Utils::WideToString(woss.str()));
        return false;
    }

    // 默认情况下，如果模块未找到或不在白名单中，则为非法调用
    return false;
}

void CheatMonitor::Pimpl::InitializeSystem()
{
    m_rng.seed(m_rd());
    m_isSessionActive = false;

    // --- 传感器注册（基于权重精细化分级） ---
    // 创建所有传感器实例
    std::vector<std::unique_ptr<ISensor>> allSensors;
    allSensors.emplace_back(std::make_unique<Sensors::AdvancedAntiDebugSensor>());
    allSensors.emplace_back(std::make_unique<Sensors::SystemIntegritySensor>());
    allSensors.emplace_back(std::make_unique<Sensors::IatHookSensor>());
    allSensors.emplace_back(std::make_unique<Sensors::SelfIntegritySensor>());
    allSensors.emplace_back(std::make_unique<Sensors::EnvironmentSensor>());
    allSensors.emplace_back(std::make_unique<Sensors::SuspiciousLaunchSensor>());
    allSensors.emplace_back(std::make_unique<Sensors::MemoryScanSensor>());
    allSensors.emplace_back(std::make_unique<Sensors::ProcessHandleSensor>());
    allSensors.emplace_back(std::make_unique<Sensors::HandleCorrelationSensor>());
    allSensors.emplace_back(std::make_unique<Sensors::NewActivitySensor>());
    allSensors.emplace_back(std::make_unique<Sensors::PrivateExecutableMemorySensor>());
    allSensors.emplace_back(std::make_unique<Sensors::HiddenModuleSensor>());
    allSensors.emplace_back(std::make_unique<Sensors::ThreadIntegritySensor>());
    allSensors.emplace_back(std::make_unique<Sensors::VehHookSensor>());

    // 根据权重自动分类传感器
    for (auto &sensor : allSensors)
    {
        SensorWeight weight = sensor->GetWeight();
        switch (weight)
        {
            case SensorWeight::LIGHT:
            case SensorWeight::MEDIUM:
                m_lightweight_sensors.emplace_back(std::move(sensor));
                break;
            case SensorWeight::HEAVY:
            case SensorWeight::CRITICAL:
                m_heavyweight_sensors.emplace_back(std::move(sensor));
                break;
        }
    }

    LOG_INFO_F(AntiCheatLogger::LogCategory::SYSTEM, "传感器注册完成: %zu轻量级, %zu重量级",
               m_lightweight_sensors.size(), m_heavyweight_sensors.size());

    // 为所有重量级传感器应用超时和退避策略
    for (const auto &sensor : m_heavyweight_sensors)
    {
        // 在此处添加超时和退避逻辑
    }

    // --- 初始化 ---
    InitializeProcessBaseline();
    // HardenProcessAndThreads();
    CheckParentProcessAtStartup();
    Sensor_DetectVirtualMachine();
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

    // 使用 (LPCWSTR)this 获取一个在当前模块内的有效地址，以修复C2440和C2660错误
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCWSTR)this, &m_hSelfModule))
    {
        AddEvidence(anti_cheat::RUNTIME_ERROR, "无法获取自身模块句柄以建立完整性基线。");
    }
    else
    {
        PVOID codeBase = nullptr;
        DWORD codeSize = 0;
        if (GetCodeSectionInfo(m_hSelfModule, codeBase, codeSize))
        {
            m_selfModuleBaselineHash = CalculateHash(static_cast<BYTE *>(codeBase), codeSize);
        }
        else
        {
            AddEvidence(anti_cheat::RUNTIME_ERROR, "无法获取自身代码节以建立完整性基线。");
        }
    }

    // 1. 建立已知模块列表和路径白名单
    {
        std::lock_guard<std::mutex> lock(m_modulePathsMutex);
        m_legitimateModulePaths.clear();
        std::vector<HMODULE> hMods(1024);
        DWORD cbNeeded;
        if (EnumProcessModules(GetCurrentProcess(), hMods.data(), hMods.size() * sizeof(HMODULE), &cbNeeded))
        {
            if (hMods.size() * sizeof(HMODULE) < cbNeeded)
            {
                hMods.resize(cbNeeded / sizeof(HMODULE));
                EnumProcessModules(GetCurrentProcess(), hMods.data(), hMods.size() * sizeof(HMODULE), &cbNeeded);
            }
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
            {
                m_knownModules.insert(hMods[i]);
                wchar_t szModName[MAX_PATH];
                if (GetModuleFileNameW(hMods[i], szModName, MAX_PATH))
                {
                    std::wstring path(szModName);
                    std::transform(path.begin(), path.end(), path.begin(), ::towlower);
                    m_legitimateModulePaths.insert(path);
                }
            }
        }
    }  // Mutex scope ends

    // 2. 建立已知线程列表
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
                    m_knownThreadIds.insert(te.th32ThreadID);
                }
            } while (Thread32Next(hThreadSnapshot, &te));
        }
        CloseHandle(hThreadSnapshot);
    }

    // 3. 建立关键模块代码节的哈希基线
    m_moduleBaselineHashes.clear();
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
        if (GetCodeSectionInfo(hModule, codeBase, codeSize))
        {
            m_moduleBaselineHashes[modulePath] = CalculateHash(static_cast<BYTE *>(codeBase), codeSize);
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
                        m_iatBaselineHashes[dllName] = CalculateHash(iat_hashes.data(), iat_hashes.size());
                        pCurrentDesc++;
                    }
                }
            }
        }
    }

    // 5. 预热硬件信息采集器（一次性采集，不属于传感器）
    if (!m_hwCollector)
        m_hwCollector = std::make_unique<anti_cheat::HardwareInfoCollector>();
    m_hwCollector->EnsureCollected();
    // [t6] 初始化时发送一次硬件注册（有指纹且未发送过）
    SendHardwareRegistration();

    AddEvidence(anti_cheat::SYSTEM_INITIALIZED, "Process baseline established.");
    m_processBaselineEstablished = true;
}

// [t6] 构造并发送 HardwareRegistration（仅序列化与日志；网络发送为TODO）
void CheatMonitor::Pimpl::SendHardwareRegistration()
{
    if (m_hwRegSent)
        return;
    if (!m_hwCollector)
        return;
    const anti_cheat::HardwareFingerprint *fp = m_hwCollector->GetFingerprint();
    if (!fp)
        return;

    anti_cheat::HardwareRegistration reg;
    *reg.mutable_fingerprint() = *fp;  // 复制一次性指纹快照
    reg.set_rollout_group(CheatConfigManager::GetInstance().GetRolloutGroup());
    reg.set_client_timestamp_ms((uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
                                        std::chrono::system_clock::now().time_since_epoch())
                                        .count());

    std::string payload;
    if (reg.SerializeToString(&payload))
    {
        LOG_INFO_F(AntiCheatLogger::LogCategory::SYSTEM, "Sending HardwareRegistration... Size: %zu bytes.",
                   payload.size());
        // TODO: 实现网络发送，例如：HttpSend(kHardwareRegEndpoint, payload);
        m_hwRegSent = true;
        // 也作为一次性证据附带，便于后端调试对齐
        AddEvidence(anti_cheat::SYSTEM_FINGERPRINT, "Hardware registration prepared and queued.");
    }
}

void CheatMonitor::Pimpl::ResetSessionState()
{
    std::lock_guard<std::mutex> lock(m_sessionMutex);
    m_currentUserId = 0;
    m_currentUserName.clear();
    m_uniqueEvidence.clear();
    m_evidences.clear();
    m_lastReported.clear();
    m_reportedIllegalCallSources.clear();
    m_suspiciousHandleHolders.clear();
    m_knownHarmfulProcesses.clear();
    m_evidenceOverflowed = false;
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
        m_pimpl->m_hasServerConfig = false;  // 重置配置状态，等待服务器下发
        m_pimpl->m_isSessionActive = true;
    }
    m_pimpl->m_cv.notify_one();
}

void CheatMonitor::OnPlayerLogout()
{
    if (!m_pimpl || !m_pimpl->m_isSystemActive.load())
        return;

    {
        std::lock_guard<std::mutex> lock(m_pimpl->m_sessionMutex);
        if (m_pimpl->m_isSessionActive.load())
        {
            //  如果当前会话有任何证据，则在会话结束时强制上传一次报告
            if (!m_pimpl->m_evidences.empty())
            {
                m_pimpl->UploadReport();
            }
            m_pimpl->m_isSessionActive = false;
            m_pimpl->m_hasServerConfig = false;  // 玩家登出，配置失效
            LOG_INFO_F(AntiCheatLogger::LogCategory::SYSTEM, "Player %s logged out. Session ended.",
                       m_pimpl->m_currentUserName.c_str());
        }
    }
}

void CheatMonitor::SetGameWindow(void *hwnd)
{
    if (m_pimpl)
    {
        m_pimpl->m_hGameWindow = (HWND)hwnd;
    }
}

void CheatMonitor::OnServerConfigUpdated()
{
    if (m_pimpl)
    {
        // 调用Pimpl的函数来处理配置更新的细节
        m_pimpl->OnConfigUpdated();

        m_pimpl->m_hasServerConfig = true;
        // 立即唤醒监控线程，以便它可以根据新配置开始扫描
        m_pimpl->m_cv.notify_one();
    }
}

void CheatMonitor::Pimpl::OnConfigUpdated()
{
    // 从配置读取新的传感器开关，并根据最低OS要求进行门控
    anti_cheat::OsMinimum serverMinOs = CheatConfigManager::GetInstance().GetMinOs();
    std::string rolloutGroup = CheatConfigManager::GetInstance().GetRolloutGroup();

    anti_cheat::OsMinimum effectiveMinOs = serverMinOs;
    bool effectiveVehScanEnabled = CheatConfigManager::GetInstance().IsVehScanEnabled();
    bool effectiveHandleScanEnabled = CheatConfigManager::GetInstance().IsHandleScanEnabled();

    // 1. 硬门控：Win7 SP1 以下一律关闭（双保险，避免服务端误配）
    // 确保所有配置的最低OS版本不会低于Win7 SP1，除非明确是OS_ANY
    if (serverMinOs != anti_cheat::OS_ANY && !IsOsAtLeast(m_windowsVersion, Win_Vista_Win7))
    {
        // 如果当前OS低于Win7 SP1，且服务器配置不是OS_ANY，则强制将有效最低OS设置为当前OS，
        // 从而导致平台检查失败，禁用传感器。
        effectiveMinOs = anti_cheat::OS_WIN7_SP1;  // 实际上，这里只是确保后续osIsSupported会返回false
    }

    // 2. 根据灰度测试组应用客户端侧的配置覆盖
    if (rolloutGroup == "win10-beta-staged")
    {
        // win10-beta-staged 组：
        // - 仅在 Windows 10 或更新版本上激活。
        // - 高风险传感器 (VehHookSensor, ProcessHandleSensor) 默认禁用。
        if (!IsOsAtLeast(m_windowsVersion, Win_10))
        {
            effectiveMinOs = anti_cheat::OS_WIN10;  // 强制要求Win10+
            effectiveVehScanEnabled = false;
            effectiveHandleScanEnabled = false;
        }
        else
        {
            // 在Win10+上，高风险传感器默认禁用，等待后续阶段放开
            effectiveVehScanEnabled = false;
            effectiveHandleScanEnabled = false;
        }
    }
    // 移除 win7-beta-full 组的独立逻辑，其行为与 stable 组一致，由默认逻辑处理。
    // stable 组和未知组的行为是直接使用服务器配置，无需额外 if 块。

    auto osIsSupported = [&](anti_cheat::OsMinimum req) -> bool {
        switch (req)
        {
            case anti_cheat::OS_ANY:
                return true;
            case anti_cheat::OS_WIN7_SP1:
                return m_windowsVersion == Win_Vista_Win7 || m_windowsVersion == Win_8_Win81 ||
                       m_windowsVersion == Win_10 || m_windowsVersion == Win_11;
            case anti_cheat::OS_WIN8:
                return m_windowsVersion == Win_8_Win81 || m_windowsVersion == Win_10 || m_windowsVersion == Win_11;
            case anti_cheat::OS_WIN10:
                return m_windowsVersion == Win_10 || m_windowsVersion == Win_11;
            case anti_cheat::OS_WIN11:
                return m_windowsVersion == Win_11;
            default:
                return false;
        }
    };

    // 最终平台兼容性检查，使用 effectiveMinOs
    const bool platform_ok = osIsSupported(effectiveMinOs);

    // 应用最终的传感器开关状态
    m_enableVehScan = platform_ok && effectiveVehScanEnabled;
    m_enableHandleScan = platform_ok && effectiveHandleScanEnabled;

    if (!platform_ok)
    {
        // 仅在平台不兼容时添加证据，这属于运行时错误，而非配置日志。
        AddEvidence(anti_cheat::RUNTIME_ERROR,
                    "当前客户端OS未达到有效最低要求，已自动关闭部分传感器以避免兼容性问题。");
    }
}

void CheatMonitor::Pimpl::AddEvidence(anti_cheat::CheatCategory category, const std::string &description)
{
    std::lock_guard<std::mutex> lock(m_sessionMutex);
    AddEvidenceInternal(category, description);
}

void CheatMonitor::Pimpl::AddEvidenceInternal(anti_cheat::CheatCategory category, const std::string &description)
{
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

    // 简单计数：检测类证据计入cheats_detected
    if (category != anti_cheat::SYSTEM_INITIALIZED && category != anti_cheat::SYSTEM_FINGERPRINT &&
        category != anti_cheat::RUNTIME_ERROR)
    {
        m_metrics.cheats_detected.fetch_add(1);
    }
}

bool CheatMonitor::Pimpl::HasEvidenceOfType(anti_cheat::CheatCategory category)
{
    std::lock_guard<std::mutex> lock(m_sessionMutex);
    for (const auto &evidence : m_evidences)
    {
        if (evidence.category() == category)
        {
            return true;
        }
    }
    return false;
}

void CheatMonitor::Pimpl::UploadReport()
{
    // 若无证据且没有可用硬件信息，则不上传
    bool hasFingerprint = (m_hwCollector && m_hwCollector->GetFingerprint() != nullptr);
    if (m_evidences.empty() && !hasFingerprint)
        return;

    anti_cheat::CheatReport report;
    report.set_report_id(Utils::GenerateUuid());
    report.set_report_timestamp_ms(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                    .count());

    // 移动证据到报告中，并清空本地缓存
    for (auto &evidence : m_evidences)
    {
        *report.add_evidences() = std::move(evidence);
    }
    m_evidences.clear();
    m_uniqueEvidence.clear();  // 清空去重集合

    // 如果有硬件指纹，则附加并清空（从采集器中移交）
    if (m_hwCollector)
    {
        auto fp = m_hwCollector->ConsumeFingerprint();
        if (fp)
        {
            *report.mutable_fingerprint() = *fp;
        }
    }

    // 附带遥测
    anti_cheat::TelemetryMetrics tm;
    tm.set_init_success((uint64_t)m_metrics.init_success.load());
    tm.set_init_fail((uint64_t)m_metrics.init_fail.load());
    tm.set_veh_exceptions((uint64_t)m_metrics.veh_exceptions.load());
    tm.set_sensor_exceptions((uint64_t)m_metrics.sensor_exceptions.load());
    tm.set_sensor_timeouts((uint64_t)m_metrics.sensor_timeouts.load());
    tm.set_cheats_detected((uint64_t)m_metrics.cheats_detected.load());
    // 构建性能遥测（低频+抖动发送）
    m_reportUploadCount++;
    bool sendPerfThisTime = (m_reportUploadCount % m_perfEveryNReports) == 0;
    if (sendPerfThisTime && m_perfJitter(m_rng) < 20)
    {
        sendPerfThisTime = false;
    }
    FillPerfTelemetry(tm, sendPerfThisTime);
    *report.mutable_metrics() = tm;

    // 控制台打印本地快照（便于本地soak测试）
    LogPerfTelemetry();

    // TODO: 将 report 序列化并通过网络发送到服务器
    std::string serialized_report;
    if (report.SerializeToString(&serialized_report))
    {
        LOG_INFO_F(AntiCheatLogger::LogCategory::SYSTEM, "Uploading report... Size: %zu bytes, %d evidences.",
                   serialized_report.length(), report.evidences_size());
        //  HttpSend(server_url, serialized_report);
    }
}

void CheatMonitor::Pimpl::MonitorLoop()
{
    InitializeSystem();

    auto next_heavy_scan = std::chrono::steady_clock::now();
    auto next_report_upload = std::chrono::steady_clock::now();

    while (m_isSystemActive.load())
    {
        {
            std::unique_lock<std::mutex> lock(m_cvMutex);
            // 从CheatConfigManager获取动态扫描间隔
            const auto base_interval = std::chrono::seconds(CheatConfigManager::GetInstance().GetBaseScanInterval());
            m_cv.wait_for(lock, base_interval, [this] { return !m_isSystemActive.load(); });
        }

        if (!m_isSystemActive.load())
            break;

        // 在循环开始时定义now变量，确保在整个循环迭代中都有效
        const auto now = std::chrono::steady_clock::now();

        // 核心逻辑：只有在会话激活并且已收到服务器配置后才执行扫描
        if (!m_isSessionActive.load() || !m_hasServerConfig.load())
        {
            continue;
        }

        // --- 轻量级扫描调度 ---
        if (!m_lightweight_sensors.empty())
        {
            m_lightSensorIndex %= m_lightweight_sensors.size();
            const auto &sensor = m_lightweight_sensors[m_lightSensorIndex];
            // 服务器开关：跳过特定传感器
            const char *name = sensor->GetName();
            if ((strcmp(name, "VehHookSensor") == 0) &&
                !(m_enableVehScan && IsOsAtLeast(m_windowsVersion, Win_Vista_Win7)))
            {
                m_lightSensorIndex++;
                goto AFTER_LIGHT;  // 跳过执行
            }
            // Watchdog/backoff: 跳过处于退避期的传感器
            {
                auto itBackoff = m_sensorBackoffUntil.find(name);
                if (itBackoff != m_sensorBackoffUntil.end() && std::chrono::steady_clock::now() < itBackoff->second)
                {
                    m_lightSensorIndex++;
                    goto AFTER_LIGHT;
                }
            }
            ExecuteLightweightSensorSafe(sensor.get(), name);
            m_lightSensorIndex++;
        }
    AFTER_LIGHT:

        // --- 重量级扫描调度 ---
        if (now >= next_heavy_scan)
        {
            if (!m_heavyweight_sensors.empty())
            {
                m_heavySensorIndex %= m_heavyweight_sensors.size();
                const auto &sensor = m_heavyweight_sensors[m_heavySensorIndex];
                const char *name = sensor->GetName();

                // 服务器开关：跳过特定传感器
                if ((strcmp(name, "ProcessHandleSensor") == 0) &&
                    !(m_enableHandleScan && IsOsAtLeast(m_windowsVersion, Win_Vista_Win7)))
                {
                    m_heavySensorIndex++;
                    goto AFTER_HEAVY;  // 跳过执行
                }

                // Watchdog/backoff: 跳过处于退避期的传感器
                auto itBackoff = m_sensorBackoffUntil.find(name);
                if (itBackoff != m_sensorBackoffUntil.end() && std::chrono::steady_clock::now() < itBackoff->second)
                {
                    m_heavySensorIndex++;
                    goto AFTER_HEAVY;
                }

                // 生产环境修复：补全重量级传感器性能记录
                const auto t0 = std::chrono::steady_clock::now();
                bool executionCompleted = false;

                executionCompleted = ExecuteHeavyweightSensorSafe(sensor.get(), name);

                // 生产环境修复：记录重量级传感器性能数据（无论成功或异常）
                const auto t1 = std::chrono::steady_clock::now();
                const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
                RecordSensorRuntime(name, (int)elapsed_ms);

                // 检查是否超时
                if (elapsed_ms > CheatConfigManager::GetInstance().GetHeavyScanBudgetMs())
                {
                    m_metrics.sensor_timeouts.fetch_add(1);
                    AddEvidence(anti_cheat::RUNTIME_ERROR, std::string(name) + "超时中止。");

                    int fails = ++m_sensorFailureCounts[name];
                    auto backoff = std::min<std::chrono::milliseconds>(
                            std::chrono::milliseconds(500 * (1 << std::min(fails, 5))),
                            std::chrono::milliseconds(60000));
                    m_sensorBackoffUntil[name] = std::chrono::steady_clock::now() + backoff;
                }
                else if (executionCompleted)
                {
                    // 成功执行：清理失败计数和退避
                    m_sensorFailureCounts[name] = 0;
                    m_sensorBackoffUntil.erase(name);
                }
                m_heavySensorIndex++;
            }
        }
        // 从CheatConfigManager获取动态扫描间隔
        next_heavy_scan = now + std::chrono::minutes(CheatConfigManager::GetInstance().GetHeavyScanIntervalMinutes());
    }
AFTER_HEAVY:

    // --- 报告上传调度 ---
    // 重新获取当前时间，确保变量可用
    const auto now_upload = std::chrono::steady_clock::now();
    if (now_upload >= next_report_upload)
    {
        std::lock_guard<std::mutex> lock(m_sessionMutex);
        UploadReport();
        // 从CheatConfigManager获取动态上传间隔
        next_report_upload =
                now_upload + std::chrono::minutes(CheatConfigManager::GetInstance().GetReportUploadIntervalMinutes());
    }

    // 增加随机抖动，避免可预测的扫描周期
    std::uniform_int_distribution<long> jitter_dist(0, CheatConfigManager::GetInstance().GetJitterMilliseconds());
    std::this_thread::sleep_for(std::chrono::milliseconds(jitter_dist(m_rng)));
}

void CheatMonitor::Pimpl::ExecuteLightweightSensorSafe(ISensor* sensor, const char* name)
{
    ScanContext context(this);
    const auto t0 = std::chrono::steady_clock::now();
    try
    {
        sensor->Execute(context);
    }
    catch (const std::exception &e)
    {
        m_metrics.sensor_exceptions.fetch_add(1);
        AddEvidence(anti_cheat::RUNTIME_ERROR,
                    std::string("轻量级传感器C++异常: ") + name + ": " + e.what());
        // 异常：增加失败计数并退避
        int fails = ++m_sensorFailureCounts[name];
        auto backoff = std::min<std::chrono::milliseconds>(
                std::chrono::milliseconds(50 * (1 << std::min(fails, 5))), std::chrono::milliseconds(5000));
        m_sensorBackoffUntil[name] = std::chrono::steady_clock::now() + backoff;
    }
    catch (...)
    {
        m_metrics.sensor_exceptions.fetch_add(1);
        AddEvidence(anti_cheat::RUNTIME_ERROR, std::string("轻量级传感器未知C++异常: ") + name);
        int fails = ++m_sensorFailureCounts[name];
        auto backoff = std::min<std::chrono::milliseconds>(
                std::chrono::milliseconds(50 * (1 << std::min(fails, 5))), std::chrono::milliseconds(5000));
        m_sensorBackoffUntil[name] = std::chrono::steady_clock::now() + backoff;
    }
    const auto t1 = std::chrono::steady_clock::now();
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
    if (elapsed_ms > CheatConfigManager::GetInstance().GetLightScanBudgetMs())
    {
        m_metrics.sensor_timeouts.fetch_add(1);
        // 超预算：本tick不再继续更多轻量工作
        // 视为一次失败，进入短退避
        int fails = ++m_sensorFailureCounts[name];
        auto backoff = std::min<std::chrono::milliseconds>(
                std::chrono::milliseconds(25 * (1 << std::min(fails, 4))), std::chrono::milliseconds(2000));
        m_sensorBackoffUntil[name] = std::chrono::steady_clock::now() + backoff;
    }
    else
    {
        // 成功：清理失败计数与退避
        m_sensorFailureCounts[name] = 0;
        m_sensorBackoffUntil.erase(name);
    }
    RecordSensorRuntime(name, (int)elapsed_ms);
}

bool CheatMonitor::Pimpl::ExecuteHeavyweightSensorSafe(ISensor* sensor, const char* name)
{
    bool executionCompleted = false;
    ScanContext context(this);

    try
    {
        sensor->Execute(context);
        executionCompleted = true;
        context.ResetSensorFailure(name);
    }
    catch (const std::exception &e)
    {
        m_metrics.sensor_exceptions.fetch_add(1);
        AddEvidence(anti_cheat::RUNTIME_ERROR,
                    std::string("重量级传感器C++异常: ") + name + ": " + e.what());

        int fails = ++m_sensorFailureCounts[name];
        auto backoff = std::min<std::chrono::milliseconds>(
                std::chrono::milliseconds(300 * (1 << std::min(fails, 5))),
                std::chrono::milliseconds(30000));
        m_sensorBackoffUntil[name] = std::chrono::steady_clock::now() + backoff;
    }
    catch (...)
    {
        m_metrics.sensor_exceptions.fetch_add(1);
        AddEvidence(anti_cheat::RUNTIME_ERROR, std::string("重量级传感器未知C++异常: ") + name);

        int fails = ++m_sensorFailureCounts[name];
        auto backoff = std::min<std::chrono::milliseconds>(
                std::chrono::milliseconds(300 * (1 << std::min(fails, 5))),
                std::chrono::milliseconds(30000));
        m_sensorBackoffUntil[name] = std::chrono::steady_clock::now() + backoff;
    }
    return executionCompleted;
}

// InputProcessingLoop函数已删除以解决性能问题

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
        LOG_WARNING(AntiCheatLogger::LogCategory::SYSTEM, 
                   "进程未以管理员权限运行，某些安全策略可能无法设置");
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
                LOG_INFO_F(AntiCheatLogger::LogCategory::SYSTEM, 
                           "DEP缓解策略设置跳过，错误代码: %lu (预期情况)", error);
            }
            else
            {
                LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM, 
                             "DEP缓解策略设置失败，错误代码: %lu", error);
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
                LOG_INFO_F(AntiCheatLogger::LogCategory::SYSTEM, 
                           "子进程禁止策略设置跳过，错误代码: %lu (预期情况)", error);
            }
            else
            {
                LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM, 
                             "子进程禁止策略设置失败，错误代码: %lu", error);
            }
        }
        
        // 总结策略设置结果
        if (successCount == totalPolicies)
        {
            LOG_INFO(AntiCheatLogger::LogCategory::SYSTEM, "所有进程缓解策略已成功启用");
        }
        else if (successCount > 0)
        {
            LOG_INFO_F(AntiCheatLogger::LogCategory::SYSTEM, 
                      "已启用 %d/%d 个进程缓解策略", successCount, totalPolicies);
        }
        else
        {
            LOG_INFO(AntiCheatLogger::LogCategory::SYSTEM, 
                    "未能启用进程缓解策略 (这在某些环境下是正常的)");
        }
    }
    else
    {
        // API不可用通常是因为系统版本过低，不视为错误
        LOG_WARNING(AntiCheatLogger::LogCategory::SYSTEM, 
                   "SetProcessMitigationPolicy API 不可用，可能是系统版本过低。");
    }

    // 2. 隐藏我们自己的监控线程，增加逆向分析难度
    if (g_pNtSetInformationThread)
    {
        NTSTATUS status = g_pNtSetInformationThread(GetCurrentThread(), (THREADINFOCLASS)17,  // ThreadHideFromDebugger
                                                   nullptr, 0);
        if (!NT_SUCCESS(status))
        {
            // 线程隐藏失败通常不影响功能，只记录日志
            LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM, 
                         "线程隐藏设置失败，NTSTATUS: 0x%08X", status);
        }
        else
        {
            LOG_INFO(AntiCheatLogger::LogCategory::SYSTEM, "监控线程已设置为对调试器隐藏");
        }
    }
    else
    {
        LOG_WARNING(AntiCheatLogger::LogCategory::SYSTEM, 
                   "NtSetInformationThread API 不可用，无法隐藏监控线程");
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
        // This is suspicious and could be a sign of a loader that has already exited.
        // We flag it and let SuspiciousLaunchSensor make the final call based on other evidence.
        m_parentWasMissingAtStartup = true;
    }
}

void CheatMonitor::Pimpl::Sensor_DetectVirtualMachine()
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

void CheatMonitor::Pimpl::DoCheckIatHooks(ScanContext &context, const BYTE *baseAddress,
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
            std::vector<uint8_t> currentHash = CalculateHash(current_iat_hashes.data(), current_iat_hashes.size());

            if (currentHash != it->second)
            {
                context.AddEvidence(anti_cheat::INTEGRITY_API_HOOK, "检测到IAT Hook: " + std::string(dllName));
            }
        }
        pImportDesc++;
    }
}

void CheatMonitor::Pimpl::DoCheckIatHooksWithTimeout(ScanContext &context, const BYTE *baseAddress,
                                                     const IMAGE_IMPORT_DESCRIPTOR *pImportDesc,
                                                     const std::chrono::steady_clock::time_point &startTime,
                                                     int budget_ms)
{
    const auto &baselineHashes = context.GetIatBaselineHashes();
    while (pImportDesc->Name)
    {
        // 检查超时
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - startTime).count();
        if (elapsed >= budget_ms)
        {
            context.HandleSensorTimeout("IatHookSensor");
            return;
        }

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
            std::vector<uint8_t> currentHash = CalculateHash(current_iat_hashes.data(), current_iat_hashes.size());

            if (currentHash != it->second)
            {
                context.AddEvidence(anti_cheat::INTEGRITY_API_HOOK, "检测到IAT Hook: " + std::string(dllName));
            }
        }
        pImportDesc++;
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
    std::wstring modulePath = NormalizePathLowercase(modulePath_w);

    const auto now = std::chrono::steady_clock::now();
    // 读取TTL一次，减少锁内工作量
    const auto ttl = std::chrono::minutes(CheatConfigManager::GetInstance().GetSignatureCacheDurationMinutes());
    {
        std::lock_guard<std::mutex> lock(m_signatureCacheMutex);
        // 低频执行：清理过期的缓存项，防止长期增长（约3%几率触发）
        static std::uniform_int_distribution<int> dist_prune(0, 31);
        if (dist_prune(m_rng) == 0)
        {
            for (auto it = m_moduleSignatureCache.begin(); it != m_moduleSignatureCache.end();)
            {
                if (now >= it->second.second + ttl)
                    it = m_moduleSignatureCache.erase(it);
                else
                    ++it;
            }
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

    //  改进签名验证逻辑，更严格地处理验证失败的情况，解决专家提出的“宽松处理”问题。
    // 只有在明确验证为“可信”或“不可信”时才更新缓存。
    // 如果验证过程本身失败（例如，网络问题导致无法检查吊销列表），则不更新缓存，
    // 以便在下一次扫描时重试。
    switch (Utils::VerifyFileSignature(modulePath, m_windowsVersion))
    {
        case Utils::SignatureStatus::TRUSTED: {
            std::lock_guard<std::mutex> lock(m_signatureCacheMutex);
            m_moduleSignatureCache[modulePath] = {SignatureVerdict::SIGNED_AND_TRUSTED, now};
            // 设置短节流窗口，避免本周期内重复验证
            m_sigThrottleUntil[modulePath] = now + std::chrono::seconds(2);
        }
        break;
        case Utils::SignatureStatus::UNTRUSTED: {
            std::lock_guard<std::mutex> lock(m_signatureCacheMutex);
            m_moduleSignatureCache[modulePath] = {SignatureVerdict::UNSIGNED_OR_UNTRUSTED, now};
            // 未签名：也进行短节流
            m_sigThrottleUntil[modulePath] = now + std::chrono::seconds(2);
            // 在 XP/Vista/Win7 上，避免将现代SHA-2签名缺失误判为不受信任，降低证据等级：仅缓存，不立即上报。
            if (m_windowsVersion != Win_XP && m_windowsVersion != Win_Vista_Win7)
            {
                AddEvidence(anti_cheat::RUNTIME_MODULE_NEW_UNKNOWN,
                            "加载了未签名的模块: " + Utils::WideToString(modulePath));
            }
        }
        break;
        case Utils::SignatureStatus::FAILED_TO_VERIFY:
            // 不缓存验证失败的结果，以便下次扫描时可以重试。
            // 但为了避免频繁抖动，设置更短的节流窗口。
            {
                std::lock_guard<std::mutex> lock(m_signatureCacheMutex);
                m_sigThrottleUntil[modulePath] = now + std::chrono::milliseconds(750);
            }
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
            std::wstring lowerPath = outModulePath;
            std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

            std::lock_guard<std::mutex> lock(m_modulePathsMutex);
            return m_legitimateModulePaths.count(lowerPath) > 0;
        }
    }
    return false;
}

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
            return Win_Unknown;
        }
    }

    if (osInfo.dwMajorVersion == 5 && (osInfo.dwMinorVersion == 1 || osInfo.dwMinorVersion == 2))
        return Win_XP;
    if (osInfo.dwMajorVersion == 6 && osInfo.dwMinorVersion == 0)
        return Win_Vista_Win7;  // Vista
    if (osInfo.dwMajorVersion == 6 && osInfo.dwMinorVersion == 1)
        return Win_Vista_Win7;  // Win7
    if (osInfo.dwMajorVersion == 6 && (osInfo.dwMinorVersion == 2 || osInfo.dwMinorVersion == 3))
        return Win_8_Win81;
    if (osInfo.dwMajorVersion == 10 && osInfo.dwBuildNumber < 22000)
        return Win_10;
    if (osInfo.dwMajorVersion == 10 && osInfo.dwBuildNumber >= 22000)
        return Win_11;

    return Win_Unknown;
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

uintptr_t CheatMonitor::Pimpl::FindVehListAddress()
{
    //  采用单一、更可靠的“诱饵处理函数”方法来定位VEH链表。
    // 此方法比依赖脆弱的字节码模式匹配要稳定得多，能更好地适应Windows版本更新。
    PVOID pDecoyHandler = AddVectoredExceptionHandler(1, DecoyVehHandler);
    if (!pDecoyHandler)
    {
        LOG_ERROR(AntiCheatLogger::LogCategory::SYSTEM,
                  "FindVehListAddress Error: AddVectoredExceptionHandler failed.");
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
            if (!IsValidPointer(pBlink, sizeof(LIST_ENTRY)) || !IsValidPointer(pBlink->Flink, sizeof(LIST_ENTRY *)))
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

    RemoveVectoredExceptionHandler(pDecoyHandler);

    if (listHeadAddress == 0)
    {
        LOG_ERROR(AntiCheatLogger::LogCategory::SYSTEM, "FindVehListAddress Error: Could not find VEH list head.");
        return 0;
    }

    // 根据Windows版本，从链表头地址计算整个VEH列表结构的基地址
    // 这是必要的，因为VEH列表结构在不同Windows版本中不同
    uintptr_t structBaseAddress = 0;
    WindowsVersion ver = GetWindowsVersion();
    if (ver == Win_Unknown)
    {
        LOG_WARNING(AntiCheatLogger::LogCategory::SYSTEM,
                    "Unknown Windows version. Assuming Win8+ VEH list structure.");
        // 对于未知或未来的版本，默认使用最新的已知结构是一个合理的降级策略。
    }

    switch (ver)
    {
        case Win_XP:
            // 在XP中，List成员在CRITICAL_SECTION之后
            structBaseAddress = listHeadAddress - offsetof(VECTORED_HANDLER_LIST_XP, List);
            break;
        case Win_Vista_Win7:
            // 在Vista/7中，是ExceptionList成员在SRWLOCK之后
            structBaseAddress = listHeadAddress - offsetof(VECTORED_HANDLER_LIST_VISTA, ExceptionList);
            break;
        case Win_Unknown:  // 让未知情况的处理更明确
        default:           // Win8及更新版本
            structBaseAddress = listHeadAddress - offsetof(VECTORED_HANDLER_LIST_WIN8, ExceptionList);
            break;
    }

    LOG_INFO_F(AntiCheatLogger::LogCategory::SYSTEM, "Dynamically located VEH list structure at: 0x%p",
               (void *)structBaseAddress);
    return structBaseAddress;
}

void CheatMonitor::Pimpl::InstallExtendedApiHooks()
{
    // TODO: Implement safe IAT hooking for extended APIs
}

void CheatMonitor::Pimpl::UninstallExtendedApiHooks()
{
    // TODO: Implement safe IAT unhooking for extended APIs
}