#include "CheatMonitor.h"
#include "CheatConfigManager.h"

// 定义 NOMINMAX 宏以防止 Windows.h 定义 min/max 宏,
// 从而解决与 std::max 的编译冲突。
#define NOMINMAX
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
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <iostream>
#include <memory>
#include <mutex>
#include <numeric>
#include <random>
#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")  // 为注册表函数 (Reg*) 添加库链接
#pragma comment(lib, "iphlpapi.lib")  // 为 GetAdaptersInfo 添加库链接
#pragma comment(lib, "wintrust.lib")  // 为 WinVerifyTrust 添加库链接

// 为兼容旧版Windows SDK (pre-Win8)，手动定义缺失的类型
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
#endif  // (NTDDI_VERSION < NTDDI_WIN8)

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
        // Log("[AntiCheat] WideCharToMultiByte failed to get size");
        return std::string();
    }
    std::string strTo(size_needed, 0);
    if (WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL) == 0)
    {
        // Log("[AntiCheat] WideCharToMultiByte failed to convert string");
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
SignatureStatus VerifyFileSignature(const std::wstring &filePath)
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

    winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &guid, &winTrustData);

    if (result == ERROR_SUCCESS)
    {
        return SignatureStatus::TRUSTED;
    }

    // 区分“验证失败”和“文件确实无签名”
    // 证书相关的错误码，表示验证过程本身有问题，而非文件有问题
    switch (result)
    {
        case TRUST_E_NOSIGNATURE:
        case TRUST_E_BAD_DIGEST:
            return SignatureStatus::UNTRUSTED;
        default:
            // 其他所有错误 (如网络问题、证书服务问题) 都视为验证失败
            return SignatureStatus::FAILED_TO_VERIFY;
    }
}

}  // namespace Utils

namespace
{

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
        DWORD exceptionCode = GetExceptionCode();
        std::cout << "[AntiCheat] GetCodeSectionInfo Exception: hModule=0x" << std::hex << hModule
                  << ", code=" << exceptionCode << std::endl;

        return false;
    }
    return false;
}
#pragma warning(pop)

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

// ---- 新增: 路径规范化工具与限流工具 ----
static std::wstring NormalizePathLowercase(const std::wstring &path)
{
    if (path.empty())
        return path;

    wchar_t fullPath[MAX_PATH];
    DWORD len = GetFullPathNameW(path.c_str(), MAX_PATH, fullPath, nullptr);
    std::wstring normalized = (len > 0 && len < MAX_PATH) ? std::wstring(fullPath) : path;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), ::towlower);
    return normalized;
}

// ---- 新增: 固定容量环形缓冲（线程外部需自持锁） ----
template <typename T>
class RingBuffer
{
   public:
    explicit RingBuffer(size_t capacity) : m_data(std::max<size_t>(1, capacity)), m_head(0), m_size(0)
    {
    }
    void clear()
    {
        m_head = 0;
        m_size = 0;
    }
    size_t capacity() const
    {
        return m_data.size();
    }
    size_t size() const
    {
        return m_size;
    }
    void push(const T &value)
    {
        if (m_data.empty())
            return;
        size_t index = (m_head + m_size) % m_data.size();
        if (m_size < m_data.size())
        {
            m_data[index] = value;
            m_size++;
        }
        else
        {
            // overwrite oldest
            m_data[m_head] = value;
            m_head = (m_head + 1) % m_data.size();
        }
    }
    void snapshot(std::vector<T> &out) const
    {
        out.clear();
        out.reserve(m_size);
        for (size_t i = 0; i < m_size; ++i)
        {
            size_t idx = (m_head + i) % m_data.size();
            out.push_back(m_data[idx]);
        }
    }

   private:
    std::vector<T> m_data;
    size_t m_head;
    size_t m_size;
};

// ---- 新增: 可疑调用者地址解析（优先使用受控回溯） ----
static PVOID ResolveSuspiciousCallerAddress(HMODULE hSelf)
{
    // 采集简短回溯，跳过属于自身模块的帧，返回第一个外部地址
    PVOID addrs[16] = {};
    USHORT frames = RtlCaptureStackBackTrace(1, 16, addrs, nullptr);
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

// --- 核心架构组件 ---

class ScanContext;

// ISensor: 所有检测传感器的抽象基类接口 (策略模式)
class ISensor
{
   public:
    virtual ~ISensor() = default;
    virtual const char *GetName() const = 0;  // 用于日志和调试
    virtual void Execute(ScanContext &context) = 0;
};

struct CheatMonitor::Pimpl
{
    Pimpl();  // 新增构造函数

    std::atomic<bool> m_isSystemActive = false;
    std::atomic<bool> m_isSessionActive = false;
    std::atomic<bool> m_hasServerConfig = false;  // 新增：用于标记是否已收到服务器配置
    std::thread m_monitorThread;
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

    // 用于控制会话基线重建的标志
    // std::atomic<bool> m_newSessionNeedsBaseline = false;

    // 使用 std::set 以获得更快的查找速度 (O(logN)) 并自动处理重复项
    std::set<DWORD> m_knownThreadIds;
    std::set<HMODULE> m_knownModules;
    //  硬件指纹信息，只在首次登录时收集一次
    std::unique_ptr<anti_cheat::HardwareFingerprint> m_fingerprint;
    std::unordered_set<std::wstring> m_legitimateModulePaths;  // 使用哈希集合以实现O(1)复杂度的快速查找
    std::unordered_map<uintptr_t, std::chrono::steady_clock::time_point>
            m_reportedIllegalCallSources;  // 用于记录已上报的非法调用来源，并实现5分钟上报冷却
    //  记录每个用户、每种作弊类型的最近上报时间，防止重复上报
    std::map<std::pair<uint32_t, anti_cheat::CheatCategory>, std::chrono::steady_clock::time_point> m_lastReported;
    // 用于句柄代理攻击关联分析的状态容器
    std::unordered_map<DWORD, std::chrono::steady_clock::time_point> m_suspiciousHandleHolders;

    // --- 限流与容量控制 ---
    bool m_evidenceOverflowed = false;

    // --- 传感器调度：时间预算与轮转索引 ---
    size_t m_lightSensorIndex = 0;
    size_t m_heavySensorIndex = 0;

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
    struct KeyboardEvent
    {
        DWORD vkCode;
        DWORD time;
    };

    HWND m_hGameWindow = NULL;  // 游戏主窗口句柄
    HHOOK m_hMouseHook = NULL;
    HHOOK m_hKeyboardHook = NULL;   // 键盘钩子
    DWORD m_hookOwnerThreadId = 0;  // 记录钩子所有者线程ID
    std::mutex m_inputMutex;
    RingBuffer<MouseMoveEvent> m_mouseMoveEvents;
    RingBuffer<MouseClickEvent> m_mouseClickEvents;
    RingBuffer<KeyboardEvent> m_keyboardEvents;
    static Pimpl *s_pimpl_for_hooks;  // Static pointer for hook procedures

    std::mt19937 m_rng;       // 随机数生成器
    std::random_device m_rd;  // 随机数种子

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
    // 进程句柄检测缓存
    enum class ProcessVerdict
    {
        UNKNOWN,
        SIGNED_AND_TRUSTED,
        UNSIGNED_OR_UNTRUSTED
    };
    std::unordered_map<DWORD, std::pair<ProcessVerdict, std::chrono::steady_clock::time_point>> m_processVerdictCache;

    // 存储关键模块代码节的基线哈希值
    std::unordered_map<std::wstring, std::vector<uint8_t>> m_moduleBaselineHashes;

    // IAT Hook检测基线：为每个导入的DLL存储一个独立的哈希值
    std::unordered_map<std::string, std::vector<uint8_t>> m_iatBaselineHashes;
    uintptr_t m_vehListAddress = 0;  // 存储VEH链表(LdrpVectorHandlerList)的绝对地址

    // 传感器集合
    std::vector<std::unique_ptr<ISensor>> m_lightweight_sensors;
    std::vector<std::unique_ptr<ISensor>> m_heavyweight_sensors;

    // Main loop and state management
    void MonitorLoop();
    void UploadReport();
    void InitializeSystem();
    void InitializeProcessBaseline();
    void ResetSessionState();
    void AddEvidence(anti_cheat::CheatCategory category, const std::string &description);
    void AddEvidenceInternal(anti_cheat::CheatCategory category,
                             const std::string &description);  // 不加锁的内部版本
    void HardenProcessAndThreads();                            //  进程与线程加固
    bool HasEvidenceOfType(anti_cheat::CheatCategory category);

    // --- Sensor Functions ---
    void CheckParentProcessAtStartup();
    void Sensor_DetectVirtualMachine();
    void Sensor_CollectHardwareFingerprint();  //  收集硬件指纹

    void DoCheckIatHooks(ScanContext &context, const BYTE *baseAddress, const IMAGE_IMPORT_DESCRIPTOR *pImportDesc);
    void VerifyModuleSignature(HMODULE hModule);

    // Helper to check if an address belongs to a whitelisted module
    // Helper to check if an address belongs to a whitelisted module
    bool IsAddressInLegitimateModule(PVOID address, std::wstring &outModulePath);

    // 扩展监控辅助函数
    void TrackLargeAllocation(LPVOID address, SIZE_T size);
    void CleanupOldAllocations();
    bool IsPathInWhitelist(const std::wstring &modulePath);
    // 使用“诱饵处理函数”技术动态查找VEH链表的地址
    uintptr_t FindVehListAddress();

    // VM detection helpers
    void DetectVmByCpuid();
    void DetectVmByRegistry();
    void DetectVmByMacAddress();

    // --- Hook Procedures ---
    static LRESULT CALLBACK LowLevelMouseProc(int nCode, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam);
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
    bool HasEvidenceOfType(anti_cheat::CheatCategory category) const
    {
        return m_pimpl->HasEvidenceOfType(category);
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

    // 为句柄关联传感器提供共享数据访问
    std::unordered_map<DWORD, std::chrono::steady_clock::time_point> &GetSuspiciousHandleHolders()
    {
        return m_pimpl->m_suspiciousHandleHolders;
    }

    // --- 提供对输入数据的访问 ---
    RingBuffer<CheatMonitor::Pimpl::MouseMoveEvent> &GetMouseMoveEvents()
    {
        return m_pimpl->m_mouseMoveEvents;
    }
    RingBuffer<CheatMonitor::Pimpl::MouseClickEvent> &GetMouseClickEvents()
    {
        return m_pimpl->m_mouseClickEvents;
    }
    RingBuffer<CheatMonitor::Pimpl::KeyboardEvent> &GetKeyboardEvents()
    {
        return m_pimpl->m_keyboardEvents;
    }
    std::mutex &GetInputMutex()
    {
        return m_pimpl->m_inputMutex;
    }
    HWND GetGameWindow() const
    {
        return m_pimpl->m_hGameWindow;
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
    long long cross_product =
            static_cast<long long>(p2.y - p1.y) * (p3.x - p2.x) - static_cast<long long>(p2.x - p1.x) * (p3.y - p2.y);
    return cross_product == 0;
}

// --- START: Efficient Longest Repeating Substring (Suffix Array + LCP) ---
//
// The original O(n^3) brute-force algorithm was causing severe performance issues.
// It is replaced by a standard and efficient Suffix Array + LCP-Array-based approach.
// The time complexity is now O(n*log^2(n)) due to the sort-based suffix array construction,
// which is a massive improvement and resolves the frame rate drop.

// 结构体：用于存储后缀信息，便于排序
struct Suffix
{
    int index; // 后缀的起始索引
    int rank[2]; // 两个排名，用于排序
};

// 比较函数，用于std::sort
static int CmpSuffix(const struct Suffix &a, const struct Suffix &b)
{
    return (a.rank[0] == b.rank[0]) ? (a.rank[1] < b.rank[1] ? 1 : 0) : (a.rank[0] < b.rank[0] ? 1 : 0);
}

// 构建后缀数组的核心函数
static std::vector<int> BuildSuffixArray(const std::vector<DWORD> &sequence, int n)
{
    std::vector<struct Suffix> suffixes(n);

    // 初始化后缀数组，填充每个后缀的起始索引和初始排名
    for (int i = 0; i < n; i++)
    {
        suffixes[i].index = i;
        suffixes[i].rank[0] = sequence[i];
        suffixes[i].rank[1] = ((i + 1) < n) ? (sequence[i + 1]) : -1;
    }

    // 按照初始排名对后缀进行排序
    std::sort(suffixes.begin(), suffixes.end(), CmpSuffix);

    std::vector<int> inv(n);
    // k从4开始，每次加倍，对所有后缀进行2k长度的排序
    for (int k = 4; k < 2 * n; k = k * 2)
    {
        int rank = 0;
        int prev_rank = suffixes[0].rank[0];
        suffixes[0].rank[0] = rank;
        inv[suffixes[0].index] = 0;

        // 计算新的排名
        for (int i = 1; i < n; i++)
        {
            if (suffixes[i].rank[0] == prev_rank && suffixes[i].rank[1] == suffixes[i - 1].rank[1])
            {
                prev_rank = suffixes[i].rank[0];
                suffixes[i].rank[0] = rank;
            }
            else
            {
                prev_rank = suffixes[i].rank[0];
                suffixes[i].rank[0] = ++rank;
            }
            inv[suffixes[i].index] = i;
        }

        // 更新第二排名
        for (int i = 0; i < n; i++)
        {
            int nextindex = suffixes[i].index + k / 2;
            suffixes[i].rank[1] = (nextindex < n) ? suffixes[inv[nextindex]].rank[0] : -1;
        }

        // 根据新的排名再次排序
        std::sort(suffixes.begin(), suffixes.end(), CmpSuffix);
    }

    std::vector<int> suffixArr(n);
    for (int i = 0; i < n; i++)
        suffixArr[i] = suffixes[i].index;

    return suffixArr;
}

// 使用Kasai算法在O(n)时间内构建LCP数组
static std::vector<int> Kasai(const std::vector<DWORD> &sequence, const std::vector<int> &suffixArr)
{
    int n = suffixArr.size();
    std::vector<int> lcp(n, 0);
    std::vector<int> invSuff(n, 0);

    for (int i = 0; i < n; i++)
        invSuff[suffixArr[i]] = i;

    int k = 0;
    for (int i = 0; i < n; i++)
    {
        if (invSuff[i] == n - 1)
        {
            k = 0;
            continue;
        }
        int j = suffixArr[invSuff[i] + 1];
        while (i + k < n && j + k < n && sequence[i + k] == sequence[j + k])
            k++;
        lcp[invSuff[i]] = k;
        if (k > 0)
            k--;
    }
    return lcp;
}

// 寻找最长重复子串，用于宏检测 (重构后的高效版本)
size_t FindLongestRepeatingSubstring(const std::vector<DWORD> &sequence)
{
    if (sequence.size() < 2)
        return 0;

    int n = sequence.size();

    // 1. 构建后缀数组
    std::vector<int> suffixArr = BuildSuffixArray(sequence, n);

    // 2. 基于后缀数组和原始序列，构建LCP数组
    std::vector<int> lcp = Kasai(sequence, suffixArr);

    // 3. LCP数组中的最大值，就是最长重复子串的长度
    size_t longest = 0;
    for (int i = 0; i < n; i++)
    {
        if (lcp[i] > longest)
        {
            longest = lcp[i];
        }
    }
    return longest;
}
// --- END: Efficient Longest Repeating Substring (Suffix Array + LCP) ---

}  // namespace InputAnalysis
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
    void Execute(ScanContext &context) override
    {
        // 该传感器的逻辑直接从原 Sensor_CheckAdvancedAntiDebug 函数迁移而来
        std::array<std::function<void()>, 6> checks = {
                [&]() {
                    BOOL isDebuggerPresent = FALSE;
                    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent) && isDebuggerPresent)
                    {
                        context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED,
                                            "CheckRemoteDebuggerPresent() API返回true");
                    }
                },
                [&]() {
#ifdef _WIN64
                    auto pPeb = (PPEB)__readgsqword(0x60);
#else
                    auto pPeb = (PPEB)__readfsdword(0x30);
#endif
                    if (pPeb && pPeb->BeingDebugged)
                    {
                        context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED,
                                            "PEB->BeingDebugged 标志位为true");
                    }
                },
                []() { CheckCloseHandleException(); },
                [&]() {
                    CONTEXT ctx = {};
                    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                    if (GetThreadContext(GetCurrentThread(), &ctx))
                    {
                        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0)
                        {
                            context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED,
                                                "检测到硬件断点 (Debug Registers)");
                        }
                    }
                },
                [&]() {
                    SYSTEM_KERNEL_DEBUGGER_INFORMATION info;
                    if (g_pNtQuerySystemInformation &&
                        NT_SUCCESS(g_pNtQuerySystemInformation(SystemKernelDebuggerInformation, &info, sizeof(info),
                                                               NULL)))
                    {
                        if (info.KernelDebuggerEnabled && !info.KernelDebuggerNotPresent)
                        {
                            context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED,
                                                "检测到内核调试器 (NtQuerySystemInformation)");
                        }
                    }
                },
                [&]() {
                    if (IsKernelDebuggerPresent_KUserSharedData())
                    {
                        context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED,
                                            "检测到内核调试器 (KUSER_SHARED_DATA)");
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
    const char *GetName() const override
    {
        return "MemoryScanSensor";
    }

    void Execute(ScanContext &context) override
    {
        const auto &baselineHashes = context.GetModuleBaselineHashes();
        std::vector<HMODULE> hMods(1024);
        DWORD cbNeeded = 0;

        // 获取模块列表
        if (!EnumProcessModules(GetCurrentProcess(), hMods.data(), hMods.size() * sizeof(HMODULE), &cbNeeded))
        {
            return;  // 获取失败，直接返回
        }

        // 如果缓冲区不足，调整大小并重新获取
        if (hMods.size() * sizeof(HMODULE) < cbNeeded)
        {
            hMods.resize(cbNeeded / sizeof(HMODULE));
            if (!EnumProcessModules(GetCurrentProcess(), hMods.data(), hMods.size() * sizeof(HMODULE), &cbNeeded))
            {
                return;  // 再次失败，直接返回
            }
        }

        // 遍历模块
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); ++i)
        {
            ProcessModule(hMods[i], context, baselineHashes);
        }
    }

   private:
    // 处理单个模块的逻辑
    void ProcessModule(HMODULE hModule, ScanContext &context,
                       const std::unordered_map<std::wstring, std::vector<uint8_t>> &baselineHashes)
    {
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
        return;  // 没有导入表，正常情况，直接返回
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
    const char *GetName() const override
    {
        return "IatHookSensor";
    }
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
    const char *GetName() const override
    {
        return "VehHookSensor";
    }
    void Execute(ScanContext &context) override
    {
        const uintptr_t vehListAddress = context.GetVehListAddress();
        if (vehListAddress == 0)
        {
            // 地址未找到，在初始化时已上报，此处静默返回。
            return;
        }

        // 直接使用获取到的绝对地址
        const auto *pVehList = reinterpret_cast<const VECTORED_HANDLER_LIST *>(vehListAddress);
        if (!IsValidPointer(pVehList, sizeof(VECTORED_HANDLER_LIST)))
        {
            context.AddEvidence(anti_cheat::RUNTIME_ERROR, "VEH Hook检测失败: 获取到的链表地址无效。");
            return;
        }

        const LIST_ENTRY *pListHead = &pVehList->List;
        const LIST_ENTRY *pCurrentEntry = pListHead->Flink;
        int handlerIndex = 0;
        constexpr int maxHandlersToScan = 32;

        // 辅助函数处理每个处理程序，避免在关键部分使用 C++ 对象展开
        auto ProcessHandler = [&](const VECTORED_HANDLER_ENTRY *pHandlerEntry, int index) -> bool {
            const PVOID handlerAddress = pHandlerEntry->Handler;
            std::wstring modulePath;

            // 检查处理函数地址是否属于一个已知的、合法的模块
            if (context.IsAddressInLegitimateModule(handlerAddress, modulePath))
            {
                // 增加代码节校验，防御VEH劫持
                HMODULE hModule = NULL;
                if (GetModuleHandleExW(
                            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCWSTR)handlerAddress, &hModule) &&
                    hModule)
                {
                    PVOID codeBase = nullptr;
                    DWORD codeSize = 0;
                    if (GetCodeSectionInfo(hModule, codeBase, codeSize))
                    {
                        uintptr_t handlerAddr = reinterpret_cast<uintptr_t>(handlerAddress);
                        uintptr_t codeStart = reinterpret_cast<uintptr_t>(codeBase);
                        uintptr_t codeEnd = codeStart + codeSize;
                        if (handlerAddr >= codeStart && handlerAddr < codeEnd)
                        {
                            // 地址在合法模块的合法代码节内，安全
                            return true;
                        }
                    }
                }
                // 如果获取模块/代码节信息失败，或地址不在代码节内，视为劫持
                std::wostringstream woss;
                woss << L"检测到VEH处理器被劫持到模块的非代码区. 模块: " << (modulePath.empty() ? L"未知" : modulePath)
                     << L", 地址: 0x" << std::hex << handlerAddress;
                context.AddEvidence(anti_cheat::INTEGRITY_API_HOOK,  // 可考虑新增类别
                                                                     // INTEGRITY_VEH_HIJACK
                                    Utils::WideToString(woss.str()));
                return true;
            }

            // --- 原有的逻辑：处理来自未知模块或Shellcode的VEH ---
            bool hasModule = !modulePath.empty();
            if (hasModule)
            {
                // 将模块路径转换为小写以进行比较
                std::wstring lowerModulePath = modulePath;
                std::transform(lowerModulePath.begin(), lowerModulePath.end(), lowerModulePath.begin(), ::towlower);
                auto whitelistedVEHModules = context.GetWhitelistedVEHModules();
                if (whitelistedVEHModules && whitelistedVEHModules->count(lowerModulePath) == 0)
                {
                    std::wostringstream woss;
                    woss << L"检测到可疑的VEH Hook (Handler #" << index << L").来源: " << modulePath << L", 地址: 0x"
                         << std::hex << handlerAddress;
                    context.AddEvidence(anti_cheat::INTEGRITY_API_HOOK, Utils::WideToString(woss.str()));
                }
            }
            else
            {
                // 处理程序不在任何模块中，可能是 Shellcode
                std::wostringstream woss;
                woss << L"检测到来自Shellcode的VEH Hook (Handler #" << index << L").地址: 0x" << std::hex
                     << handlerAddress;
                context.AddEvidence(anti_cheat::INTEGRITY_API_HOOK, Utils::WideToString(woss.str()));
            }
            return true;
        };

        // 遍历 VEH 链表，使用指针检查避免异常
        while (pCurrentEntry && pCurrentEntry != pListHead && handlerIndex < maxHandlersToScan)
        {
            // 在解引用前验证指针有效性
            if (!IsValidPointer(pCurrentEntry,
                                sizeof(*pCurrentEntry)))  // 替换为实际的指针验证
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
    const char *GetName() const override
    {
        return "InputAutomationSensor";
    }
    void Execute(ScanContext &context) override
    {
        std::vector<CheatMonitor::Pimpl::MouseMoveEvent> local_moves;
        std::vector<CheatMonitor::Pimpl::MouseClickEvent> local_clicks;
        std::vector<CheatMonitor::Pimpl::KeyboardEvent> local_keys;
        {
            std::lock_guard<std::mutex> lock(context.GetInputMutex());
            context.GetMouseMoveEvents().snapshot(local_moves);
            context.GetMouseClickEvents().snapshot(local_clicks);
            context.GetKeyboardEvents().snapshot(local_keys);
            // 清空环形缓冲，避免数据滞留
            context.GetMouseMoveEvents().clear();
            context.GetMouseClickEvents().clear();
            context.GetKeyboardEvents().clear();
        }

        // 1. 鼠标点击规律性检测 (原有逻辑)
        if (local_clicks.size() > 10)
        {
            std::vector<double> deltas;
            for (size_t i = 1; i < local_clicks.size(); ++i)
            {
                deltas.push_back(static_cast<double>(local_clicks[i].time - local_clicks[i - 1].time));
            }
            double stddev = InputAnalysis::CalculateStdDev(deltas);
            if (stddev < 5.0 && stddev > 0)
            {
                context.AddEvidence(anti_cheat::INPUT_AUTOMATION_DETECTED,
                                    "检测到规律性鼠标点击 (StdDev: " + std::to_string(stddev) + "ms)");
            }
        }

        // 2. 鼠标移动直线检测 (原有逻辑)
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

        // 3. 键盘宏序列检测
        if (local_keys.size() > (size_t)CheatConfigManager::GetInstance().GetKeyboardMacroMinSequenceLength())
        {
            std::vector<DWORD> vkCodes;
            vkCodes.reserve(local_keys.size());
            for (const auto &key_event : local_keys)
            {
                vkCodes.push_back(key_event.vkCode);
            }

            size_t longest_pattern = InputAnalysis::FindLongestRepeatingSubstring(vkCodes);
            if (longest_pattern >= (size_t)CheatConfigManager::GetInstance().GetKeyboardMacroMinPatternLength())
            {
                context.AddEvidence(anti_cheat::INPUT_AUTOMATION_DETECTED,
                                    "检测到可疑的键盘宏行为 (重复序列长度: " + std::to_string(longest_pattern) + ")");
            }
        }
    }
};

class OverlaySensor : public ISensor
{
   public:
    const char *GetName() const override
    {
        return "OverlaySensor";
    }

    void Execute(ScanContext &context) override
    {
        HWND hGameWnd = context.GetGameWindow();
        if (!hGameWnd || !IsWindow(hGameWnd))
        {
            return;  // 游戏窗口句柄无效
        }

        RECT gameRect;
        if (!GetWindowRect(hGameWnd, &gameRect))
        {
            return;
        }

        struct EnumWindowsCallbackData
        {
            ScanContext *pContext;
            HWND hGameWnd;
            RECT gameRect;
        };

        EnumWindowsCallbackData callbackData = {&context, hGameWnd, gameRect};

        EnumWindows(
                [](HWND hWnd, LPARAM lParam) -> BOOL {
                    EnumWindowsCallbackData *pCallbackData = reinterpret_cast<EnumWindowsCallbackData *>(lParam);
                    ScanContext *pContext = pCallbackData->pContext;
                    HWND hGameWnd = pCallbackData->hGameWnd;
                    const RECT *pGameRect = &pCallbackData->gameRect;

                    if (hWnd == hGameWnd || !IsWindowVisible(hWnd))
                    {
                        return TRUE;  // 跳过自己和不可见窗口
                    }

                    LONG_PTR style = GetWindowLongPtr(hWnd, GWL_EXSTYLE);
                    if (!(style & WS_EX_LAYERED) && !(style & WS_EX_TRANSPARENT))
                    {
                        return TRUE;  // 只关心分层或透明窗口
                    }

                    RECT overlayRect;
                    if (!GetWindowRect(hWnd, &overlayRect))
                    {
                        return TRUE;
                    }

                    RECT intersection;
                    if (IntersectRect(&intersection, pGameRect, &overlayRect))
                    {
                        // 窗口有重叠
                        DWORD processId = 0;
                        GetWindowThreadProcessId(hWnd, &processId);
                        if (processId > 0)
                        {
                            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
                            if (hProcess)
                            {
                                std::wstring processPath = Utils::GetProcessFullName(hProcess);
                                CloseHandle(hProcess);
                                if (!processPath.empty())
                                {
                                    // 在这里可以加入白名单逻辑，例如忽略obs, discord等
                                    pContext->AddEvidence(anti_cheat::ENVIRONMENT_UNEXPECTED_OVERLAY,
                                                          "检测到可疑的覆盖窗口: " + Utils::WideToString(processPath));
                                }
                            }
                        }
                    }
                    return TRUE;
                },
                reinterpret_cast<LPARAM>(&callbackData));
    }
};

// --- 重量级传感器 ---

class ProcessHandleSensor : public ISensor
{
   public:
    const char *GetName() const override
    {
        return "ProcessHandleSensor";
    }

    // 这个函数被设计为“不安全的”，因为它直接处理可能无效的句柄。
    // 它不使用任何需要对象展开的C++类，因此可以安全地使用 __try/__except。
    // 返回值: 如果句柄确实指向我们自己的进程，则返回true，否则返回false。
    bool IsHandlePointingToUs_Safe(const SYSTEM_HANDLE_TABLE_ENTRY_INFO &handle, DWORD ownPid)
    {
        __try
        {
            // 1. 打开持有句柄的源进程
            // 我们只需要复制句柄的权限，所以请求 PROCESS_DUP_HANDLE 即可。
            HANDLE hOwnerProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, handle.UniqueProcessId);
            if (!hOwnerProcess)
            {
                return false;
            }

            // 2. 将句柄从源进程复制到我们自己的进程中
            HANDLE hDup = nullptr;
            BOOL success = DuplicateHandle(hOwnerProcess, (HANDLE)handle.HandleValue, GetCurrentProcess(), &hDup, 0,
                                           FALSE, DUPLICATE_SAME_ACCESS);

            // 不再需要源进程的句柄，立即关闭
            CloseHandle(hOwnerProcess);

            if (!success || hDup == nullptr)
            {
                return false;
            }

            // 3. 检查复制过来的句柄指向哪个进程
            bool pointsToUs = (GetProcessId(hDup) == ownPid);

            // 必须关闭复制过来的句柄
            CloseHandle(hDup);

            return pointsToUs;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            // 如果在任何步骤发生访问冲突等硬件异常，安全地捕获并返回false。
            return false;
        }
    }

    void Execute(ScanContext &context) override
    {
        const auto &knownGoodProcesses = CheatConfigManager::GetInstance().GetKnownGoodProcesses();

        if (!g_pNtQuerySystemInformation)
            return;

        ULONG bufferSize = 0x10000;
        std::vector<BYTE> handleInfoBuffer(bufferSize);
        NTSTATUS status;

        // 1. 获取系统句柄信息
        do
        {
            status = g_pNtQuerySystemInformation(SystemHandleInformation, handleInfoBuffer.data(), bufferSize, nullptr);
            if (status == STATUS_INFO_LENGTH_MISMATCH)
            {
                bufferSize *= 2;
                if (bufferSize > 0x4000000)  // 64MB 的上限
                {
                    return;
                }
                handleInfoBuffer.resize(bufferSize);
            }
        } while (status == STATUS_INFO_LENGTH_MISMATCH);

        if (!NT_SUCCESS(status))
            return;

        // 2. 准备扫描
        const DWORD ownPid = GetCurrentProcessId();
        const auto *pHandleInfo = reinterpret_cast<const SYSTEM_HANDLE_INFORMATION *>(handleInfoBuffer.data());
        const auto now = std::chrono::steady_clock::now();
        std::unordered_set<DWORD> processedPidsThisScan;

        // 3. 遍历所有系统句柄
        for (ULONG i = 0; i < pHandleInfo->NumberOfHandles; ++i)
        {
            const auto &handle = pHandleInfo->Handles[i];

            // 优化: 跳过...
            // - 我们自己的进程
            // - 本轮扫描已完整分析过的PID
            // - 没有危险访问权限的句柄
            if (handle.UniqueProcessId == ownPid || processedPidsThisScan.count(handle.UniqueProcessId) > 0 ||
                !(handle.GrantedAccess &
                  (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_ALL_ACCESS)))
            {
                continue;
            }

            // 优化: 检查长期缓存
            auto &cache = context.GetProcessVerdictCache();
            auto cacheIt = cache.find(handle.UniqueProcessId);
            if (cacheIt != cache.end())
            {
                if (now <
                    cacheIt->second.second +
                            std::chrono::minutes(CheatConfigManager::GetInstance().GetProcessCacheDurationMinutes()))
                {
                    if (cacheIt->second.first == CheatMonitor::Pimpl::ProcessVerdict::SIGNED_AND_TRUSTED)
                        continue;
                }
                else
                {
                    cache.erase(cacheIt);  // 移除过时条目
                }
            }

            // --- 调用安全的辅助函数来执行危险操作 ---
            if (!IsHandlePointingToUs_Safe(handle, ownPid))
            {
                continue;
            }

            // --- 命中: 该进程持有指向我们的句柄。现在可以安全地进行分析和报告了 ---
            // 在这里，我们已经不在 __try 块中，可以自由使用所有C++特性。

            processedPidsThisScan.insert(handle.UniqueProcessId);  // 关键优化：标记此PID已处理

            // 使用 RAII 来管理句柄生命周期
            using UniqueHandle = std::unique_ptr<void, decltype(&::CloseHandle)>;
            UniqueHandle hOwnerProcess(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, handle.UniqueProcessId),
                                       &::CloseHandle);

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
            Utils::SignatureStatus signatureStatus = Utils::VerifyFileSignature(ownerProcessPath);

            if (knownGoodProcesses->count(lowerProcessName) > 0 && signatureStatus == Utils::SignatureStatus::TRUSTED)
            {
                suspiciousHandleHolders[handle.UniqueProcessId] = now;
                currentVerdict = CheatMonitor::Pimpl::ProcessVerdict::SIGNED_AND_TRUSTED;
            }
            else if (signatureStatus == Utils::SignatureStatus::UNTRUSTED)
            {
                currentVerdict = CheatMonitor::Pimpl::ProcessVerdict::UNSIGNED_OR_UNTRUSTED;
            }
            else  // FAILED_TO_VERIFY
            {
                continue;  // 签名检查失败，为保险起见不做判断
            }

            cache[handle.UniqueProcessId] = {currentVerdict, now};

            if (currentVerdict == CheatMonitor::Pimpl::ProcessVerdict::UNSIGNED_OR_UNTRUSTED)
            {
                context.AddEvidence(anti_cheat::INTEGRITY_SUSPICIOUS_HANDLE,
                                    "可疑进程持有我们进程的句柄: " + Utils::WideToString(ownerProcessPath) +
                                            " (PID: " + std::to_string(handle.UniqueProcessId) + ")");
            }
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

    void Execute(ScanContext &context) override
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
    }
};

class NewActivitySensor : public ISensor
{
   public:
    const char *GetName() const override
    {
        return "NewActivitySensor";
    }
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
                            context.AddEvidence(anti_cheat::RUNTIME_THREAD_NEW_UNKNOWN,
                                                "检测到新线程 (TID: " + std::to_string(te.th32ThreadID) + ")");
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
                        context.AddEvidence(anti_cheat::RUNTIME_MODULE_NEW_UNKNOWN,
                                            "加载了新模块: " + Utils::WideToString(szModName));
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
    const char *GetName() const override
    {
        return "EnvironmentSensor";
    }
    void Execute(ScanContext &context) override
    {
        auto knownGoodProcesses = CheatConfigManager::GetInstance().GetKnownGoodProcesses();

        // 1. 首先，一次性遍历所有窗口，构建一个 PID -> WindowTitles 的映射
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

                // 新增优化：首先通过进程名快速过滤已知的安全进程。
                if (knownGoodProcesses && knownGoodProcesses->count(processName) > 0)
                {
                    continue;
                }

                // 检查点 1: 廉价的进程名黑名单检查
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
                        auto whitelistedProcessPaths = context.GetWhitelistedProcessPaths();
                        if (whitelistedProcessPaths && whitelistedProcessPaths->count(fullProcessPath) > 0)
                        {
                            continue;  // 进程在路径白名单中，安全，继续检查下一个进程
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
                        auto whitelistedWindowKeywords = context.GetWhitelistedWindowKeywords();
                        if (whitelistedWindowKeywords)
                        {
                            for (const auto &whitelistedKeyword : *whitelistedWindowKeywords)
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

            next_process_loop:;
            } while (Process32NextW(hSnapshot.get(), &pe));
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
    void Execute(ScanContext &context) override
    {
        LPBYTE address = nullptr;
        MEMORY_BASIC_INFORMATION mbi;

        // 从地址0开始遍历自身进程的全部用户态内存空间
        while (VirtualQuery(address, &mbi, sizeof(mbi)))
        {
            // 检查是否是私有的、已提交的、可执行的内存区域
            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
                (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
            {
                // 关键一步：检查这块内存是否属于一个已知的、合法的模块。
                // 这可以有效避免将JIT编译器的代码等合法动态内存误报为作弊。
                std::wstring modulePath;
                if (!context.IsAddressInLegitimateModule(mbi.BaseAddress, modulePath))
                {
                    // 如果它不属于任何合法模块，这是一个强烈的可疑信号。
                    std::ostringstream oss;
                    oss << "检测到私有可执行内存. 地址: 0x" << std::hex << reinterpret_cast<uintptr_t>(mbi.BaseAddress)
                        << ", 大小: " << std::dec << mbi.RegionSize << " 字节.";

                    context.AddEvidence(anti_cheat::RUNTIME_MEMORY_EXEC_PRIVATE, oss.str());
                }
            }

            // 移动到下一个内存区域的起始地址
            address = reinterpret_cast<LPBYTE>(mbi.BaseAddress) + mbi.RegionSize;

            // 安全检查：防止因地址回绕导致的无限循环
            if (address < reinterpret_cast<LPBYTE>(mbi.BaseAddress))
            {
                break;
            }
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
    void Execute(ScanContext &context) override
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

    void Execute(ScanContext &context) override
    {
        // 使用智能指针确保快照句柄总是被关闭
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
            do
            {
                if (te.th32OwnerProcessID != currentPid)
                {
                    continue;  // 只关心本进程的线程
                }

                // 使用智能指针确保线程句柄总是被关闭
                using UniqueThreadHandle = std::unique_ptr<void, decltype(snapshot_closer)>;
                UniqueThreadHandle hThread(OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID),
                                           snapshot_closer);

                if (!hThread.get())
                {
                    continue;  // 无法打开线程句柄，可能线程已退出，安全跳过
                }

                // 1. 检测线程起点是否在合法模块中
                PVOID startAddress = nullptr;
                if (g_pNtQueryInformationThread &&
                    NT_SUCCESS(g_pNtQueryInformationThread(hThread.get(),
                                                           (THREADINFOCLASS)9,  // ThreadQuerySetWin32StartAddress
                                                           &startAddress, sizeof(startAddress), nullptr)))
                {
                    if (startAddress)
                    {
                        std::wstring modulePath;  // 用于接收模块路径的输出参数
                        if (!context.IsAddressInLegitimateModule(startAddress, modulePath))
                        {
                            // 起始地址不在任何已知模块中，这是Shellcode的强烈信号
                            std::ostringstream oss;
                            oss << "检测到线程(TID: " << te.th32ThreadID << ") 的起始地址 (0x" << std::hex
                                << startAddress << ") 不在任何已知模块中，疑似Shellcode。";
                            context.AddEvidence(anti_cheat::RUNTIME_THREAD_NEW_UNKNOWN, oss.str());
                        }
                    }
                }

                // 2. 检测线程是否被设置为“对调试器隐藏”
                ULONG isHidden = 0;
                if (g_pNtQueryInformationThread &&
                    NT_SUCCESS(g_pNtQueryInformationThread(hThread.get(),
                                                           (THREADINFOCLASS)17,  // ThreadHideFromDebugger
                                                           &isHidden, sizeof(isHidden), nullptr)))
                {
                    if (isHidden)
                    {
                        // 我们自己的监控线程不应该被隐藏，所以任何隐藏的线程都值得怀疑
                        std::ostringstream oss;
                        oss << "检测到线程(TID: " << te.th32ThreadID << ") 被设置为对调试器隐藏。";
                        context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, oss.str());
                    }
                }

            } while (Thread32Next(hThreadSnapshot.get(), &te));
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
    void Execute(ScanContext &context) override
    {
        MEMORY_BASIC_INFORMATION mbi;
        LPBYTE address = nullptr;

        while (VirtualQuery(address, &mbi, sizeof(mbi)))
        {
            // 检查可执行内存区域
            if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
            {
                HMODULE hMod = nullptr;
                // 尝试获取该地址对应的模块句柄
                if (!GetModuleHandleExW(
                            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCWSTR)mbi.BaseAddress, &hMod))
                {
                    // 检查是否是系统保留区域或已知的合法内存
                    if (reinterpret_cast<uintptr_t>(mbi.BaseAddress) > 0x10000 &&  // 跳过NULL页附近
                        mbi.RegionSize > 0x1000)                                   // 只关注较大的内存区域

                    {
                        std::ostringstream oss;
                        oss << "检测到隐藏的可执行内存区域: 0x" << std::hex
                            << reinterpret_cast<uintptr_t>(mbi.BaseAddress) << " 大小: " << std::dec << mbi.RegionSize
                            << " 字节";

                        context.AddEvidence(anti_cheat::INTEGRITY_MEMORY_PATCH, oss.str());
                    }
                }
            }
            address = reinterpret_cast<LPBYTE>(mbi.BaseAddress) + mbi.RegionSize;

            // 防止无限循环
            if (address < reinterpret_cast<LPBYTE>(mbi.BaseAddress))
                break;
        }
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

CheatMonitor::Pimpl *CheatMonitor::Pimpl::s_pimpl_for_hooks = nullptr;
LRESULT CALLBACK CheatMonitor::Pimpl::LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode == HC_ACTION && s_pimpl_for_hooks)
    {
        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)
        {
            KBDLLHOOKSTRUCT *pkbhs = (KBDLLHOOKSTRUCT *)lParam;
            if (pkbhs)
            {
                std::lock_guard<std::mutex> lock(s_pimpl_for_hooks->m_inputMutex);
                s_pimpl_for_hooks->m_keyboardEvents.push({pkbhs->vkCode, pkbhs->time});
            }
        }
    }
    return CallNextHookEx(s_pimpl_for_hooks->m_hKeyboardHook, nCode, wParam, lParam);
}

CheatMonitor &CheatMonitor::GetInstance()
{
    static CheatMonitor instance;
    return instance;
}

CheatMonitor::Pimpl::Pimpl()
    : m_mouseMoveEvents(CheatConfigManager::GetInstance().GetMaxMouseMoveEvents()),
      m_mouseClickEvents(CheatConfigManager::GetInstance().GetMaxMouseClickEvents()),
      m_keyboardEvents(CheatConfigManager::GetInstance().GetMaxKeyboardEvents())
{
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

    Pimpl::s_pimpl_for_hooks = m_pimpl.get();

    m_pimpl->m_hookOwnerThreadId = GetCurrentThreadId();
    m_pimpl->m_hMouseHook = SetWindowsHookEx(WH_MOUSE_LL, Pimpl::LowLevelMouseProc, GetModuleHandle(NULL), 0);

    m_pimpl->m_hKeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, Pimpl::LowLevelKeyboardProc, GetModuleHandle(NULL), 0);

    if (!m_pimpl->m_hMouseHook || !m_pimpl->m_hKeyboardHook)
    {
        std::cout << "[AntiCheat] Initialize Error: Failed to set hooks. Mouse: " << (m_pimpl->m_hMouseHook != NULL)
                  << ", Keyboard: " << (m_pimpl->m_hKeyboardHook != NULL) << " Error code: " << GetLastError()
                  << std::endl;
        return false;
    }

    try
    {
        m_pimpl->m_monitorThread = std::thread(&Pimpl::MonitorLoop, m_pimpl.get());
    }
    catch (const std::system_error &e)
    {
        std::cout << "[AntiCheat] Initialize Error: Failed to create monitor "
                     "thread. Error: "
                  << e.what() << std::endl;
        if (m_pimpl->m_hMouseHook)
            UnhookWindowsHookEx(m_pimpl->m_hMouseHook);
        if (m_pimpl->m_hKeyboardHook)
            UnhookWindowsHookEx(m_pimpl->m_hKeyboardHook);

        m_pimpl->m_hMouseHook = NULL;
        m_pimpl->m_hKeyboardHook = NULL;
        return false;
    }

    m_pimpl->m_isSystemActive = true;
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

    // 关键改动：调整卸载和清理顺序
    // 1. 立即卸载钩子，停止接收新的回调
    if (m_pimpl->m_hMouseHook)
        UnhookWindowsHookEx(m_pimpl->m_hMouseHook);
    if (m_pimpl->m_hKeyboardHook)
        UnhookWindowsHookEx(m_pimpl->m_hKeyboardHook);
    m_pimpl->m_hMouseHook = NULL;
    m_pimpl->m_hKeyboardHook = NULL;

    // 2. 等待工作线程完全结束。这是最重要的同步点。
    if (m_pimpl->m_monitorThread.joinable())
    {
        m_pimpl->m_monitorThread.join();
    }

    // 3. 在所有线程活动结束后，才安全地将静态指针置空
    Pimpl::s_pimpl_for_hooks = nullptr;

    // 4. 最后清理Pimpl实例
    m_pimpl.reset();
}

bool CheatMonitor::IsCallerLegitimate()
{
    // This function must be fast and safe, as it can be called from
    // performance-critical game logic.
    if (!m_pimpl || !m_pimpl->m_isSystemActive.load())
    {
        // If the system isn't active, conservatively deny legitimacy.
        return false;
    }

    // Use the intrinsic to get the return address of the function that called
    // IsCallerLegitimate.
    PVOID caller_address = _ReturnAddress();

    // Now, find which module this address belongs to.
    HMODULE hModule = NULL;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)caller_address, &hModule) &&
        hModule)
    {
        wchar_t modulePath_w[MAX_PATH];
        if (GetModuleFileNameW(hModule, modulePath_w, MAX_PATH) > 0)
        {
            std::wstring modulePath(modulePath_w);
            // Normalize the path for consistent comparison.
            std::transform(modulePath.begin(), modulePath.end(), modulePath.begin(), ::towlower);

            // CRITICAL: Lock the mutex before accessing the shared set of legitimate
            // module paths.
            std::lock_guard<std::mutex> lock(m_pimpl->m_modulePathsMutex);
            if (m_pimpl->m_legitimateModulePaths.count(modulePath) > 0)
            {
                return true;  // The caller is from a known, legitimate module.
            }
        }
    }

    // By default, if the caller's module cannot be identified or is not in the
    // list, it's not legitimate.
    return false;
}

void CheatMonitor::Pimpl::InitializeSystem()
{
    m_rng.seed(m_rd());
    m_isSessionActive = false;

    // --- 传感器注册 ---
    // 轻量级传感器 (高频执行)
    m_lightweight_sensors.emplace_back(std::make_unique<Sensors::AdvancedAntiDebugSensor>());
    m_lightweight_sensors.emplace_back(std::make_unique<Sensors::SystemIntegritySensor>());
    m_lightweight_sensors.emplace_back(std::make_unique<Sensors::IatHookSensor>());
    m_lightweight_sensors.emplace_back(std::make_unique<Sensors::VehHookSensor>());
    m_lightweight_sensors.emplace_back(std::make_unique<Sensors::InputAutomationSensor>());
    m_lightweight_sensors.emplace_back(std::make_unique<Sensors::SuspiciousLaunchSensor>());

    // 重量级传感器 (低频执行)
    m_heavyweight_sensors.emplace_back(std::make_unique<Sensors::MemoryScanSensor>());
    m_heavyweight_sensors.emplace_back(std::make_unique<Sensors::ProcessHandleSensor>());
    m_heavyweight_sensors.emplace_back(std::make_unique<Sensors::HandleCorrelationSensor>());
    m_heavyweight_sensors.emplace_back(std::make_unique<Sensors::NewActivitySensor>());
    m_heavyweight_sensors.emplace_back(std::make_unique<Sensors::EnvironmentSensor>());
    m_heavyweight_sensors.emplace_back(std::make_unique<Sensors::PrivateExecutableMemorySensor>());
    m_heavyweight_sensors.emplace_back(std::make_unique<Sensors::HiddenModuleSensor>());
    m_heavyweight_sensors.emplace_back(std::make_unique<Sensors::ThreadIntegritySensor>());

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

    std::cout << "[AntiCheat] Initializing process baseline..." << std::endl;

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

    // 5. 收集硬件指纹 (如果尚未收集)
    if (!m_fingerprint)
    {
        Sensor_CollectHardwareFingerprint();
    }

    AddEvidence(anti_cheat::SYSTEM_INITIALIZED, "Process baseline established.");
    m_processBaselineEstablished = true;
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
    m_evidenceOverflowed = false;

    // 清空输入事件的缓冲区
    {
        std::lock_guard<std::mutex> input_lock(m_inputMutex);
        m_mouseMoveEvents.clear();
        m_mouseClickEvents.clear();
        m_keyboardEvents.clear();
    }
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
            std::cout << "[AntiCheat] Player " << m_pimpl->m_currentUserName << " logged out. Session ended."
                      << std::endl;
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
        m_pimpl->m_hasServerConfig = true;
        // 立即唤醒监控线程，以便它可以根据新配置开始扫描
        m_pimpl->m_cv.notify_one();
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

    std::cout << "[AntiCheat] Evidence added: " << description << std::endl;
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
    if (m_evidences.empty() && !m_fingerprint)
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

    // 如果有硬件指纹，则附加并清空
    if (m_fingerprint)
    {
        *report.mutable_fingerprint() = *m_fingerprint;
        m_fingerprint.reset();
    }

    // TODO: 将 report 序列化并通过网络发送到服务器
    std::string serialized_report;
    if (report.SerializeToString(&serialized_report))
    {
        std::cout << "[AntiCheat] Uploading report... Size: " << serialized_report.length() << " bytes. "
                  << report.evidences_size() << " evidences." << std::endl;
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

        // 核心逻辑：只有在会话激活并且已收到服务器配置后才执行扫描
        if (!m_isSessionActive.load() || !m_hasServerConfig.load())
        {
            continue;
        }

        const auto now = std::chrono::steady_clock::now();

        // --- 轻量级扫描调度 ---
        if (!m_lightweight_sensors.empty())
        {
            m_lightSensorIndex %= m_lightweight_sensors.size();
            ScanContext context(this);
            m_lightweight_sensors[m_lightSensorIndex]->Execute(context);
            m_lightSensorIndex++;
        }

        // --- 重量级扫描调度 ---
        if (now >= next_heavy_scan)
        {
            if (!m_heavyweight_sensors.empty())
            {
                m_heavySensorIndex %= m_heavyweight_sensors.size();
                ScanContext context(this);
                m_heavyweight_sensors[m_heavySensorIndex]->Execute(context);
                m_heavySensorIndex++;
            }
            // 从CheatConfigManager获取动态扫描间隔
            next_heavy_scan =
                    now + std::chrono::minutes(CheatConfigManager::GetInstance().GetHeavyScanIntervalMinutes());
        }

        // --- 报告上传调度 ---
        if (now >= next_report_upload)
        {
            std::lock_guard<std::mutex> lock(m_sessionMutex);
            UploadReport();
            // 从CheatConfigManager获取动态上传间隔
            next_report_upload =
                    now + std::chrono::minutes(CheatConfigManager::GetInstance().GetReportUploadIntervalMinutes());
        }

        // 增加随机抖动，避免可预测的扫描周期
        std::uniform_int_distribution<long> jitter_dist(0, CheatConfigManager::GetInstance().GetJitterMilliseconds());
        std::this_thread::sleep_for(std::chrono::milliseconds(jitter_dist(m_rng)));
    }
    std::cout << "[AntiCheat] Monitor thread finished." << std::endl;
}

void CheatMonitor::Pimpl::HardenProcessAndThreads()
{
    // 1. 启用进程缓解策略 (DEP, 禁止创建子进程等)
    // 动态加载 SetProcessMitigationPolicy
    typedef BOOL(WINAPI * PSetProcessMitigationPolicy)(PROCESS_MITIGATION_POLICY Policy, PVOID lpBuffer,
                                                       SIZE_T dwLength);
    static PSetProcessMitigationPolicy pSetProcessMitigationPolicy = (PSetProcessMitigationPolicy)GetProcAddress(
            GetModuleHandleW(L"kernel32.dll"), "SetProcessMitigationPolicy");

    if (pSetProcessMitigationPolicy)
    {
        // 启用DEP
        PROCESS_MITIGATION_DEP_POLICY depPolicy = {};
        depPolicy.Enable = 1;
        depPolicy.Permanent = true;
        pSetProcessMitigationPolicy(ProcessDEPPolicy, &depPolicy, sizeof(depPolicy));

        // 禁止创建子进程
        PROCESS_MITIGATION_CHILD_PROCESS_POLICY childPolicy = {};
        childPolicy.NoChildProcessCreation = 1;
        pSetProcessMitigationPolicy(ProcessChildProcessPolicy, &childPolicy, sizeof(childPolicy));
    }
    else
    {
        AddEvidence(anti_cheat::RUNTIME_ERROR, "SetProcessMitigationPolicy API 不可用，无法启用进程缓解策略。");
    }

    // 2. 隐藏我们自己的监控线程，增加逆向分析难度
    if (g_pNtSetInformationThread)
    {
        g_pNtSetInformationThread(GetCurrentThread(), (THREADINFOCLASS)17,  // ThreadHideFromDebugger
                                  nullptr, 0);
    }
}

void CheatMonitor::Pimpl::CheckParentProcessAtStartup()
{
    DWORD parentPid = 0;
    std::string parentName;
    if (Utils::GetParentProcessInfo(parentPid, parentName))
    {
        std::transform(parentName.begin(), parentName.end(), parentName.begin(), ::tolower);
        // TODO: Replace m_legitimateParentProcesses with a configurable list
        // if (m_legitimateParentProcesses.find(parentName) == m_legitimateParentProcesses.end())
        // {
        //     AddEvidence(anti_cheat::ENVIRONMENT_INVALID_PARENT_PROCESS,
        //                 "由一个非法的父进程启动: " + parentName + " (PID: " + std::to_string(parentPid) + ")");
        // }
    }
    else
    {
        // 如果在启动时无法获取父进程信息，这本身就是一个可疑信号。
        // 我们先记录这个状态，后续可以与其他证据进行关联分析。
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

void CheatMonitor::Pimpl::Sensor_CollectHardwareFingerprint()
{
    m_fingerprint = std::make_unique<anti_cheat::HardwareFingerprint>();

    // 1. Disk Serial
    DWORD serialNum = 0;
    if (GetVolumeInformationW(L"C:\\", NULL, 0, &serialNum, NULL, NULL, NULL, 0))
    {
        m_fingerprint->set_disk_serial(std::to_string(serialNum));
    }

    // 2. MAC Addresses
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
            m_fingerprint->add_mac_addresses(macStr);
            pAdapterInfo = pAdapterInfo->Next;
        }
    }

    // 3. Computer Name
    wchar_t computerName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(computerName, &size))
    {
        m_fingerprint->set_computer_name(Utils::WideToString(computerName));
    }

    // 4. OS Version
    // 使用 RtlGetVersion 获取准确的OS版本信息
    typedef NTSTATUS(WINAPI * RtlGetVersion_t)(LPOSVERSIONINFOEXW lpVersionInformation);
    static RtlGetVersion_t pRtlGetVersion =
            (RtlGetVersion_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");

    if (pRtlGetVersion)
    {
        OSVERSIONINFOEXW osInfo = {0};
        osInfo.dwOSVersionInfoSize = sizeof(osInfo);
        if (NT_SUCCESS(pRtlGetVersion(&osInfo)))
        {
            std::wstringstream wss;
            wss << L"Windows " << osInfo.dwMajorVersion << L"." << osInfo.dwMinorVersion << L" (Build "
                << osInfo.dwBuildNumber << L")";
            m_fingerprint->set_os_version(Utils::WideToString(wss.str()));
        }
    }
    else
    {
        // Fallback for very old systems if RtlGetVersion is not available
        OSVERSIONINFOEXW osInfo;
        osInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
        if (GetVersionExW((LPOSVERSIONINFOW)&osInfo))
        {
            std::wstringstream wss;
            wss << L"Windows " << osInfo.dwMajorVersion << L"." << osInfo.dwMinorVersion << L" (Build "
                << osInfo.dwBuildNumber << L")";
            m_fingerprint->set_os_version(Utils::WideToString(wss.str()));
        }
    }

    // 5. CPU Info
    std::array<int, 4> cpuid_info;
    char cpu_brand[0x40];
    __cpuid(cpuid_info.data(), 0x80000000);
    unsigned int nExIds = cpuid_info[0];
    memset(cpu_brand, 0, sizeof(cpu_brand));
    for (unsigned int i = 0x80000000; i <= nExIds; ++i)
    {
        __cpuid(cpuid_info.data(), i);
        if (i == 0x80000002)
            memcpy(cpu_brand, cpuid_info.data(), sizeof(cpuid_info));
        else if (i == 0x80000003)
            memcpy(cpu_brand + 16, cpuid_info.data(), sizeof(cpuid_info));
        else if (i == 0x80000004)
            memcpy(cpu_brand + 32, cpuid_info.data(), sizeof(cpuid_info));
    }
    m_fingerprint->set_cpu_info(cpu_brand);

    AddEvidence(anti_cheat::SYSTEM_FINGERPRINT, "硬件指纹收集完成。");
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

void CheatMonitor::Pimpl::VerifyModuleSignature(HMODULE hModule)
{
    wchar_t modulePath_w[MAX_PATH];
    if (GetModuleFileNameW(hModule, modulePath_w, MAX_PATH) == 0)
    {
        return;
    }
    std::wstring modulePath(modulePath_w);
    std::transform(modulePath.begin(), modulePath.end(), modulePath.begin(), ::towlower);

    const auto now = std::chrono::steady_clock::now();
    {
        std::lock_guard<std::mutex> lock(m_signatureCacheMutex);
        auto it = m_moduleSignatureCache.find(modulePath);
        if (it != m_moduleSignatureCache.end())
        {
            // Check cache expiry
            if (now < it->second.second + std::chrono::minutes(
                                                  CheatConfigManager::GetInstance().GetSignatureCacheDurationMinutes()))
            {
                return;  // Still valid, no need to re-verify
            }
        }
    }

    SignatureVerdict verdict = SignatureVerdict::VERIFICATION_FAILED;
    switch (Utils::VerifyFileSignature(modulePath))
    {
        case Utils::SignatureStatus::TRUSTED:
            verdict = SignatureVerdict::SIGNED_AND_TRUSTED;
            break;
        case Utils::SignatureStatus::UNTRUSTED:
            verdict = SignatureVerdict::UNSIGNED_OR_UNTRUSTED;
            AddEvidence(anti_cheat::RUNTIME_MODULE_NEW_UNKNOWN,
                        "加载了未签名的模块: " + Utils::WideToString(modulePath));
            break;
        case Utils::SignatureStatus::FAILED_TO_VERIFY:
            verdict = SignatureVerdict::VERIFICATION_FAILED;
            break;
    }

    {
        std::lock_guard<std::mutex> lock(m_signatureCacheMutex);
        m_moduleSignatureCache[modulePath] = {verdict, now};
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
    RTL_OSVERSIONINFOW osInfo = {sizeof(osInfo)};
    if (GetVersionExW((LPOSVERSIONINFOW)&osInfo))
    {
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
    }
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

// Fallback: 增强遍历，版本适应
uintptr_t FallbackFindVehListAddress(WindowsVersion ver)
{
    PVOID pVehHandler = AddVectoredExceptionHandler(
            1, DecoyVehHandler);  // DecoyVehHandler需定义为LONG CALLBACK (EXCEPTION_POINTERS*)
    if (!pVehHandler)
    {
        std::cout << "Failed to add VEH in fallback" << std::endl;
        return 0;
    }

    uintptr_t address = 0;
    __try
    {
        const auto *pEntry = reinterpret_cast<const PVECTORED_HANDLER_ENTRY>(pVehHandler);
        const LIST_ENTRY *pCurrent = &pEntry->List;

        // 增加深度到100，XP考虑循环链表
        for (int i = 0; i < 100; ++i)
        {
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery(pCurrent->Blink, &mbi, sizeof(mbi)) == 0 || mbi.State != MEM_COMMIT ||
                (mbi.Protect & (PAGE_READWRITE | PAGE_READONLY)) == 0)
            {
                break;
            }

            if (pCurrent->Blink->Flink == pCurrent)  // 头检测
            {
                // 版本偏移
                if (ver == Win_XP)
                {
                    address = reinterpret_cast<uintptr_t>(pCurrent) - offsetof(VECTORED_HANDLER_LIST_XP, List);
                }
                else if (ver == Win_Vista_Win7)
                {
                    address = reinterpret_cast<uintptr_t>(pCurrent) -
                              offsetof(VECTORED_HANDLER_LIST_VISTA, ExceptionList);
                }
                else
                {
                    address =
                            reinterpret_cast<uintptr_t>(pCurrent) - offsetof(VECTORED_HANDLER_LIST_WIN8, ExceptionList);
                }
                break;
            }
            pCurrent = pCurrent->Blink;

            // XP防循环：如果回自身，break
            if (ver == Win_XP && pCurrent == &pEntry->List)
                break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        std::cout << "Exception in fallback" << GetExceptionCode() << std::endl;
        address = 0;
    }

    RemoveVectoredExceptionHandler(pVehHandler);
    return address;
}

uintptr_t CheatMonitor::Pimpl::FindVehListAddress()
{
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll)
    {
        std::cout << "Failed to get ntdll handle" << std::endl;
        ;
        return 0;
    }

    // 获取.text段
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hNtdll);
    PIMAGE_NT_HEADERS ntHeader =
            reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE *>(hNtdll) + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeader);
    PBYTE textBase = nullptr;
    SIZE_T textSize = 0;
    for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i)
    {
        if (strncmp(reinterpret_cast<char *>(section->Name), ".text", 6) == 0)
        {
            textBase = reinterpret_cast<PBYTE>(hNtdll) + section->VirtualAddress;
            textSize = section->Misc.VirtualSize;
            break;
        }
        ++section;
    }
    if (!textBase || textSize == 0)
    {
        std::cout << "Failed to find .text section" << std::endl;
        return 0;
    }

    WindowsVersion ver = GetWindowsVersion();
    if (ver == Win_Unknown)
    {
        std::cout << "Unknown Windows version" << std::endl;
        return FallbackFindVehListAddress(ver);
    }

    // 版本特定x86 pattern：基于逆向，针对RtlAddVectoredExceptionHandler开头 + lea eax, [LdrpVectorHandlerList]
    // XP: 简单push ebp; mov ebp,esp; sub esp,10h; ... lea eax, [addr]
    BYTE patternXP[] = {0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x8B, 0x45, 0x08, 0x8D, 0x0D};  // 通配偏移
    // Vista/Win7: sub esp,20h; mov edi, [esp+24h]; lea ecx, [Ldrp...]
    BYTE patternVista[] = {0x83, 0xEC, 0x20, 0x8B, 0x7C, 0x24, 0x24, 0x8D, 0x0D};
    // Win8/Win81: 类似Win7，但偏移变
    BYTE patternWin8[] = {0x83, 0xEC, 0x20, 0x8B, 0xF9, 0x8D, 0x0D};  // lea ecx, [...]
    // Win10: push ebp; mov ebp,esp; sub esp,20h; mov esi, [ebp+8]; lea ecx, [...]
    BYTE patternWin10[] = {0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x20, 0x8B, 0x75, 0x08, 0x8D, 0x0D};
    // Win11 (24H2兼容): 类似Win10，无重大变
    BYTE patternWin11[] = {0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x20, 0x8B, 0xF2, 0x8D, 0x0D};

    const BYTE *pattern = nullptr;
    SIZE_T patternSize = 0;
    SIZE_T offsetAdj = 0;  // 模式后到偏移的字节

    switch (ver)
    {
        case Win_XP:
            pattern = patternXP;
            patternSize = sizeof(patternXP);
            offsetAdj = 7;  // 调整基于逆向
            break;
        case Win_Vista_Win7:
            pattern = patternVista;
            patternSize = sizeof(patternVista);
            offsetAdj = 8;
            break;
        case Win_8_Win81:
            pattern = patternWin8;
            patternSize = sizeof(patternWin8);
            offsetAdj = 6;
            break;
        case Win_10:
            pattern = patternWin10;
            patternSize = sizeof(patternWin10);
            offsetAdj = 9;
            break;
        case Win_11:
            pattern = patternWin11;
            patternSize = sizeof(patternWin11);
            offsetAdj = 9;
            break;
    }

    PBYTE match = FindPattern(textBase, textSize, pattern, patternSize);
    if (!match)
    {
        std::cout << "Pattern not found" << std::endl;
        return FallbackFindVehListAddress(ver);
    }

    // 提取相对偏移 (x86: EIP-relative, 4字节)
    INT32 offset = *reinterpret_cast<INT32 *>(match + patternSize);
    uintptr_t address = reinterpret_cast<uintptr_t>(match + patternSize + 4 + offset);  // EIP + offset

    // 验证内存（.data或.mrdata，可读）
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) == 0 || mbi.State != MEM_COMMIT ||
        (mbi.Protect & PAGE_READWRITE) == 0)
    {
        std::cout << "Invalid VEH list memory" << std::endl;
        return 0;
    }

    // 调整地址到ExceptionList（基于版本偏移）
    switch (ver)
    {
        case Win_XP:
            address += offsetof(VECTORED_HANDLER_LIST_XP, List);
            break;
        case Win_Vista_Win7:
            address += offsetof(VECTORED_HANDLER_LIST_VISTA, ExceptionList);
            break;
        default:  // Win8+
            address += offsetof(VECTORED_HANDLER_LIST_WIN8, ExceptionList);
            break;
    }

    return address;
}

void CheatMonitor::Pimpl::InstallExtendedApiHooks()
{
    // TODO: Implement safe IAT hooking for extended APIs
}

void CheatMonitor::Pimpl::UninstallExtendedApiHooks()
{
    // TODO: Implement safe IAT unhooking for extended APIs
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
            s_pimpl_for_hooks->AddEvidence(anti_cheat::INPUT_AUTOMATION_DETECTED,
                                           "检测到注入的鼠标事件 (LLMHF_INJECTED flag)");
        }

        {
            std::lock_guard<std::mutex> lock(s_pimpl_for_hooks->m_inputMutex);  // [修复] 加锁保护并发写入
            if (wParam == WM_LBUTTONDOWN || wParam == WM_RBUTTONDOWN)
            {
                if (s_pimpl_for_hooks->m_mouseClickEvents.size() <
                    (size_t)CheatConfigManager::GetInstance().GetMaxMouseClickEvents())
                {
                    s_pimpl_for_hooks->m_mouseClickEvents.push({pMouseStruct->time});
                }
            }
            else if (wParam == WM_MOUSEMOVE)
            {
                if (s_pimpl_for_hooks->m_mouseMoveEvents.size() <
                    (size_t)CheatConfigManager::GetInstance().GetMaxMouseClickEvents())
                {
                    s_pimpl_for_hooks->m_mouseMoveEvents.push({pMouseStruct->pt, pMouseStruct->time});
                }
            }
        }
    }
    // 务必调用 CallNextHookEx 将消息传递给钩子链中的下一个钩子
    return CallNextHookEx(s_pimpl_for_hooks->m_hMouseHook, nCode, wParam, lParam);
}