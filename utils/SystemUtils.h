#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <cstdint>

// Forward declarations
namespace AntiCheatLogger {
    enum class LogCategory;
}

// Windows XP/Vista Compatibility Macros
#ifndef CALG_SHA_256
#define CALG_SHA_256 (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256)
#endif

#ifndef ALG_SID_SHA_256
#define ALG_SID_SHA_256 12
#endif

#ifndef CERT_SHA256_HASH_PROP_ID
#define CERT_SHA256_HASH_PROP_ID 107
#endif


// System Information Structures
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

const int CustomSystemCodeIntegrityInformation = 103;

// VEH Structures
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

// System Handle Structures
#ifndef SystemHandleInformation
#define SystemHandleInformation 16
#endif

#ifndef SystemExtendedHandleInformation
#define SystemExtendedHandleInformation 64
#endif

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

typedef struct _SYSTEM_HANDLE_INFORMATION_LEGACY
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION_LEGACY, *PSYSTEM_HANDLE_INFORMATION_LEGACY;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004L
#endif

#ifndef STATUS_INVALID_INFO_CLASS
#define STATUS_INVALID_INFO_CLASS 0xC0000003L
#endif

#ifndef STATUS_NOT_IMPLEMENTED
#define STATUS_NOT_IMPLEMENTED 0xC0000002L
#endif

typedef struct _THREAD_BASIC_INFORMATION
{
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    KPRIORITY BasePriority;
    KPRIORITY LastBasePriority;
    ULONG SubProcessTag;
    PVOID ActiveProcessAffinityPort;
    ULONG GrantedAccess;
    ULONG Flags;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

// NT API Typedefs
extern "C" {
    typedef NTSTATUS(WINAPI *NtQueryInformationThread_t)(HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
    typedef NTSTATUS(WINAPI *NtQuerySystemInformation_t)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    typedef NTSTATUS(WINAPI *PNtSetInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
                                                      PVOID ThreadInformation, ULONG ThreadInformationLength);
    typedef enum _PROCESS_INFO_CLASS_INTERNAL
    {
        InternalProcessBasicInformation = 0,
        InternalProcessDebugPort = 7,
        InternalProcessDebugFlags = 31,
        InternalProcessDebugObjectHandle = 30
    } PROCESS_INFO_CLASS_INTERNAL;
    typedef NTSTATUS(WINAPI *NtQueryInformationProcess_t)(HANDLE, PROCESS_INFO_CLASS_INTERNAL, PVOID, ULONG, PULONG);
    typedef NTSTATUS(WINAPI *NtQuerySystemInformation_t)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
}

// LDR_DLL_NOTIFICATION Definitions
#ifndef LDR_DLL_NOTIFICATION_REASON_LOADED
#define LDR_DLL_NOTIFICATION_REASON_LOADED 1
#endif

#ifndef LDR_DLL_NOTIFICATION_REASON_UNLOADED
#define LDR_DLL_NOTIFICATION_REASON_UNLOADED 2
#endif

typedef struct _LDR_DLL_LOAD_NOTIFICATION_DATA {
    ULONG Flags;            // Reserved
    PCUNICODE_STRING FullDllName;
    PCUNICODE_STRING BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
} LDR_DLL_LOAD_NOTIFICATION_DATA, *PLDR_DLL_LOAD_NOTIFICATION_DATA;

typedef struct _LDR_DLL_UNLOAD_NOTIFICATION_DATA {
    ULONG Flags;            // Reserved
    PCUNICODE_STRING FullDllName;
    PCUNICODE_STRING BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
} LDR_DLL_UNLOAD_NOTIFICATION_DATA, *PLDR_DLL_UNLOAD_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA {
    LDR_DLL_LOAD_NOTIFICATION_DATA Loaded;
    LDR_DLL_UNLOAD_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;

typedef VOID (CALLBACK *PLDR_DLL_NOTIFICATION_FUNCTION)(
    ULONG NotificationReason,
    const LDR_DLL_NOTIFICATION_DATA *NotificationData,
    PVOID Context
);

namespace SystemUtils
{
    enum class ApiCapability : uint64_t
    {
        ProcessQueryLimitedInformation = 1ull << 0,  // Vista+
        LdrDllNotification = 1ull << 1,              // Win8+
        ProcessMitigationPolicy = 1ull << 2,         // Win8+
        WmiAsyncProcessMonitor = 1ull << 3,          // Prefer Vista+; XP falls back
    };

    // Global API Pointers
    extern NtQueryInformationThread_t g_pNtQueryInformationThread;
    extern NtQuerySystemInformation_t g_pNtQuerySystemInformation;
    extern PNtSetInformationThread g_pNtSetInformationThread;
    extern NtQueryInformationProcess_t g_pNtQueryInformationProcess;

    void EnsureNtApisLoaded();

    enum WindowsVersion
    {
        Win_XP,
        Win_Vista_Win7,
        Win_8_Win81,
        Win_10,
        Win_11,
        Win_Unknown
    };

    WindowsVersion GetWindowsVersion();
    uint64_t GetApiCapabilityMask();
    bool HasApiCapability(ApiCapability capability);
    DWORD GetProcessQueryAccessMask();

    bool GetModuleCodeSectionInfo(HMODULE hModule, PVOID &outBase, DWORD &outSize);
    PBYTE FindPattern(PBYTE base, SIZE_T size, const BYTE *pattern, SIZE_T patternSize, BYTE wildcard = 0x00);

    struct CallerValidationResult
    {
        bool success = false;
        HMODULE hModule = nullptr;
        bool inCodeSection = false;
        bool hasModulePath = false;
        wchar_t modulePath[MAX_PATH] = {0};
    };

    CallerValidationResult CheckCallerAddressSafe(PVOID caller_address);
    std::wstring SystemNormalizePathLowercase(const std::wstring &input);
    std::wstring NormalizeKernelPathToWinPath(const std::wstring &input);
    int IsVbsEnabled();
    bool IsValidPointer(const void *ptr, size_t size);
    bool IsReadableMemory(const void *ptr, size_t size);

    // Decoy Handler for VEH detection
    LONG WINAPI DecoyVehHandler(PEXCEPTION_POINTERS ExceptionInfo);

    void CheckCloseHandleException();
    bool IsKernelDebuggerPresent_KUserSharedData();
    std::vector<uint8_t> CalculateFnv1aHash(const BYTE *data, size_t size);
    void DumpPESections(const std::wstring &filePath);
    std::string CalculateModuleHashFromDisk(const std::wstring &filePath);

    struct MemoryReadResult
    {
        bool success = false;
        SIZE_T bytesRead = 0;
        bool exceptionRaised = false;
        DWORD exceptionCode = 0;
        DWORD lastError = 0;
    };

    MemoryReadResult ReadProcessMemorySafe(LPCVOID address, BYTE *buffer, SIZE_T size);

    bool IsSystemDirectoryPath(const std::wstring &path);
}
