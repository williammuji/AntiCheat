#include "SystemUtils.h"
#include "Utils.h"
// SystemUtils::CalculateModuleHashFromDisk logs using WideToString.
// Cycle? SystemUtils -> Utils -> SystemUtils.
// SystemUtils needs WideToString for logging.
// Utils needs SystemUtils for WindowsVersion.
// This is a circular dependency if headers include each other.
// SystemUtils.cpp can include Utils.h. Utils.h includes SystemUtils.h.
// This is fine.

#include "../Logger.h"
#include <vector>
#include <string>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <memory>
#include <mutex>

namespace SystemUtils
{
    // Global API Pointers
    NtQueryInformationThread_t g_pNtQueryInformationThread = nullptr;
    NtQuerySystemInformation_t g_pNtQuerySystemInformation = nullptr;
    PNtSetInformationThread g_pNtSetInformationThread = nullptr;
    NtQueryInformationProcess_t g_pNtQueryInformationProcess = nullptr;

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
        if (!g_pNtQueryInformationProcess)
        {
            g_pNtQueryInformationProcess =
                reinterpret_cast<NtQueryInformationProcess_t>(GetProcAddress(hNtdll, "NtQueryInformationProcess"));
        }
    }

    WindowsVersion GetWindowsVersion()
    {
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
            if (!GetVersionExW((LPOSVERSIONINFOW)&osInfo))
            {
                return WindowsVersion::Win_Unknown;
            }
        }

        if (osInfo.dwMajorVersion == 5 && osInfo.dwMinorVersion == 1)
            return WindowsVersion::Win_XP;

        if (osInfo.dwMajorVersion == 6 && osInfo.dwMinorVersion == 0)
            return WindowsVersion::Win_Vista_Win7;

        if (osInfo.dwMajorVersion == 6 && osInfo.dwMinorVersion == 1)
            return WindowsVersion::Win_Vista_Win7;

        if (osInfo.dwMajorVersion == 6 && (osInfo.dwMinorVersion == 2 || osInfo.dwMinorVersion == 3))
            return WindowsVersion::Win_8_Win81;

        if (osInfo.dwMajorVersion == 10 && osInfo.dwBuildNumber < 22000)
            return WindowsVersion::Win_10;

        if (osInfo.dwMajorVersion == 10 && osInfo.dwBuildNumber >= 22000)
            return WindowsVersion::Win_11;

        return WindowsVersion::Win_Unknown;
    }

    static uint64_t BuildCapabilityMask(WindowsVersion version)
    {
        uint64_t mask = 0;
        switch (version)
        {
            case WindowsVersion::Win_XP:
                // XP: keep conservative capability set and rely on fallbacks.
                break;
            case WindowsVersion::Win_Vista_Win7:
                mask |= static_cast<uint64_t>(ApiCapability::ProcessQueryLimitedInformation);
                mask |= static_cast<uint64_t>(ApiCapability::WmiAsyncProcessMonitor);
                break;
            case WindowsVersion::Win_8_Win81:
            case WindowsVersion::Win_10:
            case WindowsVersion::Win_11:
                mask |= static_cast<uint64_t>(ApiCapability::ProcessQueryLimitedInformation);
                mask |= static_cast<uint64_t>(ApiCapability::LdrDllNotification);
                mask |= static_cast<uint64_t>(ApiCapability::ProcessMitigationPolicy);
                mask |= static_cast<uint64_t>(ApiCapability::WmiAsyncProcessMonitor);
                break;
            case WindowsVersion::Win_Unknown:
            default:
                // Unknown OS: use safer fallbacks by default.
                break;
        }
        return mask;
    }

    uint64_t GetApiCapabilityMask()
    {
        static const uint64_t kCapabilities = BuildCapabilityMask(GetWindowsVersion());
        return kCapabilities;
    }

    bool HasApiCapability(ApiCapability capability)
    {
        return (GetApiCapabilityMask() & static_cast<uint64_t>(capability)) != 0;
    }

    DWORD GetProcessQueryAccessMask()
    {
        return HasApiCapability(ApiCapability::ProcessQueryLimitedInformation) ? PROCESS_QUERY_LIMITED_INFORMATION
                                                                               : PROCESS_QUERY_INFORMATION;
    }

    PBYTE FindPattern(PBYTE base, SIZE_T size, const BYTE *pattern, SIZE_T patternSize, BYTE wildcard)
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

    // Helper for WideToString since we might not want to depend on Utils here to avoid cycle in headers?
    // But we can include Utils.h in cpp.
    // Let's implement a local helper or use Utils::WideToString if we include Utils.h
    // Since we are splittng files, it's safer to not have circular dependencies even incpp if possible,
    // but C++ allows it.
    // However, I haven't created Utils.h yet.
    // I can implement a simple WideToStringLocal here for logging to be safe.
    static std::string WideToStringLocal(const std::wstring &wstr)
    {
        if (wstr.empty()) return "";
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
        if (size_needed <= 0) return "";
        std::string strTo(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
        return strTo;
    }

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
                if (pSectionHeader->Characteristics & IMAGE_SCN_CNT_CODE)
                {
                    codeSectionCount++;
                    if (codeSectionCount == 1)
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

        wchar_t modulePath[MAX_PATH] = {0};
        GetModuleFileNameW(hModule, modulePath, MAX_PATH);

        PVOID tempBase = nullptr;
        DWORD tempSize = 0;
        bool result = GetModuleCodeSectionInfoInternal(hModule, &tempBase, &tempSize);

        if (result)
        {
            outBase = tempBase;
            outSize = tempSize;
            return true;
        }

        std::string modulePathStr = "未知模块";
        if (wcslen(modulePath) > 0)
        {
            modulePathStr = WideToStringLocal(std::wstring(modulePath));
        }

        LOG_DEBUG_F(AntiCheatLogger::LogCategory::SYSTEM,
                    "GetModuleCodeSectionInfo: 未找到代码节, hModule=0x%p, 模块路径=%s", hModule, modulePathStr.c_str());

        return false;
    }

    CallerValidationResult CheckCallerAddressSafe(PVOID caller_address)
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

    // Win32 compatible path normalization (No std::filesystem)
    std::wstring SystemNormalizePathLowercase(const std::wstring &input)
    {
        wchar_t fullPath[MAX_PATH] = {0};
        DWORD len = GetFullPathNameW(input.c_str(), MAX_PATH, fullPath, NULL);

        std::wstring s;
        if (len > 0 && len < MAX_PATH)
        {
            s = fullPath;
        }
        else
        {
            s = input; // Fallback
        }

        std::transform(s.begin(), s.end(), s.begin(), ::towlower);
        return s;
    }

    std::wstring NormalizeKernelPathToWinPath(const std::wstring &input)
    {
        std::wstring out = input;
        if (out.find(L"\\SystemRoot\\") == 0)
        {
            wchar_t winDir[MAX_PATH] = {0};
            if (GetWindowsDirectoryW(winDir, MAX_PATH) > 0)
            {
                out.replace(0, 12, std::wstring(winDir) + L"\\");
            }
        }
        else if (out.find(L"\\??\\") == 0)
        {
            out.replace(0, 4, L"");
        }
        return SystemNormalizePathLowercase(out);
    }

    int IsVbsEnabled()
    {
        HKEY hKey;
        LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard", 0, KEY_READ, &hKey);
        if (rc != ERROR_SUCCESS)
            return -1;
        DWORD enabled = 0;
        DWORD cb = sizeof(enabled);
        DWORD type = 0;
        if (RegQueryValueExW(hKey, L"EnableVirtualizationBasedSecurity", nullptr, &type, (LPBYTE)&enabled, &cb) != ERROR_SUCCESS || type != REG_DWORD)
        {
            RegCloseKey(hKey);
            return -1;
        }
        RegCloseKey(hKey);
        return (enabled != 0) ? 1 : 0;
    }

    bool IsReadableMemory(const void *ptr, size_t size)
    {
        if (!ptr || size == 0) return false;
        const uintptr_t startAddr = reinterpret_cast<uintptr_t>(ptr);
        if (startAddr > (UINTPTR_MAX - size)) return false;
        const uintptr_t endAddrExclusive = startAddr + size;

        uintptr_t cursor = startAddr;
        while (cursor < endAddrExclusive)
        {
            MEMORY_BASIC_INFORMATION mbi = {};
            if (VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &mbi, sizeof(mbi)) == 0)
            {
                return false;
            }

            if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD))
            {
                return false;
            }

            const uintptr_t regionStart = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            const uintptr_t regionEnd = regionStart + mbi.RegionSize;
            if (regionEnd <= cursor)
            {
                return false;
            }
            cursor = regionEnd;
        }

        // SEH probe to prevent stale VirtualQuery metadata from causing AV later.
        __try
        {
            volatile const BYTE first = *reinterpret_cast<const BYTE *>(startAddr);
            (void)first;
            volatile const BYTE last = *reinterpret_cast<const BYTE *>(endAddrExclusive - 1);
            (void)last;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }

        return true;
    }

    bool IsValidPointer(const void *ptr, size_t size)
    {
        return IsReadableMemory(ptr, size);
    }

    LONG WINAPI DecoyVehHandler(PEXCEPTION_POINTERS ExceptionInfo)
    {
        UNREFERENCED_PARAMETER(ExceptionInfo);
        return EXCEPTION_CONTINUE_SEARCH;
    }

    void CheckCloseHandleException()
    {
        __try
        {
            CloseHandle(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(0xDEADBEEF)));
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
        }
    }

    bool IsKernelDebuggerPresent_KUserSharedData()
    {
        __try
        {
            const UCHAR *pSharedData = (const UCHAR *)0x7FFE0000;
            const BOOLEAN kdDebuggerEnabled = *(pSharedData + 0x2D4);
            return kdDebuggerEnabled;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    std::vector<uint8_t> CalculateFnv1aHash(const BYTE *data, size_t size)
    {
        uint64_t hash = 14695981039346656037ULL;
        const uint64_t fnv_prime = 1099511628211ULL;

        for (size_t i = 0; i < size; ++i)
        {
            hash ^= data[i];
            hash *= fnv_prime;
        }
        std::vector<uint8_t> result(sizeof(hash));
        memcpy(result.data(), &hash, sizeof(hash));
        return result;
    }

    void DumpPESections(const std::wstring &filePath)
    {
        HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
        {
            return;
        }

        DWORD fileSize = GetFileSize(hFile, NULL);
        if (fileSize == INVALID_FILE_SIZE || fileSize == 0)
        {
            CloseHandle(hFile);
            return;
        }

        std::vector<BYTE> fileData(fileSize);
        DWORD bytesRead = 0;
        if (!ReadFile(hFile, fileData.data(), fileSize, &bytesRead, NULL) || bytesRead != fileSize)
        {
            CloseHandle(hFile);
            return;
        }
        CloseHandle(hFile);

        const BYTE *baseAddress = fileData.data();
        const auto *pDosHeader = reinterpret_cast<const IMAGE_DOS_HEADER *>(baseAddress);
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;

        const auto *pNtHeaders = reinterpret_cast<const IMAGE_NT_HEADERS *>(baseAddress + pDosHeader->e_lfanew);
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return;

        PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
        for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++)
        {
            char sectionName[9] = {0};
            strncpy(sectionName, (const char *)pSectionHeader->Name, 8);
            // Log omitted to avoid circular dependency complexity, or use local WideToString if needed
        }
    }

    std::string CalculateModuleHashFromDisk(const std::wstring &filePath)
    {
        HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return "";

        DWORD fileSize = GetFileSize(hFile, NULL);
        if (fileSize == INVALID_FILE_SIZE || fileSize == 0)
        {
            CloseHandle(hFile);
            return "";
        }

        std::vector<BYTE> fileData(fileSize);
        DWORD bytesRead = 0;
        if (!ReadFile(hFile, fileData.data(), fileSize, &bytesRead, NULL) || bytesRead != fileSize)
        {
            CloseHandle(hFile);
            return "";
        }
        CloseHandle(hFile);

        const BYTE *baseAddress = fileData.data();
        const auto *pDosHeader = reinterpret_cast<const IMAGE_DOS_HEADER *>(baseAddress);
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return "";

        const auto *pNtHeaders = reinterpret_cast<const IMAGE_NT_HEADERS *>(baseAddress + pDosHeader->e_lfanew);
        if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return "";

        PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
        PIMAGE_SECTION_HEADER pFirstCodeSection = nullptr;
        PIMAGE_SECTION_HEADER pTextSection = nullptr;
        PIMAGE_SECTION_HEADER pFirstExecutableSection = nullptr;

        for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSectionHeader++)
        {
            if (!pFirstCodeSection && (pSectionHeader->Characteristics & IMAGE_SCN_CNT_CODE))
                pFirstCodeSection = pSectionHeader;
            if (!pTextSection && strncmp((const char *)pSectionHeader->Name, ".text", 8) == 0)
                pTextSection = pSectionHeader;
            if (!pFirstExecutableSection && (pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE))
                pFirstExecutableSection = pSectionHeader;
        }

        PIMAGE_SECTION_HEADER pSelectedSection = pFirstCodeSection ? pFirstCodeSection
                                                : pTextSection   ? pTextSection
                                                                 : pFirstExecutableSection;

        if (pSelectedSection)
        {
            DWORD rawOffset = pSelectedSection->PointerToRawData;
            DWORD rawSize = pSelectedSection->SizeOfRawData;

            if (rawOffset + rawSize > fileSize) return "";

            std::vector<uint8_t> hashBytes = CalculateFnv1aHash(baseAddress + rawOffset, rawSize);
            std::ostringstream oss;
            oss << "fnv1a:";
            for (auto byte : hashBytes)
            {
                oss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
            }
            return oss.str();
        }
        return "";
    }

    MemoryReadResult ReadProcessMemorySafe(LPCVOID address, BYTE *buffer, SIZE_T size)
    {
        MemoryReadResult result;
        __try
        {
            SIZE_T bytesReadLocal = 0;
            if (ReadProcessMemory(GetCurrentProcess(), address, buffer, size, &bytesReadLocal))
            {
                result.success = true;
                result.bytesRead = bytesReadLocal;
                result.lastError = ERROR_SUCCESS;
            }
            else
            {
                result.success = (bytesReadLocal > 0);
                result.bytesRead = bytesReadLocal;
                result.lastError = GetLastError();
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            result.success = false;
            result.bytesRead = 0;
            result.exceptionRaised = true;
            result.exceptionCode = GetExceptionCode();
            result.lastError = 0;
        }
        return result;
    }

    bool IsSystemDirectoryPath(const std::wstring &path)
    {
        struct SysDirs
        {
            std::wstring sys32, syswow64, winsxs, drivers;
        };

        static const SysDirs s_sysDirs = []() -> SysDirs {
            SysDirs dirs;
            wchar_t winDirBuf[MAX_PATH] = {0};
            if (GetWindowsDirectoryW(winDirBuf, MAX_PATH) > 0)
            {
                std::wstring winDir = winDirBuf;
                std::transform(winDir.begin(), winDir.end(), winDir.begin(), ::towlower);
                if (!winDir.empty() && winDir.back() != L'\\')
                    winDir.push_back(L'\\');
                dirs.sys32 = winDir + L"system32\\";
                dirs.syswow64 = winDir + L"syswow64\\";
                dirs.winsxs = winDir + L"winsxs\\";
                dirs.drivers = winDir + L"system32\\drivers\\";
            }
            return dirs;
        }();

        std::wstring lower = path;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

        if (lower.rfind(s_sysDirs.sys32, 0) == 0) return true;
        if (lower.rfind(s_sysDirs.syswow64, 0) == 0) return true;
        if (lower.rfind(s_sysDirs.winsxs, 0) == 0) return true;
        if (lower.rfind(s_sysDirs.drivers, 0) == 0) return true;

        return false;
    }
}
