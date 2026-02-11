#include "Utils.h"
#include "SystemUtils.h"
#include "../CheatConfigManager.h"
#include "../Logger.h"

#include <algorithm>
#include <vector>
#include <memory>
#include <sstream>
#include <iomanip>
#include <cstdarg>

#include <Softpub.h>
#include <Wincrypt.h>
#include <wintrust.h>
#include <objbase.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "version.lib") // For GetFileVersionInfo if needed, or Psapi/Kernel32 linked by default?

namespace Utils
{
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
            return std::wstring();
        }
        std::wstring wstrTo(size_needed, 0);
        if (MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed) == 0)
        {
            return std::wstring();
        }
        return wstrTo;
    }

    std::wstring GetFileName(const std::wstring &path)
    {
        size_t lastSlash = path.find_last_of(L"\\/");
        if (lastSlash != std::wstring::npos)
        {
            return path.substr(lastSlash + 1);
        }
        return path;
    }

    std::string FormatString(const char* format, ...)
    {
        va_list args;
        va_start(args, format);
        // _vscprintf is Microsoft specific, available in Visual Studio
        #ifdef _MSC_VER
        int len = _vscprintf(format, args);
        #else
        int len = vsnprintf(nullptr, 0, format, args);
        #endif

        if (len == -1)
        {
            va_end(args);
            return "";
        }
        std::vector<char> buffer(len + 1);
        vsnprintf(buffer.data(), len + 1, format, args);
        va_end(args);
        return std::string(buffer.data(), len);
    }

    bool GetParentProcessInfo(DWORD &parentPid, std::string &parentName)
    {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE)
        {
            return false;
        }

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
            return false;
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

        return false;
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
        return "";
    }

    std::wstring GetProcessNameByPid(DWORD pid)
    {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE)
            return L"";

        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);

        if (Process32FirstW(hSnapshot, &pe))
        {
            do
            {
                if (pe.th32ProcessID == pid)
                {
                    CloseHandle(hSnapshot);
                    return pe.szExeFile;
                }
            } while (Process32NextW(hSnapshot, &pe));
        }

        CloseHandle(hSnapshot);
        return L"";
    }

    std::wstring GetProcessFullName(HANDLE hProcess)
    {
        wchar_t processName[MAX_PATH] = {0};

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

        if (GetModuleFileNameExW(hProcess, NULL, processName, MAX_PATH))
        {
            return processName;
        }

        return L"";
    }

    SignatureStatus VerifyFileSignature(const std::wstring &filePath, SystemUtils::WindowsVersion winVer)
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
        winTrustData.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;
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

        // Consolidated system directory check
        bool isInWindowsSystemDir = SystemUtils::IsSystemDirectoryPath(filePath);

        if (isInWindowsSystemDir)
        {
            if (result == TRUST_E_NOSIGNATURE || result == CERT_E_CHAINING || result == CERT_E_UNTRUSTEDROOT ||
                result == TRUST_E_SYSTEM_ERROR || result == CRYPT_E_NO_MATCH)
            {
                return SignatureStatus::FAILED_TO_VERIFY;
            }
        }

        if (winVer == SystemUtils::WindowsVersion::Win_XP)
        {
            switch (result)
            {
                case TRUST_E_SYSTEM_ERROR:
                case TRUST_E_PROVIDER_UNKNOWN:
                case CERT_E_CHAINING:
                case TRUST_E_BAD_DIGEST:
                    return SignatureStatus::FAILED_TO_VERIFY;
            }
        }

        switch (result)
        {
            case TRUST_E_NOSIGNATURE:
            case TRUST_E_BAD_DIGEST:
                return SignatureStatus::UNTRUSTED;
            default:
                return SignatureStatus::FAILED_TO_VERIFY;
        }
    }

    ModuleValidationResult ValidateModule(const std::wstring &modulePath, SystemUtils::WindowsVersion winVer)
    {
        ModuleValidationResult result;

        std::wstring normalizedPath;
        // Use Win32 path normalization instead of std::filesystem
        normalizedPath = SystemUtils::SystemNormalizePathLowercase(modulePath);

        bool isInSystemDir = SystemUtils::IsSystemDirectoryPath(normalizedPath);

        result.signatureStatus = VerifyFileSignature(modulePath, winVer);

        if (isInSystemDir)
        {
            if (result.signatureStatus == SignatureStatus::TRUSTED)
            {
                result.isTrusted = true;
                result.reason = "系统目录 + 可信签名";
            }
            else if (result.signatureStatus == SignatureStatus::FAILED_TO_VERIFY)
            {
                result.isTrusted = true;
                result.reason = "系统目录 + 离线降噪";
            }
            else
            {
                result.isTrusted = false;
                result.reason = "系统目录但签名不可信 [CRITICAL]";
            }
        }
        else
        {
            if (result.signatureStatus == SignatureStatus::TRUSTED)
            {
                result.isTrusted = true;
                result.reason = "非系统目录 + 可信签名";
            }
            else
            {
                std::wstring fileName = Utils::GetFileName(normalizedPath);
                uint64_t moduleSize = 0;
                std::string codeHash;

                WIN32_FILE_ATTRIBUTE_DATA attrs;
                if (GetFileAttributesExW(modulePath.c_str(), GetFileExInfoStandard, &attrs))
                {
                    ULARGE_INTEGER size;
                    size.HighPart = attrs.nFileSizeHigh;
                    size.LowPart = attrs.nFileSizeLow;
                    moduleSize = size.QuadPart;
                }

                codeHash = SystemUtils::CalculateModuleHashFromDisk(modulePath);

                if (CheatConfigManager::GetInstance().IsTrustedThirdPartyModule(fileName, moduleSize, codeHash))
                {
                    result.isTrusted = true;
                    result.reason = "官方第三方库白名单 + 文件名匹配";
                }
                else
                {
                    result.isTrusted = false;
                    result.reason = "非系统目录 + 无可信签名 [SUSPICIOUS]";
                }
            }
        }

        return result;
    }

    // Implemented via config check
    bool IsWhitelistedModule(const std::wstring &modulePath)
    {
        // 1. Get long path if possible
        wchar_t longPath[MAX_PATH] = {0};
        DWORD len = GetLongPathNameW(modulePath.c_str(), longPath, MAX_PATH);
        std::wstring normalizedPath;
        if (len > 0 && len < MAX_PATH)
        {
            normalizedPath = longPath;
        }
        else
        {
            normalizedPath = modulePath;
        }

        std::transform(normalizedPath.begin(), normalizedPath.end(), normalizedPath.begin(), ::towlower);

        // 3. System dir check
        if (SystemUtils::IsSystemDirectoryPath(normalizedPath))
        {
            return true;
        }

        // 4. White listed configs
        auto whitelistedDirs = CheatConfigManager::GetInstance().GetWhitelistedIntegrityDirs();
        if (whitelistedDirs)
        {
            for (const auto &dir : *whitelistedDirs)
            {
                if (normalizedPath.find(dir) != std::wstring::npos)
                {
                    return true;
                }
            }
        }

        auto whitelistedFiles = CheatConfigManager::GetInstance().GetWhitelistedIntegrityFiles();
        if (whitelistedFiles)
        {
            size_t lastSlash = normalizedPath.find_last_of(L"\\/");
            std::wstring fileName = (lastSlash != std::wstring::npos) ? normalizedPath.substr(lastSlash + 1) : normalizedPath;

            for (const auto &file : *whitelistedFiles)
            {
                if (fileName == file)
                {
                    return true;
                }
            }
        }

        return false;
    }
}
