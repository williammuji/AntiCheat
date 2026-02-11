#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include "SystemUtils.h"

namespace Utils
{
    // Return values for signature verification
    enum class SignatureStatus
    {
        UNKNOWN,          // Not verified
        TRUSTED,          // Trusted signature
        UNTRUSTED,        // Untrusted signature
        FAILED_TO_VERIFY  // Verification failed
    };

    // Module validation result
    struct ModuleValidationResult
    {
        bool isTrusted = false;
        std::string reason;
        SignatureStatus signatureStatus = SignatureStatus::UNKNOWN;
    };

    // String conversion
    std::string WideToString(const std::wstring &wstr);
    std::wstring StringToWide(const std::string &str);
    std::wstring GetFileName(const std::wstring &path);
    std::string FormatString(const char* format, ...);

    // Process helpers
    bool GetParentProcessInfo(DWORD &parentPid, std::string &parentName);
    std::string GenerateUuid();
    std::wstring GetProcessNameByPid(DWORD pid);
    std::wstring GetProcessFullName(HANDLE hProcess);

    // Signature and Module validation
    SignatureStatus VerifyFileSignature(const std::wstring &filePath, SystemUtils::WindowsVersion winVer);
    ModuleValidationResult ValidateModule(const std::wstring &modulePath, SystemUtils::WindowsVersion winVer);
    bool IsWhitelistedModule(const std::wstring &modulePath);
}
