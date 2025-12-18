// Module Hash Extraction Tool
// Extract real code hashes for specific DLLs in development environment
// Supports Windows XP and above
// Usage: extract_module_hashes.exe [path1] [path2] ...

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <conio.h>

// Windows XP compatibility definitions
#ifndef CALG_SHA_256
#define CALG_SHA_256 (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256)
#endif

#ifndef ALG_SID_SHA_256
#define ALG_SID_SHA_256 12
#endif

struct ModuleHashInfo {
    std::wstring moduleName;
    std::wstring fullPath;
    uint64_t fileSize;
    uint64_t moduleSize;
    HMODULE moduleHandle;
    std::string sha256Hash;
    std::string sha1Hash;
    bool hashCalculated;
    std::string errorMessage;
};

// Utility functions: String conversion
std::wstring StringToWide(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

std::string WideToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

// Get module code section information
bool GetModuleCodeSectionInfo(HMODULE hModule, LPVOID& outBase, DWORD& outSize) {
    if (!hModule) return false;

    __try {
        IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)hModule;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return false;
        }

        IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)hModule + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return false;
        }

        IMAGE_SECTION_HEADER* sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders);
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            IMAGE_SECTION_HEADER* section = &sectionHeaders[i];

            if ((section->Characteristics & IMAGE_SCN_CNT_CODE) &&
                (section->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {

                outBase = (LPVOID)((BYTE*)hModule + section->VirtualAddress);
                outSize = section->SizeOfRawData;
                return true;
            }
        }
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    return false;
}

// Calculate hash (Windows XP compatible)
std::string CalculateHash(const BYTE* data, size_t size, ALG_ID algId, const std::string& prefix) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
            return "";
        }
    }

    if (!CryptCreateHash(hProv, algId, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return "";
    }

    if (!CryptHashData(hHash, data, (DWORD)size, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    DWORD hashLen = 0;
    DWORD hashLenSize = sizeof(DWORD);
    if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&hashLen, &hashLenSize, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    std::vector<BYTE> hash(hashLen);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    std::ostringstream oss;
    oss << prefix;
    for (DWORD i = 0; i < hashLen; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return oss.str();
}

// Calculate SHA-256 hash (fallback to SHA-1)
std::string CalculateSHA256String(const BYTE* data, size_t size) {
    std::string sha256 = CalculateHash(data, size, CALG_SHA_256, "sha256:");
    if (!sha256.empty()) {
        return sha256;
    }
    std::string sha1 = CalculateHash(data, size, CALG_SHA1, "sha1:");
    return sha1;
}

// Calculate SHA-1 hash
std::string CalculateSHA1String(const BYTE* data, size_t size) {
    return CalculateHash(data, size, CALG_SHA1, "sha1:");
}

// Process a single module path
bool ProcessModulePath(const std::wstring& path, ModuleHashInfo& info) {
    try {
        if (!std::filesystem::exists(path)) {
            std::wcout << L"Warning: Path does not exist: " << path << std::endl;
            return false;
        }

        info.fullPath = std::filesystem::absolute(path).wstring();
        info.moduleName = std::filesystem::path(info.fullPath).filename().wstring();
        info.moduleHandle = NULL;
        info.hashCalculated = false;

        // Get file size
        std::error_code ec;
        auto fileSize = std::filesystem::file_size(path, ec);
        if (!ec) {
            info.fileSize = static_cast<uint64_t>(fileSize);
        } else {
            info.fileSize = 0;
        }

        info.moduleSize = 0;

        // Check if module is already loaded
        HMODULE hMods[1024];
        DWORD cbNeeded;
        if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
            DWORD moduleCount = cbNeeded / sizeof(HMODULE);
            for (DWORD i = 0; i < moduleCount; i++) {
                wchar_t modulePath[MAX_PATH];
                if (GetModuleFileNameW(hMods[i], modulePath, MAX_PATH)) {
                    if (_wcsicmp(modulePath, info.fullPath.c_str()) == 0) {
                        info.moduleHandle = hMods[i];
                        MODULEINFO modInfo;
                        if (GetModuleInformation(GetCurrentProcess(), hMods[i], &modInfo, sizeof(modInfo))) {
                            info.moduleSize = modInfo.SizeOfImage;
                        }
                        break;
                    }
                }
            }
        }

        return true;
    } catch (const std::exception& e) {
        std::cout << "Error processing path: " << e.what() << std::endl;
        return false;
    }
}

// Calculate module hash
bool CalculateModuleHash(ModuleHashInfo& info) {
    if (info.moduleHandle) {
        LPVOID codeBase = nullptr;
        DWORD codeSize = 0;

        if (GetModuleCodeSectionInfo(info.moduleHandle, codeBase, codeSize)) {
            info.sha256Hash = CalculateSHA256String(static_cast<BYTE*>(codeBase), codeSize);
            info.sha1Hash = CalculateSHA1String(static_cast<BYTE*>(codeBase), codeSize);
            info.hashCalculated = true;
            return true;
        } else {
            info.errorMessage = "Cannot get code section info";
            return false;
        }
    } else {
        HMODULE hModule = LoadLibraryW(info.fullPath.c_str());
        if (hModule) {
            LPVOID codeBase = nullptr;
            DWORD codeSize = 0;

            if (GetModuleCodeSectionInfo(hModule, codeBase, codeSize)) {
                info.sha256Hash = CalculateSHA256String(static_cast<BYTE*>(codeBase), codeSize);
                info.sha1Hash = CalculateSHA1String(static_cast<BYTE*>(codeBase), codeSize);
                info.hashCalculated = true;
                FreeLibrary(hModule);
                return true;
            } else {
                info.errorMessage = "Cannot get code section info";
                FreeLibrary(hModule);
                return false;
            }
        } else {
            info.errorMessage = "Cannot load module, error code: " + std::to_string(GetLastError());
            return false;
        }
    }
}

// Print results
void PrintResults(const std::vector<ModuleHashInfo>& results) {
    std::wcout << L"\n=== Module Hash Extraction Results ===" << std::endl;
    std::wcout << L"Found " << results.size() << L" modules" << std::endl;

    for (const auto& info : results) {
        std::wcout << L"\nModule Name: " << info.moduleName << std::endl;
        std::wcout << L"Full Path: " << info.fullPath << std::endl;
        std::wcout << L"File Size: " << info.fileSize << L" bytes" << std::endl;
        if (info.moduleSize > 0) {
            std::wcout << L"Memory Size: " << info.moduleSize << L" bytes" << std::endl;
        }
        std::wcout << L"Status: " << (info.moduleHandle ? L"Loaded" : L"Not Loaded") << std::endl;

        if (info.hashCalculated) {
            std::wcout << L"SHA-256/SHA-1: " << StringToWide(info.sha256Hash.empty() ? info.sha1Hash : info.sha256Hash) << std::endl;
            if (!info.sha1Hash.empty() && !info.sha256Hash.empty()) {
                std::wcout << L"SHA-1: " << StringToWide(info.sha1Hash) << std::endl;
            }
        } else {
            std::wcout << L"Hash calculation failed: " << StringToWide(info.errorMessage) << std::endl;
        }
    }
}

// Generate config code
void GenerateConfigCode(const std::vector<ModuleHashInfo>& results) {
    std::wcout << L"\n=== Generated Configuration Code ===" << std::endl;

    for (const auto& info : results) {
        if (info.hashCalculated) {
            std::wstring varName = info.moduleName;
            std::transform(varName.begin(), varName.end(), varName.begin(), ::tolower);
            if (varName.find(L"fmod") != std::wstring::npos) {
                varName = L"fmod";
            } else if (varName.find(L"ak") != std::wstring::npos || varName.find(L"wwise") != std::wstring::npos) {
                varName = L"ak";
            } else {
                varName = L"module";
            }

            std::wcout << L"\n// " << info.moduleName << L" configuration" << std::endl;
            std::wcout << L"auto* " << varName << L"_module = configData.config->add_trusted_third_party_modules();" << std::endl;
            std::wcout << varName << L"_module->set_module_name(\"" << info.moduleName << L"\");" << std::endl;
            std::wcout << varName << L"_module->set_module_size(" << info.fileSize << L");  // Exact file size" << std::endl;

            if (!info.sha256Hash.empty()) {
                std::wcout << varName << L"_module->add_code_hashes(\"" << StringToWide(info.sha256Hash) << L"\");" << std::endl;
            }
            if (!info.sha1Hash.empty()) {
                std::wcout << varName << L"_module->add_code_hashes(\"" << StringToWide(info.sha1Hash) << L"\");  // Windows XP compatible" << std::endl;
            }

            std::wstring description = L"Third-party library";
            if (info.moduleName.find(L"fmod") != std::wstring::npos) {
                description = L"FMOD Audio Engine";
            } else if (info.moduleName.find(L"ak") != std::wstring::npos || info.moduleName.find(L"wwise") != std::wstring::npos) {
                description = L"Audiokinetic Wwise Audio Engine";
            }

            std::wcout << varName << L"_module->set_description(\"" << description << L"\");" << std::endl;
            std::wcout << varName << L"_module->set_enabled(true);" << std::endl;
        }
    }
}

// Save results to file
void SaveResultsToFile(const std::vector<ModuleHashInfo>& results) {
    std::ofstream file("module_hashes.txt");
    if (!file.is_open()) {
        std::wcout << L"Warning: Cannot create output file module_hashes.txt" << std::endl;
        return;
    }

    file << "=== Module Hash Extraction Results ===" << std::endl;
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    char timeStr[100];
    ctime_s(timeStr, sizeof(timeStr), &time);
    file << "Generated at: " << timeStr << std::endl;

    for (const auto& info : results) {
        file << "\nModule Name: " << WideToString(info.moduleName) << std::endl;
        file << "Full Path: " << WideToString(info.fullPath) << std::endl;
        file << "File Size: " << info.fileSize << " bytes" << std::endl;
        if (info.moduleSize > 0) {
            file << "Memory Size: " << info.moduleSize << " bytes" << std::endl;
        }
        file << "Status: " << (info.moduleHandle ? "Loaded" : "Not Loaded") << std::endl;

        if (info.hashCalculated) {
            if (!info.sha256Hash.empty()) {
                file << "SHA-256: " << info.sha256Hash << std::endl;
            }
            if (!info.sha1Hash.empty()) {
                file << "SHA-1: " << info.sha1Hash << std::endl;
            }
        } else {
            file << "Hash calculation failed: " << info.errorMessage << std::endl;
        }
    }

    file.close();
    std::wcout << L"\nResults saved to module_hashes.txt" << std::endl;
}

// Print usage
void PrintUsage() {
    std::wcout << L"Usage: extract_module_hashes.exe [path1] [path2] ..." << std::endl;
    std::wcout << L"\nExamples:" << std::endl;
    std::wcout << L"  extract_module_hashes.exe fmodex.dll" << std::endl;
    std::wcout << L"  extract_module_hashes.exe C:\\Game\\fmodex.dll C:\\Game\\Audio\\aksoundenginedll_d.dll" << std::endl;
    std::wcout << L"  extract_module_hashes.exe (no arguments - scans current directory)" << std::endl;
}

int wmain(int argc, wchar_t* argv[]) {
    std::wcout << L"Module Hash Extraction Tool v2.0" << std::endl;
    std::wcout << L"Supports Windows XP and above" << std::endl;
    std::wcout << L"Command-line mode: Specify DLL paths as arguments" << std::endl << std::endl;

    std::vector<ModuleHashInfo> allModules;

    if (argc > 1) {
        // Command-line mode: process specified paths
        std::wcout << L"Processing " << (argc - 1) << L" specified paths..." << std::endl;

        for (int i = 1; i < argc; i++) {
            std::wstring path = argv[i];
            std::wcout << L"\nProcessing: " << path << std::endl;

            ModuleHashInfo info;
            if (ProcessModulePath(path, info)) {
                std::wcout << L"  Found: " << info.moduleName << L" (" << info.fileSize << L" bytes)" << std::endl;
                std::wcout << L"  Calculating hash..." << std::endl;
                CalculateModuleHash(info);
                allModules.push_back(info);
            }
        }
    } else {
        // Interactive mode: show usage and wait
        PrintUsage();
        std::wcout << L"\nPress any key to exit..." << std::endl;
        _getch();
        return 0;
    }

    // Output results
    if (!allModules.empty()) {
        PrintResults(allModules);
        GenerateConfigCode(allModules);
        SaveResultsToFile(allModules);

        std::wcout << L"\nProcessing complete! Press any key to exit..." << std::endl;
    } else {
        std::wcout << L"\nNo modules processed. Press any key to exit..." << std::endl;
    }

    _getch();
    return 0;
}
