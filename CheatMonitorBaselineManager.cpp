#include "CheatMonitor.h"
#include "CheatMonitorEngine.h"
#include "CheatConfigManager.h"
#include "utils/SystemUtils.h"
#include "utils/Utils.h"
#include "Logger.h"

#include <algorithm>
#include <iomanip>
#include <iphlpapi.h>
#include <sstream>
#include <wincrypt.h>
#include <wintrust.h>

void CheatMonitorEngine::InitializeProcessBaseline()
{
    std::unordered_map<std::wstring, std::vector<uint8_t>> moduleBaselineHashes;
    std::unordered_map<std::string, std::vector<uint8_t>> iatBaselineHashes;

    std::vector<HMODULE> hMods(1024);
    DWORD cbNeeded = 0;
    if (EnumProcessModules(GetCurrentProcess(), hMods.data(), hMods.size() * sizeof(HMODULE), &cbNeeded))
    {
        size_t count = cbNeeded / sizeof(HMODULE);
        for (size_t i = 0; i < count; i++)
        {
            HMODULE hModule = hMods[i];
            wchar_t modulePath_w[MAX_PATH];
            if (GetModuleFileNameW(hModule, modulePath_w, MAX_PATH) == 0) continue;
            std::wstring modulePath(modulePath_w);

            PVOID codeBase = nullptr;
            DWORD codeSize = 0;
            if (SystemUtils::GetModuleCodeSectionInfo(hModule, codeBase, codeSize))
            {
                moduleBaselineHashes[modulePath] =
                        SystemUtils::CalculateFnv1aHash(static_cast<BYTE *>(codeBase), codeSize);
            }
        }
    }

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
                        iatBaselineHashes[dllName] =
                                SystemUtils::CalculateFnv1aHash(iat_hashes.data(), iat_hashes.size());
                        pCurrentDesc++;
                    }
                }
            }
        }
    }

    {
        std::lock_guard<std::mutex> lock(m_baselineMutex);
        m_moduleBaselineHashes = std::move(moduleBaselineHashes);
        m_iatBaselineHashes = std::move(iatBaselineHashes);
    }

    if (!m_hwCollector) m_hwCollector = std::make_unique<anti_cheat::HardwareInfoCollector>();
    m_hwCollector->EnsureCollected();

    AddEvidence(anti_cheat::SYSTEM_INITIALIZED, "Process baseline established.");
    m_processBaselineEstablished = true;
}

void CheatMonitorEngine::VerifyModuleSignature(HMODULE hModule)
{
    wchar_t modulePath_w[MAX_PATH];
    if (GetModuleFileNameW(hModule, modulePath_w, MAX_PATH) == 0) return;
    std::wstring modulePath = modulePath_w;
    std::transform(modulePath.begin(), modulePath.end(), modulePath.begin(), ::towlower);

    const auto now = std::chrono::steady_clock::now();
    const auto ttl = std::chrono::minutes(CheatConfigManager::GetInstance().GetSignatureCacheDurationMinutes());
    {
        std::lock_guard<std::mutex> lock(m_signatureCacheMutex);
        for (auto it = m_moduleSignatureCache.begin(); it != m_moduleSignatureCache.end();)
        {
            if (now >= it->second.second + ttl)
                it = m_moduleSignatureCache.erase(it);
            else
                ++it;
        }
        const auto itThr = m_sigThrottleUntil.find(modulePath);
        if (itThr != m_sigThrottleUntil.end() && now < itThr->second) return;

        auto it = m_moduleSignatureCache.find(modulePath);
        if (it != m_moduleSignatureCache.end())
        {
            if (now < it->second.second + ttl) return;
        }
    }

    switch (Utils::VerifyFileSignature(modulePath, m_windowsVersion))
    {
        case Utils::SignatureStatus::TRUSTED: {
            std::lock_guard<std::mutex> lock(m_signatureCacheMutex);
            m_moduleSignatureCache[modulePath] = {SignatureVerdict::SIGNED_AND_TRUSTED, now};
            m_sigThrottleUntil[modulePath] =
                    now + std::chrono::seconds(CheatConfigManager::GetInstance().GetSignatureVerificationThrottleSeconds());
        }
        break;
        case Utils::SignatureStatus::UNTRUSTED: {
            Utils::ModuleValidationResult validation = Utils::ValidateModule(modulePath, m_windowsVersion);
            if (validation.isTrusted)
            {
                std::lock_guard<std::mutex> lock(m_signatureCacheMutex);
                m_moduleSignatureCache[modulePath] = {SignatureVerdict::SIGNED_AND_TRUSTED, now};
                m_sigThrottleUntil[modulePath] = now +
                                                 std::chrono::seconds(
                                                         CheatConfigManager::GetInstance().GetSignatureVerificationThrottleSeconds());
                LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR, "模块验证通过: %s (%s)",
                            Utils::WideToString(modulePath).c_str(), validation.reason.c_str());
            }
            else
            {
                {
                    std::lock_guard<std::mutex> lock(m_signatureCacheMutex);
                m_moduleSignatureCache[modulePath] = {SignatureVerdict::UNSIGNED_OR_UNTRUSTED, now};
                m_sigThrottleUntil[modulePath] = now +
                                                 std::chrono::seconds(
                                                         CheatConfigManager::GetInstance().GetSignatureVerificationThrottleSeconds());
                }
                if (m_windowsVersion != SystemUtils::WindowsVersion::Win_XP &&
                    m_windowsVersion != SystemUtils::WindowsVersion::Win_Vista_Win7)
                {
                    AddEvidence(anti_cheat::RUNTIME_MODULE_NEW_UNKNOWN,
                                "加载了不可信模块: " + Utils::WideToString(modulePath) + " (原因: " + validation.reason + ")");
                }
            }
        }
        break;
        case Utils::SignatureStatus::FAILED_TO_VERIFY:
            {
                std::lock_guard<std::mutex> lock(m_signatureCacheMutex);
            m_sigThrottleUntil[modulePath] =
                    now + std::chrono::milliseconds(
                                  CheatConfigManager::GetInstance().GetSignatureVerificationFailureThrottleMs());
            }
            break;
        default:
            break;
    }
}

bool CheatMonitorEngine::IsAddressInLegitimateModule(PVOID address, std::wstring &outModulePath)
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
            if (!isLegitimate) isLegitimate = Utils::IsWhitelistedModule(originalPath);

            if (!isLegitimate)
            {
                std::wostringstream debugMsg;
                debugMsg << L"[IsAddressInLegitimateModule] 地址 0x" << std::hex << address
                         << L" 不在合法模块中. 模块路径: " << originalPath << L" (小写: " << outModulePath << L")"
                         << std::endl;
                OutputDebugStringW(debugMsg.str().c_str());
                LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                            "IsAddressInLegitimateModule: 地址 0x%p 不在合法模块中, 模块路径=%s", address,
                            Utils::WideToString(originalPath).c_str());
            }
            else
            {
                LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                            "IsAddressInLegitimateModule: 地址 0x%p 匹配合法模块, 模块路径=%s", address,
                            Utils::WideToString(originalPath).c_str());
            }
            return isLegitimate;
        }
        LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                    "IsAddressInLegitimateModule: 地址 0x%p 获取模块路径失败, hModule=0x%p", address, hModule);
    }
    else
    {
        LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR, "IsAddressInLegitimateModule: 地址 0x%p 不属于任何模块", address);
    }
    return false;
}

bool CheatMonitorEngine::IsAddressInLegitimateModule(PVOID address)
{
    std::wstring dummyPath;
    return IsAddressInLegitimateModule(address, dummyPath);
}

void CheatMonitorEngine::InitializeSelfIntegrityBaseline()
{
    union
    {
        bool (CheatMonitorEngine::*pmf)(PVOID, std::wstring &);
        void *p;
    } u;
    u.pmf = &CheatMonitorEngine::IsAddressInLegitimateModule;
    if (u.p)
    {
        uint8_t buffer[16];
        SIZE_T bytesRead = 0;
        if (ReadProcessMemory(GetCurrentProcess(), u.p, buffer, sizeof(buffer), &bytesRead) && bytesRead == sizeof(buffer))
        {
            m_isAddressInLegitimateModulePrologue.assign(buffer, buffer + sizeof(buffer));
            LOG_INFO_F(AntiCheatLogger::LogCategory::SYSTEM, "自我完整性基线已建立: IsAddressInLegitimateModule @ %p", u.p);
        }
        else
        {
            LOG_ERROR(AntiCheatLogger::LogCategory::SYSTEM, "无法读取 IsAddressInLegitimateModule 函数内存以建立基线");
        }
    }
}

void CheatMonitorEngine::CheckSelfIntegrity()
{
    if (m_isAddressInLegitimateModulePrologue.empty()) return;

    union
    {
        bool (CheatMonitorEngine::*pmf)(PVOID, std::wstring &);
        void *p;
    } u;
    u.pmf = &CheatMonitorEngine::IsAddressInLegitimateModule;
    if (!u.p) return;

    uint8_t currentBytes[16];
    SIZE_T bytesRead = 0;
    if (ReadProcessMemory(GetCurrentProcess(), u.p, currentBytes, sizeof(currentBytes), &bytesRead) &&
        bytesRead == sizeof(currentBytes))
    {
        if (memcmp(currentBytes, m_isAddressInLegitimateModulePrologue.data(), sizeof(currentBytes)) != 0)
        {
            std::string diff;
            for (size_t i = 0; i < sizeof(currentBytes); ++i)
            {
                if (currentBytes[i] != m_isAddressInLegitimateModulePrologue[i])
                {
                    diff += Utils::FormatString(" [+%zu: %02X->%02X]", i, m_isAddressInLegitimateModulePrologue[i],
                                                currentBytes[i]);
                }
            }
            AddEvidence(anti_cheat::INTEGRITY_SELF_TAMPERING,
                        "关键反作弊函数 (IsAddressInLegitimateModule) 被篡改: " + diff);
        }
    }
}

std::vector<anti_cheat::ThreadSnapshot> CheatMonitorEngine::CollectThreadSnapshots()
{
    std::vector<anti_cheat::ThreadSnapshot> snapshots;
    DWORD currentPid = GetCurrentProcessId();
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return snapshots;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(hSnapshot, &te))
    {
        do
        {
            if (te.th32OwnerProcessID != currentPid) continue;
            anti_cheat::ThreadSnapshot snapshot;
            snapshot.set_thread_id(te.th32ThreadID);
            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (hThread)
            {
                PVOID startAddress = nullptr;
                if (SystemUtils::g_pNtQueryInformationThread)
                {
                    SystemUtils::g_pNtQueryInformationThread(hThread, (THREADINFOCLASS)9, &startAddress, sizeof(startAddress),
                                                             nullptr);
                }
                if (startAddress)
                {
                    snapshot.set_start_address(reinterpret_cast<uint64_t>(startAddress));
                    FILETIME creationTime, exitTime, kernelTime, userTime;
                    if (GetThreadTimes(hThread, &creationTime, &exitTime, &kernelTime, &userTime))
                    {
                        ULARGE_INTEGER uli;
                        uli.LowPart = creationTime.dwLowDateTime;
                        uli.HighPart = creationTime.dwHighDateTime;
                        snapshot.set_creation_time(uli.QuadPart);
                    }
                    MEMORY_BASIC_INFORMATION mbi = {0};
                    if (VirtualQuery(startAddress, &mbi, sizeof(mbi)))
                    {
                        snapshot.set_memory_base_address(reinterpret_cast<uint64_t>(mbi.BaseAddress));
                        snapshot.set_memory_region_size(mbi.RegionSize);
                        snapshot.set_memory_protect(mbi.Protect);
                        snapshot.set_memory_type(mbi.Type);
                    }
                    HMODULE hModule = nullptr;
                    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                           (LPCWSTR)startAddress, &hModule) &&
                        hModule)
                    {
                        wchar_t modulePath[MAX_PATH];
                        if (GetModuleFileNameW(hModule, modulePath, MAX_PATH) > 0)
                        {
                            snapshot.set_associated_module_path(Utils::WideToString(modulePath));
                            snapshot.set_module_base_address(reinterpret_cast<uint64_t>(hModule));
                            snapshot.set_relative_offset(snapshot.start_address() - snapshot.module_base_address());
                        }
                    }
                }
                CloseHandle(hThread);
            }
            snapshots.push_back(snapshot);
        } while (Thread32Next(hSnapshot, &te));
    }
    CloseHandle(hSnapshot);
    return snapshots;
}

static DWORD SafeReadPETimestamp(HMODULE hModule)
{
    DWORD timestamp = 0;
    __try
    {
        const BYTE *baseAddress = reinterpret_cast<const BYTE *>(hModule);
        const auto *pDosHeader = reinterpret_cast<const IMAGE_DOS_HEADER *>(baseAddress);
        if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
        {
            const auto *pNtHeaders = reinterpret_cast<const IMAGE_NT_HEADERS *>(baseAddress + pDosHeader->e_lfanew);
            if (pNtHeaders->Signature == IMAGE_NT_SIGNATURE)
            {
                timestamp = pNtHeaders->FileHeader.TimeDateStamp;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
    }
    return timestamp;
}

std::vector<anti_cheat::ModuleSnapshot> CheatMonitorEngine::CollectModuleSnapshots()
{
    std::vector<anti_cheat::ModuleSnapshot> snapshots;
    std::vector<HMODULE> hMods(1024);
    DWORD cbNeeded = 0;
    if (!EnumProcessModules(GetCurrentProcess(), hMods.data(), hMods.size() * sizeof(HMODULE), &cbNeeded))
        return snapshots;

    size_t moduleCount = cbNeeded / sizeof(HMODULE);
    for (size_t i = 0; i < moduleCount; i++)
    {
        anti_cheat::ModuleSnapshot snapshot;
        wchar_t modulePath[MAX_PATH];
        if (GetModuleFileNameW(hMods[i], modulePath, MAX_PATH) > 0)
        {
            snapshot.set_module_path(Utils::WideToString(modulePath));
            snapshot.set_base_address(reinterpret_cast<uint64_t>(hMods[i]));
            MODULEINFO modInfo;
            if (GetModuleInformation(GetCurrentProcess(), hMods[i], &modInfo, sizeof(modInfo)))
            {
                snapshot.set_module_size(modInfo.SizeOfImage);
            }
            DWORD peTimestamp = SafeReadPETimestamp(hMods[i]);
            if (peTimestamp != 0) snapshot.set_timestamp(peTimestamp);

            Utils::SignatureStatus sigStatus = Utils::VerifyFileSignature(modulePath, m_windowsVersion);
            snapshot.set_has_signature(sigStatus == Utils::SignatureStatus::TRUSTED);
            if (snapshot.has_signature())
            {
                std::string thumbprint = GetCertificateThumbprint(modulePath);
                snapshot.set_cert_thumbprint(thumbprint);
            }

            PVOID codeBase = nullptr;
            DWORD codeSize = 0;
            if (SystemUtils::GetModuleCodeSectionInfo(hMods[i], codeBase, codeSize))
            {
                std::string hash = CalculateSHA256String(static_cast<BYTE *>(codeBase), codeSize);
                snapshot.set_code_section_hash(hash);
            }
            snapshots.push_back(snapshot);
        }
    }
    return snapshots;
}

std::string CheatMonitorEngine::GetCertificateThumbprint(const std::wstring &filePath)
{
    HCERTSTORE hStore = NULL;
    HCRYPTMSG hMsg = NULL;
    PCCERT_CONTEXT pCertContext = NULL;
    std::string thumbprint;

    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, filePath.c_str(), CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                          CERT_QUERY_FORMAT_FLAG_BINARY, 0, NULL, NULL, NULL, &hStore, &hMsg, NULL))
    {
        return "";
    }

    DWORD dwSignerInfo = 0;
    CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, NULL, &dwSignerInfo);
    std::vector<BYTE> signerInfo(dwSignerInfo);
    CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, signerInfo.data(), &dwSignerInfo);

    CMSG_SIGNER_INFO *pSignerInfo = (CMSG_SIGNER_INFO *)signerInfo.data();
    CERT_INFO certInfo = {0};
    certInfo.Issuer = pSignerInfo->Issuer;
    certInfo.SerialNumber = pSignerInfo->SerialNumber;
    pCertContext = CertFindCertificateInStore(hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT,
                                              &certInfo, NULL);

    if (pCertContext)
    {
        BYTE hash[32];
        DWORD hashLen = sizeof(hash);
        bool useSHA256 = CertGetCertificateContextProperty(pCertContext, CERT_SHA256_HASH_PROP_ID, hash, &hashLen);
        if (!useSHA256)
        {
            LOG_DEBUG(AntiCheatLogger::LogCategory::SYSTEM, "GetCertificateThumbprint: SHA-256 证书属性不支持，降级使用 SHA-1");
            hashLen = 20;
            if (!CertGetCertificateContextProperty(pCertContext, CERT_SHA1_HASH_PROP_ID, hash, &hashLen))
            {
                LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM,
                              "GetCertificateThumbprint: 获取 SHA-1 证书指纹也失败，错误码: 0x%08X", GetLastError());
                CertFreeCertificateContext(pCertContext);
                if (hStore) CertCloseStore(hStore, 0);
                if (hMsg) CryptMsgClose(hMsg);
                return "";
            }
        }

        std::ostringstream oss;
        oss << (useSHA256 ? "sha256:" : "sha1:");
        for (DWORD i = 0; i < hashLen; i++)
        {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
        }
        thumbprint = oss.str();
        CertFreeCertificateContext(pCertContext);
    }

    if (hStore) CertCloseStore(hStore, 0);
    if (hMsg) CryptMsgClose(hMsg);
    return thumbprint;
}

std::string CheatMonitorEngine::CalculateSHA256String(const BYTE *data, size_t size)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    bool useAES = CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    if (!useAES)
    {
        if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
        {
            LOG_DEBUG(AntiCheatLogger::LogCategory::SYSTEM, "CalculateSHA256String: 无法获取加密上下文，可能不支持加密API");
            return "";
        }
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        DWORD error = GetLastError();
        if (error == NTE_BAD_ALGID || error == ERROR_INVALID_PARAMETER)
        {
            LOG_DEBUG(AntiCheatLogger::LogCategory::SYSTEM, "CalculateSHA256String: SHA-256 不支持，降级使用 SHA-1");
            if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash))
            {
                LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM, "CalculateSHA256String: SHA-1 也不支持，错误码: 0x%08X",
                              GetLastError());
                CryptReleaseContext(hProv, 0);
                return "";
            }
        }
        else
        {
            LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM, "CalculateSHA256String: 创建哈希失败，错误码: 0x%08X", error);
            CryptReleaseContext(hProv, 0);
            return "";
        }
    }

    if (!CryptHashData(hHash, data, size, 0))
    {
        LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM, "CalculateSHA256String: 哈希数据失败，错误码: 0x%08X",
                      GetLastError());
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    DWORD hashLen = 0;
    DWORD paramLen = sizeof(hashLen);
    if (!CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE *)&hashLen, &paramLen, 0))
    {
        LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM, "CalculateSHA256String: 获取哈希长度失败，错误码: 0x%08X",
                      GetLastError());
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    std::vector<BYTE> hash(hashLen);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashLen, 0))
    {
        LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM, "CalculateSHA256String: 获取哈希值失败，错误码: 0x%08X",
                      GetLastError());
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    std::ostringstream oss;
    if (hashLen == 20)
        oss << "sha1:";
    else if (hashLen == 32)
        oss << "sha256:";
    for (DWORD i = 0; i < hashLen; i++)
    {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return oss.str();
}
