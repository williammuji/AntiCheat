#include "ModuleIntegritySensor.h"
#include "SensorRuntimeContext.h"
#include "utils/SystemUtils.h"
#include "Logger.h"
#include "utils/Utils.h"
#include "utils/Scanners.h"
#include "CheatConfigManager.h"
#include <algorithm>
#include <limits>
#include <psapi.h>
#include <sstream>

namespace
{
    std::wstring ToLowerCopy(std::wstring value)
    {
        std::transform(value.begin(), value.end(), value.begin(), ::towlower);
        return value;
    }

    bool IsProtectedAssetModule(const std::wstring &modulePath)
    {
        return Utils::GetFileName(ToLowerCopy(modulePath)) == L"game.exe";
    }

    const char *SignatureStatusToString(Utils::SignatureStatus status)
    {
        switch (status)
        {
            case Utils::SignatureStatus::TRUSTED:
                return "trusted";
            case Utils::SignatureStatus::UNTRUSTED:
                return "untrusted";
            case Utils::SignatureStatus::FAILED_TO_VERIFY:
                return "failed_to_verify";
            case Utils::SignatureStatus::UNKNOWN:
            default:
                return "unknown";
        }
    }
}

bool ModuleIntegritySensor::IsWritableCodeProtection(DWORD protect)
{
    return (protect & (PAGE_EXECUTE_READWRITE | PAGE_READWRITE | PAGE_EXECUTE_WRITECOPY | PAGE_WRITECOPY)) != 0;
}

bool ModuleIntegritySensor::ShouldLearnTrustedBaseline(bool validationTrusted)
{
    return validationTrusted;
}

bool ModuleIntegritySensor::ShouldEmitTamperEvidence(bool isSelfModule, bool isWhitelisted)
{
    if (isSelfModule)
    {
        return true;
    }
    return !isWhitelisted;
}

SensorExecutionResult ModuleIntegritySensor::Execute(SensorRuntimeContext &context)
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
    const bool targetedScan = context.IsTargetedScan();

    // 2. 内存使用限制：代码节大小限制
    // ModuleIntegritySensor专注于检测所有模块的代码完整性，但限制单个代码节大小
    const size_t MAX_CODE_SECTION_SIZE = CheatConfigManager::GetInstance().GetMaxCodeSectionSize();
    const int budget_ms = targetedScan ? std::numeric_limits<int>::max()
                                       : CheatConfigManager::GetInstance().GetHeavyScanBudgetMs();
    const auto startTime = std::chrono::steady_clock::now();
    auto recordValue = [&](const std::string &key, uint64_t value) {
        context.RecordSensorDiagnosticValue("ModuleIntegritySensor", key, std::to_string(value));
    };
    auto recordText = [&](const std::string &key, const std::string &value) {
        context.RecordSensorDiagnosticValue("ModuleIntegritySensor", key, value);
    };
    recordValue("config_max_code_section_size_bytes", static_cast<uint64_t>(MAX_CODE_SECTION_SIZE));
    recordText("scan_mode", targetedScan ? "targeted" : "periodic");

    // 3. 使用公共扫描器枚举模块（游标 + 限额 + 时间片）
    size_t startCursor = targetedScan ? 0 : context.GetModuleCursorOffset();
    size_t index = 0;
    size_t processed = 0;
    const int maxModules = targetedScan ? std::numeric_limits<int>::max()
                                        : std::max(1, CheatConfigManager::GetInstance().GetMaxModulesPerScan());
    bool timeoutOccurred = false;
    bool stopEnumerate = false;
    std::wstring lastModName;
    ModuleScanner::EnumerateModules([&](HMODULE hModule) {
        if (stopEnumerate)
            return;
        // 游标：跳过上次已处理过的部分
        if (index++ < startCursor)
            return;

        // 缓存机制：如果HMODULE未变且路径一致，复用CodeSection信息，避免重复解析PE头
        CachedModuleInfo modInfo = {};
        auto it = m_moduleCache.find(hModule);
        wchar_t curNameW[MAX_PATH] = {0};
        bool needsUpdate = true;

        // 总是先快速获取文件名，用于验证缓存有效性
        if (GetModuleFileNameW(hModule, curNameW, MAX_PATH) != 0)
        {
            if (it != m_moduleCache.end())
            {
                // 检查路径是否匹配（处理DLL卸载重加载情况）
                if (it->second.modulePath == curNameW)
                {
                    modInfo = it->second;
                    needsUpdate = false;
                }
            }
        }
        else
        {
            // 获取文件名失败，无法继续
            context.RecordSensorDiagnosticCounter("ModuleIntegritySensor", "get_module_path_failed_count", 1);
            context.RecordSensorDiagnosticValue("ModuleIntegritySensor", "last_get_module_path_failed_hmodule",
                                                Utils::FormatString("0x%p", hModule));
            RecordFailure(anti_cheat::MODULE_INTEGRITY_GET_MODULE_PATH_FAILED);
            return;
        }

        // 如果需要更新缓存（新模块或模块变更）
        if (needsUpdate)
        {
            modInfo.modulePath = curNameW;
            modInfo.codeSectionResult =
                    SystemUtils::GetModuleCodeSectionInfoDetailed(hModule, modInfo.codeBase, modInfo.codeSize);
            modInfo.valid = modInfo.codeSectionResult.success;

            // 检查特殊模块逻辑（用于标记）
            if (!modInfo.valid)
            {
                std::wstring lowerName = curNameW;
                std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
                auto integrityIgnoreList = context.GetWhitelistedIntegrityIgnoreList();
                bool isSpecial = false;
                if (integrityIgnoreList)
                {
                    for (const auto &kw : *integrityIgnoreList)
                    {
                        const std::wstring lowerKeyword = ToLowerCopy(kw);
                        if (!lowerKeyword.empty() && lowerName.find(lowerKeyword) != std::wstring::npos)
                        {
                            isSpecial = true;
                            context.RecordSensorDiagnosticValue("ModuleIntegritySensor",
                                                                "last_integrity_ignore_match",
                                                                Utils::WideToString(kw));
                            break;
                        }
                    }
                }
                modInfo.isSpecial = isSpecial;
            }
            m_moduleCache[hModule] = modInfo;
        }

        // The ignore list can be updated by server config after this module was cached,
        // so refresh the flag on every scan for PE files without a code section.
        if (!modInfo.valid)
        {
            std::wstring lowerName = modInfo.modulePath;
            std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
            auto integrityIgnoreList = context.GetWhitelistedIntegrityIgnoreList();
            bool isSpecial = false;
            if (integrityIgnoreList)
            {
                for (const auto &kw : *integrityIgnoreList)
                {
                    const std::wstring lowerKeyword = ToLowerCopy(kw);
                    if (!lowerKeyword.empty() && lowerName.find(lowerKeyword) != std::wstring::npos)
                    {
                        isSpecial = true;
                        context.RecordSensorDiagnosticValue("ModuleIntegritySensor",
                                                            "last_integrity_ignore_match",
                                                            Utils::WideToString(kw));
                        break;
                    }
                }
            }
            modInfo.isSpecial = isSpecial;
            m_moduleCache[hModule].isSpecial = isSpecial;
        }

        // 更新lastModName用于日志（使用缓存的路径）
        lastModName = modInfo.modulePath;
        std::transform(lastModName.begin(), lastModName.end(),
                       lastModName.begin(), ::towlower);

        MaybeReportUnsignedProtectedAsset(hModule, modInfo, context);

        // 超时检查
        {
            auto now = std::chrono::steady_clock::now();
            if (!targetedScan && processed > 0 &&
                std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count() > budget_ms)
            {
                const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count();
                LOG_WARNING_F(
                        AntiCheatLogger::LogCategory::SENSOR,
                        "ModuleIntegritySensor超时: elapsed=%lldms budget=%dms processed=%zu index=%zu current='%s'",
                        (long long)elapsed, budget_ms, processed, index,
                        Utils::WideToString(lastModName).c_str());
                context.RecordSensorDiagnosticValue("ModuleIntegritySensor", "last_timeout_module",
                                                    Utils::WideToString(lastModName));
                context.RecordSensorDiagnosticValue("ModuleIntegritySensor", "last_timeout_elapsed_ms",
                                                    std::to_string(static_cast<uint64_t>(elapsed)));
                context.RecordSensorDiagnosticValue("ModuleIntegritySensor", "last_timeout_budget_ms",
                                                    std::to_string(static_cast<uint64_t>(budget_ms)));
                RecordFailure(anti_cheat::MODULE_SCAN_TIMEOUT);
                timeoutOccurred = true;
                stopEnumerate = true;
                return;
            }
        }

        if (ProcessModuleCodeIntegrity(hModule, modInfo, context, baselineHashes, MAX_CODE_SECTION_SIZE) == SensorExecutionResult::TIMEOUT)
        {
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - startTime).count();
            context.RecordSensorDiagnosticValue("ModuleIntegritySensor", "last_timeout_module",
                                                Utils::WideToString(lastModName));
            context.RecordSensorDiagnosticValue("ModuleIntegritySensor", "last_timeout_elapsed_ms",
                                                std::to_string(static_cast<uint64_t>(elapsed)));
            context.RecordSensorDiagnosticValue("ModuleIntegritySensor", "last_timeout_budget_ms",
                                                std::to_string(static_cast<uint64_t>(budget_ms)));
            RecordFailure(anti_cheat::MODULE_SCAN_TIMEOUT);
            timeoutOccurred = true;
            stopEnumerate = true;
            return;
        }
        processed++;
        if (!targetedScan && processed >= (size_t)maxModules)
        {
            stopEnumerate = true;
            return;
        }
    });

    // 更新游标（按本轮实际处理的模块数轮转）
    if (index > 0)
    {
        size_t nextCursor = targetedScan ? 0 : (startCursor + processed) % index;
        context.SetModuleCursorOffset(nextCursor);
    }

    // Telemetry: 记录本轮模块快照与处理量
    context.RecordSensorWorkloadCounters("ModuleIntegritySensor", (uint64_t)index, (uint64_t)processed,
                                         (uint64_t)processed);
    recordValue("last_module_cursor_start", static_cast<uint64_t>(startCursor));
    recordValue("last_modules_enumerated", static_cast<uint64_t>(index));
    recordValue("last_modules_processed", static_cast<uint64_t>(processed));
    recordValue("last_module_cursor_next", static_cast<uint64_t>(context.GetModuleCursorOffset()));
    if (!lastModName.empty())
    {
        recordText("last_module_seen", Utils::WideToString(lastModName));
    }

    // 如果发生超时，直接返回超时
    if (timeoutOccurred)
    {
        return SensorExecutionResult::TIMEOUT;
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

void ModuleIntegritySensor::MaybeReportUnsignedProtectedAsset(HMODULE hModule, const CachedModuleInfo &info,
                                                              SensorRuntimeContext &context)
{
    if (info.modulePath.empty() || !IsProtectedAssetModule(info.modulePath))
    {
        return;
    }

    const std::wstring normalizedPath = SystemUtils::SystemNormalizePathLowercase(info.modulePath);

    if (m_reportedUnsignedProtectedAssets.count(normalizedPath) > 0)
    {
        return;
    }

    const Utils::SignatureStatus signatureStatus =
            Utils::VerifyFileSignature(info.modulePath, context.GetWindowsVersion());
    const char *signatureStatusText = SignatureStatusToString(signatureStatus);

    MODULEINFO moduleInfo = {};
    uint64_t moduleSize = 0;
    if (GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(moduleInfo)))
    {
        moduleSize = moduleInfo.SizeOfImage;
    }

    m_reportedUnsignedProtectedAssets.insert(normalizedPath);

    if (signatureStatus == Utils::SignatureStatus::TRUSTED)
    {
        return;
    }

    if (signatureStatus != Utils::SignatureStatus::UNTRUSTED)
    {
        return;
    }

    std::ostringstream oss;
    oss << "Protected asset module is unsigned or has a bad digest: " << Utils::WideToString(info.modulePath)
        << " (signature_status=" << signatureStatusText
        << ", module_size=" << moduleSize
        << ", code_section_size=" << static_cast<uint64_t>(info.codeSize)
        << ", code_section_status="
        << SystemUtils::ModuleCodeSectionInfoStatusToString(info.codeSectionResult.status)
        << ")";
    context.AddEvidence(anti_cheat::INTEGRITY_ASSET_TAMPERED, oss.str());
}

SensorExecutionResult ModuleIntegritySensor::ProcessModuleCodeIntegrity(HMODULE hModule, const CachedModuleInfo &info, SensorRuntimeContext &context,
                                    const std::unordered_map<std::wstring, std::vector<uint8_t>> &baselineHashes,
                                    size_t maxCodeSectionSize)
{
    // 注意：不再跳过自身模块，让ModuleCodeIntegritySensor也检测自身完整性
    if (!info.valid)
    {
        const char *status = SystemUtils::ModuleCodeSectionInfoStatusToString(info.codeSectionResult.status);
        const bool isNoCodeSection =
                info.codeSectionResult.status == SystemUtils::ModuleCodeSectionInfoStatus::NoCodeSection;
        context.RecordSensorDiagnosticCounter("ModuleIntegritySensor", "code_section_invalid_count", 1);
        context.RecordSensorDiagnosticCounter("ModuleIntegritySensor",
                                              std::string("code_section_invalid_reason.") + status, 1);
        if (info.isSpecial || isNoCodeSection)
        {
            context.RecordSensorDiagnosticValue("ModuleIntegritySensor", "last_code_section_suppressed_module",
                                                Utils::WideToString(info.modulePath));
            context.RecordSensorDiagnosticValue("ModuleIntegritySensor", "last_code_section_suppressed_reason",
                                                status);
            LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                        "ModuleIntegritySensor: module has no code section or is ignored, module=%s, hModule=0x%p",
                        Utils::WideToString(info.modulePath).c_str(), hModule);
            return SensorExecutionResult::SUCCESS;
        }

        context.RecordSensorDiagnosticValue("ModuleIntegritySensor", "last_code_section_invalid_module",
                                            Utils::WideToString(info.modulePath));
        context.RecordSensorDiagnosticValue("ModuleIntegritySensor", "last_code_section_failure_status", status);
        context.RecordSensorDiagnosticValue("ModuleIntegritySensor", "last_code_section_failure_exception",
                                            Utils::FormatString("0x%08X", info.codeSectionResult.exceptionCode));
        context.RecordSensorDiagnosticValue("ModuleIntegritySensor", "last_code_section_failure_dos_magic",
                                            Utils::FormatString("0x%04X", info.codeSectionResult.dosMagic));
        context.RecordSensorDiagnosticValue("ModuleIntegritySensor", "last_code_section_failure_nt_signature",
                                            Utils::FormatString("0x%08X", info.codeSectionResult.ntSignature));
        context.RecordSensorDiagnosticValue("ModuleIntegritySensor", "last_code_section_failure_sections",
                                            std::to_string(static_cast<uint64_t>(info.codeSectionResult.numberOfSections)));
        RecordFailure(anti_cheat::MODULE_INTEGRITY_GET_CODE_SECTION_FAILED);
        LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                      "ModuleIntegritySensor: failed to get code section info, module=%s, hModule=0x%p",
                      Utils::WideToString(info.modulePath).c_str(), hModule);
        return SensorExecutionResult::FAILURE;
    }

    // 检查代码节大小是否超过限制
    if (info.codeSize > maxCodeSectionSize)
    {
        context.RecordSensorDiagnosticCounter("ModuleIntegritySensor", "code_section_oversize_skip_count", 1);
        context.RecordSensorDiagnosticValue("ModuleIntegritySensor", "last_code_section_oversize_module",
                                            Utils::WideToString(info.modulePath));
        context.RecordSensorDiagnosticValue("ModuleIntegritySensor", "last_code_section_size_bytes",
                                            std::to_string(static_cast<uint64_t>(info.codeSize)));
        LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                      "ModuleIntegritySensor: 代码节过大，跳过模块: %s (大小: %lu > %zu MB)",
                      Utils::WideToString(info.modulePath).c_str(), info.codeSize / (1024 * 1024),
                      maxCodeSectionSize / (1024 * 1024));
        return SensorExecutionResult::SUCCESS;
    }

    // 将复杂逻辑移到外部处理
    return ValidateModuleCodeIntegrity(info.modulePath.c_str(), hModule, info.codeBase, info.codeSize, context,
                                 baselineHashes);
}

SensorExecutionResult ModuleIntegritySensor::ValidateModuleCodeIntegrity(const wchar_t *modulePath_w, HMODULE hModule, PVOID codeBase, DWORD codeSize,
                                     SensorRuntimeContext &context,
                                     const std::unordered_map<std::wstring, std::vector<uint8_t>> &baselineHashes)
{
    std::wstring modulePath(modulePath_w);

    // 提前计算自身/白名单状态，供可写代码节检查与后续 Hash 比对复用，
    // 确保两处检测使用一致的降噪策略（系统目录 DLL、显式白名单模块统一抑制）。
    HMODULE selfModule = context.GetSelfModuleHandle();
    if (!selfModule)
    {
        LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "ModuleIntegritySensor: 无法获取自身模块句柄");
        this->RecordFailure(anti_cheat::MODULE_INTEGRITY_GET_SELF_MODULE_FAILED);
        return SensorExecutionResult::FAILURE;
    }
    const bool isSelfModule = (hModule == selfModule);
    const bool isExplicitlyWhitelisted = Utils::IsExplicitlyWhitelistedModule(modulePath);
    const bool isWhitelisted = Utils::IsWhitelistedModule(modulePath);

    // 1. Check for Writable Code Section (Anti-Patching / Hooking)
    // 对于系统目录 DLL（如 SysWOW64\ntdll.dll）和显式白名单模块，用户态 Hook 非常常见
    // （国内安全软件、EDR、Windows 热补丁、兼容性 shim 等），默认降噪避免误报。
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(codeBase, &mbi, sizeof(mbi)))
    {
         if (IsWritableCodeProtection(mbi.Protect))
         {
             if (ShouldEmitTamperEvidence(isSelfModule, isWhitelisted))
             {
                 context.RecordSensorDiagnosticCounter("ModuleIntegritySensor", "writable_code_section_evidence_count", 1);
                 context.RecordSensorDiagnosticValue("ModuleIntegritySensor", "last_writable_code_section_module",
                                                     Utils::WideToString(modulePath_w));
                 context.RecordSensorDiagnosticValue("ModuleIntegritySensor", "last_writable_code_section_protect",
                                                     std::to_string(static_cast<uint64_t>(mbi.Protect)));
                 std::string u8Path = Utils::WideToString(modulePath_w);
                 context.AddEvidence(anti_cheat::INTEGRITY_MEMORY_PATCH, "Writable code section detected: " + u8Path);
             }
             else
             {
                 LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                             "ModuleIntegritySensor: 白名单/系统模块代码节可写（抑制告警）: %s (Protect=0x%08X)",
                             Utils::WideToString(modulePath).c_str(), mbi.Protect);
             }
         }
    }

    const bool targetedScan = context.IsTargetedScan();
    uint64_t currentHashState = targetedScan ? 0 : context.GetModuleIntegrityPartialHash();
    size_t internalOffset = targetedScan ? 0 : context.GetModuleInternalOffset();

    int budget_ms = targetedScan ? std::numeric_limits<int>::max()
                                 : CheatConfigManager::GetInstance().GetHeavyScanBudgetMs();
    // budget_ms <= 0 表示配置未设置；此时不对单个模块的内层 Hash 施加时间限制，
    // 让当前模块整体一次 Hash 完成（与外层超时机制协调）。
    if (budget_ms <= 0) budget_ms = std::numeric_limits<int>::max();

    auto startTime = std::chrono::steady_clock::now();

    if (internalOffset == 0)
    {
        currentHashState = 14695981039346656037ULL;
    }

    const size_t CHUNK_SIZE = 64 * 1024;
    const BYTE* pBase = static_cast<const BYTE*>(codeBase);

    while (internalOffset < codeSize)
    {
        size_t bytesToHash = std::min<size_t>(CHUNK_SIZE, (size_t)codeSize - internalOffset);
        currentHashState = SystemUtils::CalculateFnv1aHashPartial(pBase + internalOffset, bytesToHash, currentHashState);
        internalOffset += bytesToHash;

        auto now = std::chrono::steady_clock::now();
        if (!targetedScan &&
            std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count() >= budget_ms)
        {
            // Ensure we only timeout if we've made some progress in THIS call
            // OR if the setup has taken significant time.
            // But we already updated internalOffset, so we HAVE made progress.
            context.SetModuleInternalOffset(internalOffset);
            context.SetModuleIntegrityPartialHash(currentHashState);
            LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR, "ModuleIntegritySensor 模块内超时: %s (进度: %zu/%lu)", Utils::WideToString(modulePath).c_str(), internalOffset, (unsigned long)codeSize);
            return SensorExecutionResult::TIMEOUT;
        }
    }

    std::vector<uint8_t> currentHash = SystemUtils::HashToBytes(currentHashState);
    context.SetModuleInternalOffset(0);
    context.SetModuleIntegrityPartialHash(0);

    auto it = baselineHashes.find(modulePath);

    if (it == baselineHashes.end())
    {
        // LEARNING MODE: 动态基线建立
        // 安全对齐逻辑：新发现的模块必须通过可信验证（签名 + 路径）才能动态建立基线
        // 防止外挂在运行期间动态加载未签名的代码并被当作“合法现状”记录
        Utils::ModuleValidationResult validation;
        if (isExplicitlyWhitelisted)
        {
            validation.isTrusted = true;
            validation.reason = "显式配置白名单（路径或文件名匹配）";
            validation.signatureStatus = Utils::SignatureStatus::UNKNOWN;
        }
        else
        {
            validation = Utils::ValidateModule(modulePath, context.GetWindowsVersion());
        }

        if (ShouldLearnTrustedBaseline(validation.isTrusted))
        {
            // 生成哈希字符串用于日志
            std::string hash_str;
            char buf[17];
            for (uint8_t byte : currentHash)
            {
                sprintf_s(buf, sizeof(buf), "%02x", byte);
                hash_str += buf;
            }

            // 更新基线!
            context.UpdateModuleBaselineHash(modulePath, currentHash);

            std::ostringstream log_msg;
            log_msg << "动态建立新可信模块基线: " << Utils::WideToString(modulePath)
                    << " | 原因: " << validation.reason
                    << " | Hash: " << hash_str
                    << " | 代码节大小: " << codeSize << " bytes";

            // 使用SendServerLog上传到服务器
            context.SendServerLog("INFO", "MODULE_LEARNING_TRUSTED", log_msg.str());
        }
        else
        {
            // 拒绝为不可信模块建立基线，并立即产生作弊证据
            context.RecordSensorDiagnosticCounter("ModuleIntegritySensor", "untrusted_dynamic_baseline_reject_count", 1);
            context.RecordSensorDiagnosticValue("ModuleIntegritySensor", "last_untrusted_dynamic_baseline_module",
                                                Utils::WideToString(modulePath));
            context.RecordSensorDiagnosticValue("ModuleIntegritySensor", "last_untrusted_dynamic_baseline_reason",
                                                validation.reason);
            context.RecordSensorDiagnosticValue("ModuleIntegritySensor", "last_untrusted_dynamic_baseline_code_size",
                                                std::to_string(static_cast<uint64_t>(codeSize)));
            LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                          "ModuleIntegritySensor: 拒绝动态建立不可信模块基线: %s | 原因: %s",
                          Utils::WideToString(modulePath).c_str(), validation.reason.c_str());

            context.AddEvidence(anti_cheat::MODULE_UNTRUSTED_DYNAMIC_LOAD,
                                "拒绝动态建立不可信模块基线: " + Utils::WideToString(modulePath) +
                                " (原因: " + validation.reason + ")");
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
                context.RecordSensorDiagnosticCounter("ModuleIntegritySensor", "self_hash_mismatch_count", 1);
                context.RecordSensorDiagnosticValue("ModuleIntegritySensor", "last_hash_mismatch_module",
                                                    Utils::WideToString(modulePath));
                // 自身模块被篡改，使用专门的证据类型
                LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR,
                            "ModuleIntegritySensor: 检测到反作弊模块自身被篡改: %s | 当前Hash: %s | 基线Hash: %s | "
                            "代码节大小: %lu bytes",
                            Utils::WideToString(modulePath).c_str(), currentHash_str.c_str(),
                            baselineHash_str.c_str(), codeSize);
                context.AddEvidence(anti_cheat::INTEGRITY_SELF_TAMPERING,
                                    "检测到反作弊模块自身被篡改: " + Utils::WideToString(modulePath));
            }
            else if (isWhitelisted)
            {
                context.RecordSensorDiagnosticCounter("ModuleIntegritySensor", "whitelisted_hash_mismatch_count", 1);
                context.RecordSensorDiagnosticValue("ModuleIntegritySensor", "last_hash_mismatch_module",
                                                    Utils::WideToString(modulePath));
                // 白名单模块（系统DLL或合法第三方软件）被修改：降级为警告日志
                // 原因：热补丁、安全软件、驱动更新等合法场景
                LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                            "ModuleIntegritySensor: 检测到白名单模块代码节变化（合法修改）: %s | 当前Hash: %s | 基线Hash: %s | "
                            "代码节大小: %lu bytes",
                            Utils::WideToString(modulePath).c_str(), currentHash_str.c_str(),
                            baselineHash_str.c_str(), codeSize);
                // 不调用 AddEvidence，避免误报
            }
            else if (ShouldEmitTamperEvidence(isSelfModule, isWhitelisted))
            {
                context.RecordSensorDiagnosticCounter("ModuleIntegritySensor", "untrusted_hash_mismatch_count", 1);
                context.RecordSensorDiagnosticValue("ModuleIntegritySensor", "last_hash_mismatch_module",
                                                    Utils::WideToString(modulePath));
                // 非白名单模块被篡改：真正可疑的情况
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
    return SensorExecutionResult::SUCCESS;
}
