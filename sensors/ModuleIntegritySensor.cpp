#include "ModuleIntegritySensor.h"
#include "SensorRuntimeContext.h"
#include "utils/SystemUtils.h"
#include "Logger.h"
#include "utils/Utils.h"
#include "utils/Scanners.h"
#include "CheatConfigManager.h"
#include <algorithm>
#include <sstream>

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

    // 3. 使用公共扫描器枚举模块（游标 + 限额 + 时间片）
    size_t startCursor = context.GetModuleCursorOffset();
    size_t index = 0;
    size_t processed = 0;
    const int maxModules = targetedScan ? std::numeric_limits<int>::max()
                                        : std::max(1, CheatConfigManager::GetInstance().GetMaxModulesPerScan());
    bool timeoutOccurred = false;
    bool stopEnumerate = false;
    std::wstring lastProcessedModuleName;
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
            RecordFailure(anti_cheat::MODULE_INTEGRITY_GET_MODULE_PATH_FAILED);
            return;
        }

        // 如果需要更新缓存（新模块或模块变更）
        if (needsUpdate)
        {
            modInfo.modulePath = curNameW;
            modInfo.valid = SystemUtils::GetModuleCodeSectionInfo(hModule, modInfo.codeBase, modInfo.codeSize);

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
                        if (lowerName.find(kw) != std::wstring::npos) { isSpecial = true; break; }
                    }
                }
                modInfo.isSpecial = isSpecial;
            }
            m_moduleCache[hModule] = modInfo;
        }

        // 更新lastProcessedModuleName用于日志（使用缓存的路径）
        lastProcessedModuleName = modInfo.modulePath;
        std::transform(lastProcessedModuleName.begin(), lastProcessedModuleName.end(),
                       lastProcessedModuleName.begin(), ::towlower);

        // 超时检查
        {
            auto now = std::chrono::steady_clock::now();
            if (!targetedScan &&
                std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count() > budget_ms)
            {
                const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count();
                LOG_WARNING_F(
                        AntiCheatLogger::LogCategory::SENSOR,
                        "ModuleIntegritySensor超时: elapsed=%lldms budget=%dms processed=%zu index=%zu current='%s'",
                        (long long)elapsed, budget_ms, processed, index,
                        Utils::WideToString(lastProcessedModuleName).c_str());
                RecordFailure(anti_cheat::MODULE_SCAN_TIMEOUT);
                timeoutOccurred = true;
                stopEnumerate = true;
                return;
            }
        }

        ProcessModuleCodeIntegrity(hModule, modInfo, context, baselineHashes, MAX_CODE_SECTION_SIZE);
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

void ModuleIntegritySensor::ProcessModuleCodeIntegrity(HMODULE hModule, const CachedModuleInfo &info, SensorRuntimeContext &context,
                                    const std::unordered_map<std::wstring, std::vector<uint8_t>> &baselineHashes,
                                    size_t maxCodeSectionSize)
{
    // 注意：不再跳过自身模块，让ModuleCodeIntegritySensor也检测自身完整性
    if (!info.valid)
    {
        if (info.isSpecial)
        {
            // 特殊模块的代码节获取失败是正常情况，记录调试信息
            LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                        "ModuleIntegritySensor: 特殊模块代码节获取失败（正常情况）, 模块=%s, hModule=0x%p",
                        Utils::WideToString(info.modulePath).c_str(), hModule);
        }
        else
        {
            // 普通模块的代码节获取失败需要记录
            RecordFailure(anti_cheat::MODULE_INTEGRITY_GET_CODE_SECTION_FAILED);
            LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                          "ModuleIntegritySensor: 获取代码节信息失败, 模块=%s, hModule=0x%p",
                          Utils::WideToString(info.modulePath).c_str(), hModule);
        }
        return;
    }

    // 检查代码节大小是否超过限制
    if (info.codeSize > maxCodeSectionSize)
    {
        LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                      "ModuleIntegritySensor: 代码节过大，跳过模块: %s (大小: %lu > %zu MB)",
                      Utils::WideToString(info.modulePath).c_str(), info.codeSize / (1024 * 1024),
                      maxCodeSectionSize / (1024 * 1024));
        return;
    }

    // 将复杂逻辑移到外部处理
    ValidateModuleCodeIntegrity(info.modulePath.c_str(), hModule, info.codeBase, info.codeSize, context,
                                baselineHashes);
}

void ModuleIntegritySensor::ValidateModuleCodeIntegrity(const wchar_t *modulePath_w, HMODULE hModule, PVOID codeBase, DWORD codeSize,
                                     SensorRuntimeContext &context,
                                     const std::unordered_map<std::wstring, std::vector<uint8_t>> &baselineHashes)
{
    // 1. Check for Writable Code Section (Anti-Patching / Hooking)
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(codeBase, &mbi, sizeof(mbi)))
    {
         if (IsWritableCodeProtection(mbi.Protect))
         {
             std::string u8Path = Utils::WideToString(modulePath_w);
             // 忽略自身模块（某些加壳或混淆可能导致自身代码段可写）
             if (hModule != context.GetSelfModuleHandle())
             {
                 context.AddEvidence(anti_cheat::INTEGRITY_MEMORY_PATCH, "Writable code section detected: " + u8Path);
             }
         }
    }

    std::wstring modulePath(modulePath_w);
    std::vector<uint8_t> currentHash = SystemUtils::CalculateFnv1aHash(static_cast<BYTE *>(codeBase), codeSize);

    // 检查是否为自身模块
    HMODULE selfModule = context.GetSelfModuleHandle();
    if (!selfModule)
    {
        LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "ModuleIntegritySensor: 无法获取自身模块句柄");
        this->RecordFailure(anti_cheat::MODULE_INTEGRITY_GET_SELF_MODULE_FAILED);
        return;
    }
    bool isSelfModule = (hModule == selfModule);

    // 检查是否在白名单中（系统DLL或信任的第三方软件）
    bool isWhitelisted = Utils::IsWhitelistedModule(modulePath);

    auto it = baselineHashes.find(modulePath);

    if (it == baselineHashes.end())
    {
        // LEARNING MODE: 动态基线建立
        // 安全对齐逻辑：新发现的模块必须通过可信验证（签名 + 路径）才能动态建立基线
        // 防止外挂在运行期间动态加载未签名的代码并被当作“合法现状”记录
        Utils::ModuleValidationResult validation;
        if (isWhitelisted)
        {
            validation.isTrusted = true;
            validation.reason = "白名单模块（路径或文件名匹配）";
            validation.signatureStatus = Utils::SignatureStatus::UNKNOWN;  // 假设未检查或不重要
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
}
