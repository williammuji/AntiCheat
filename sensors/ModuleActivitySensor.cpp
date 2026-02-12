#include "ModuleActivitySensor.h"
#include "SensorRuntimeContext.h"
#include "CheatConfigManager.h"
#include "utils/SystemUtils.h"
#include "Logger.h"
#include "utils/Utils.h"
#include <vector>
#include <algorithm>
#include <sstream>

SensorExecutionResult ModuleActivitySensor::Execute(SensorRuntimeContext &context)
{
    // 重置失败原因
    m_lastFailureReason = anti_cheat::UNKNOWN_FAILURE;

    // 策略1：配置版本门控
    if (!IsOsSupported(context))
    {
        LOG_DEBUG(AntiCheatLogger::LogCategory::SENSOR, "模块活动监控检测已禁用：当前OS版本低于配置最低要求");
        RecordFailure(anti_cheat::THREAD_MODULE_OS_VERSION_UNSUPPORTED);
        return SensorExecutionResult::FAILURE;
    }

    const int budget_ms = CheatConfigManager::GetInstance().GetHeavyScanBudgetMs();
    const auto startTime = std::chrono::steady_clock::now();

    // 3. 扫描模块（新活动检测）
    if (!ScanModulesWithTimeout(context, budget_ms, startTime))
    {
        return SensorExecutionResult::FAILURE;
    }

    if (m_lastFailureReason != anti_cheat::UNKNOWN_FAILURE)
    {
        return SensorExecutionResult::FAILURE;
    }

    return SensorExecutionResult::SUCCESS;
}

bool ModuleActivitySensor::ScanModulesWithTimeout(SensorRuntimeContext &context, int budget_ms,
                                                  const std::chrono::steady_clock::time_point &startTime)
{
    int moduleCount = 0;
    bool timeoutOccurred = false;

    // 使用 Cache 避免重复调用 EnumProcessModules
    if (context.CachedModules.empty())
    {
         // 如果缓存为空，但没有模块是不可能的（至少有自己），说明枚举失败或者真的空
         // 检查是否是系统级失败（EnumProcessModules失败）
         std::vector<HMODULE> hMods(1);
         DWORD cbNeeded = 0;
         if (!EnumProcessModules(GetCurrentProcess(), hMods.data(), hMods.size() * sizeof(HMODULE), &cbNeeded))
         {
             LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "ModuleActivitySensor: 模块枚举失败");
             RecordFailure(anti_cheat::THREAD_MODULE_OPEN_MODULE_FAILED);
             return false;
         }
         // 如果 Cache 为空但 API 成功，可能是真的没获取到还是 SensorRuntimeContext 逻辑问题？
         // 暂且认为失败
         RecordFailure(anti_cheat::THREAD_MODULE_MODULE_SCAN_FAILED);
         return false;
    }

    for (const auto& hModule : context.CachedModules)
    {
        // 优化：每15个模块检查一次超时
        if (moduleCount % 15 == 0)
        {
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count() > budget_ms)
            {
                LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "ModuleActivitySensor: 模块扫描超时");
                RecordFailure(anti_cheat::MODULE_SCAN_TIMEOUT);
                timeoutOccurred = true;
                break;
            }
        }
        moduleCount++;

        if (context.IsModuleKnown(hModule))
        {
            continue;
        }

        wchar_t modulePath[MAX_PATH] = {0};
        if (GetModuleFileNameW(hModule, modulePath, MAX_PATH) == 0)
        {
            continue;
        }

        // 使用统一白名单检查
        bool isWhitelisted = Utils::IsWhitelistedModule(modulePath);
        SystemUtils::WindowsVersion winVer = SystemUtils::GetWindowsVersion();

        Utils::ModuleValidationResult validation;
        if (isWhitelisted)
        {
            validation.isTrusted = true;
            validation.reason = "白名单模块（路径或文件名匹配）";
            validation.signatureStatus = Utils::SignatureStatus::UNKNOWN;
        }
        else
        {
            validation = Utils::ValidateModule(modulePath, winVer);
        }

        if (validation.isTrusted)
        {
            context.InsertKnownModule(hModule);
        }
        else
        {
            std::ostringstream oss;
            oss << "检测到不可信模块: " << Utils::WideToString(modulePath);
            oss << " (原因: " << validation.reason << ")";

            context.AddEvidence(anti_cheat::RUNTIME_MODULE_NEW_UNKNOWN, oss.str());

            LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                         "ModuleActivitySensor: 发现不可信模块 %s (原因: %s)",
                         Utils::WideToString(modulePath).c_str(),
                         validation.reason.c_str());
        }
    }

    if (timeoutOccurred)
    {
        return false;
    }

    return true;
}
