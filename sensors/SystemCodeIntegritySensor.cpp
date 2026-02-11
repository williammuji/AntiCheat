#include "SystemCodeIntegritySensor.h"
#include "ScanContext.h"
#include "utils/SystemUtils.h"
#include "Logger.h"

SensorExecutionResult SystemCodeIntegritySensor::Execute(ScanContext &context)
{
    // 重置失败原因
    m_lastFailureReason = anti_cheat::UNKNOWN_FAILURE;

    // 策略1：配置版本门控 - 检查当前OS是否满足配置的最低要求
    if (!IsOsSupported(context))
    {
        LOG_DEBUG(AntiCheatLogger::LogCategory::SENSOR, "系统代码完整性检测已禁用：当前OS版本低于配置最低要求");
        RecordFailure(anti_cheat::SYSTEM_CODE_INTEGRITY_OS_VERSION_UNSUPPORTED);
        return SensorExecutionResult::FAILURE;
    }

    SYSTEM_CODE_INTEGRITY_INFORMATION sci = {sizeof(sci), 0};
    ULONG retLen = 0;
    if (SystemUtils::g_pNtQuerySystemInformation &&
        NT_SUCCESS(SystemUtils::g_pNtQuerySystemInformation(SystemCodeIntegrityInformation, &sci, sizeof(sci),
                                                            &retLen)))
    {
        if (sci.CodeIntegrityOptions & 0x02)
        {
            context.AddEvidence(anti_cheat::ENVIRONMENT_SUSPICIOUS_DRIVER,
                                "系统开启了测试签名模式 (Test Signing Mode)");
        }
        if (sci.CodeIntegrityOptions & 0x01)
        {
            // 合取判定：仅当 NtQuerySystemInformation 确认 KD 存在时才上报
            if (CheckKernelDebuggerPresent())
            {
                context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED,
                                    "系统开启了内核调试模式 (Kernel Debugging Enabled)");
            }
        }
    }
    else
    {
        // NtQuerySystemInformation失败，记录失败原因
        LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR,
                    "SystemCodeIntegritySensor: NtQuerySystemInformation失败");
        RecordFailure(anti_cheat::SYSTEM_CODE_INTEGRITY_QUERY_FAILED);
        return SensorExecutionResult::FAILURE;
    }

    // 策略2：自我完整性检查
    // 检查关键反作弊函数是否被Patch（例如 IsAddressInLegitimateModule 被改为直接返回 true）
    context.CheckSelfIntegrity();

    // 统一的执行结果判断逻辑
    // 成功条件：没有失败原因记录
    if (m_lastFailureReason != anti_cheat::UNKNOWN_FAILURE)
    {
        return SensorExecutionResult::FAILURE;
    }

    return SensorExecutionResult::SUCCESS;
}

bool SystemCodeIntegritySensor::CheckKernelDebuggerPresent()
{
    bool kdPresent = false;
    __try
    {
        SYSTEM_KERNEL_DEBUGGER_INFORMATION kdInfo = {};
        if (SystemUtils::g_pNtQuerySystemInformation &&
            NT_SUCCESS(SystemUtils::g_pNtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(35), &kdInfo,
                                                                 sizeof(kdInfo), nullptr)))
        {
            kdPresent = (kdInfo.KernelDebuggerEnabled && !kdInfo.KernelDebuggerNotPresent);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        kdPresent = false;
    }
    return kdPresent;
}
