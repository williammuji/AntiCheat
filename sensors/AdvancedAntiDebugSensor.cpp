#include "AdvancedAntiDebugSensor.h"
#include "ScanContext.h"
#include "utils/SystemUtils.h"
#include "Logger.h"
#include <array>
#include <functional>

SensorExecutionResult AdvancedAntiDebugSensor::Execute(ScanContext &context)
{
    // 重置失败原因
    m_lastFailureReason = anti_cheat::UNKNOWN_FAILURE;

    // 策略1：配置版本门控 - 检查当前OS是否满足配置的最低要求
    if (!IsOsSupported(context))
    {
        LOG_DEBUG(AntiCheatLogger::LogCategory::SENSOR, "高级反调试检测已禁用：当前OS版本低于配置最低要求");
        RecordFailure(anti_cheat::ANTI_DEBUG_OS_VERSION_UNSUPPORTED);
        return SensorExecutionResult::FAILURE;
    }

    // 反调试检测数组 - 按检测速度排序，优先执行快速检测
    std::array<std::pair<std::string, std::function<void()>>, 9> checks = {
            {{"RemoteDebugger", [&]() { CheckRemoteDebugger(context); }},
             {"PEB_BeingDebugged", [&]() { CheckPEBBeingDebugged(context); }},
             {"CloseHandle", [&]() { CheckCloseHandleDebugger(context); }},
             {"DebugRegisters", [&]() { CheckDebugRegisters(context); }},
             {"HeapFlags", [&]() { CheckProcessHeapFlags(context); }},
             {"DebugPort", [&]() { CheckProcessDebugPort(context); }},
             {"DebugFlags", [&]() { CheckProcessDebugFlags(context); }},
             {"KernelDebugger_NtQuery",
              [&]() {
                  if (SystemUtils::IsVbsEnabled())
                      return;  // 修复：void函数不能返回值
                  CheckKernelDebuggerNtQuery(context);
              }},
             {"KernelDebugger_KUSER", [&]() {
                  if (SystemUtils::IsVbsEnabled())
                      return;  // 修复：void函数不能返回值
                  CheckKernelDebuggerKUSER(context);
              }}}};

    // 执行检测，每两个检测后检查超时
    for (size_t i = 0; i < checks.size(); ++i)
    {
        checks[i].second();
    }

    // 统一的执行结果判断逻辑
    // 成功条件：没有失败原因记录
    if (m_lastFailureReason != anti_cheat::UNKNOWN_FAILURE)
    {
        return SensorExecutionResult::FAILURE;
    }

    return SensorExecutionResult::SUCCESS;
}

AdvancedAntiDebugSensor::DebugDetectionResult AdvancedAntiDebugSensor::CheckRemoteDebugger_Internal()
{
    DebugDetectionResult result = {false, nullptr, 0};
    __try
    {
        BOOL isDebuggerPresent = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent) && isDebuggerPresent)
        {
            result.detected = true;
            result.description = "CheckRemoteDebuggerPresent() API返回true";
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        result.exceptionCode = GetExceptionCode();
    }
    return result;
}

AdvancedAntiDebugSensor::DebugDetectionResult AdvancedAntiDebugSensor::CheckPEBBeingDebugged_Internal()
{
    DebugDetectionResult result = {false, nullptr, 0};
    __try
    {
#ifdef _WIN64
        auto pPeb = (PPEB)__readgsqword(0x60);
#else
        auto pPeb = (PPEB)__readfsdword(0x30);
#endif
        if (pPeb && SystemUtils::IsValidPointer(pPeb, sizeof(PEB)) && pPeb->BeingDebugged)
        {
            result.detected = true;
            result.description = "PEB->BeingDebugged 标志位为true";
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        result.exceptionCode = GetExceptionCode();
    }
    return result;
}

AdvancedAntiDebugSensor::DebugDetectionResult AdvancedAntiDebugSensor::CheckCloseHandleDebugger_Internal()
{
    DebugDetectionResult result = {false, nullptr, 0};
    __try
    {
        SystemUtils::CheckCloseHandleException();
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        result.exceptionCode = GetExceptionCode();
    }
    return result;
}

AdvancedAntiDebugSensor::DebugDetectionResult AdvancedAntiDebugSensor::CheckDebugRegisters_Internal()
{
    DebugDetectionResult result = {false, nullptr, 0};
    __try
    {
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &ctx))
        {
            if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0)
            {
                result.detected = true;
                result.description = "检测到硬件断点 (Debug Registers)";
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        result.exceptionCode = GetExceptionCode();
    }
    return result;
}

AdvancedAntiDebugSensor::DebugDetectionResult AdvancedAntiDebugSensor::CheckKernelDebuggerNtQuery_Internal()
{
    DebugDetectionResult result = {false, nullptr, 0};
    __try
    {
        SYSTEM_KERNEL_DEBUGGER_INFORMATION info;
        if (SystemUtils::g_pNtQuerySystemInformation &&
            NT_SUCCESS(SystemUtils::g_pNtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(35), &info,
                                                                sizeof(info), NULL)))
        {
            if (info.KernelDebuggerEnabled && !info.KernelDebuggerNotPresent)
            {
                result.detected = true;
                result.description = "检测到内核调试器 (NtQuerySystemInformation)";
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        result.exceptionCode = GetExceptionCode();
    }
    return result;
}

AdvancedAntiDebugSensor::DebugDetectionResult AdvancedAntiDebugSensor::CheckKernelDebuggerKUSER_Internal()
{
    DebugDetectionResult result = {false, nullptr, 0};
    __try
    {
        if (SystemUtils::IsKernelDebuggerPresent_KUserSharedData())
        {
            result.detected = true;
            result.description = "检测到内核调试器 (KUSER_SHARED_DATA)";
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        result.exceptionCode = GetExceptionCode();
    }
    return result;
}

AdvancedAntiDebugSensor::DebugDetectionResult AdvancedAntiDebugSensor::CheckProcessHeapFlags_Internal()
{
    DebugDetectionResult result = {false, nullptr, 0};
    __try
    {
        HANDLE hHeap = GetProcessHeap();
        if (hHeap)
        {
#ifdef _WIN64
            DWORD forceFlags = *(DWORD *)((BYTE *)hHeap + 0x74);
#else
            DWORD forceFlags = *(DWORD *)((BYTE *)hHeap + 0x44);
#endif
            if (forceFlags != 0)
            {
                result.detected = true;
                result.description = "Heap ForceFlags != 0";
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        result.exceptionCode = GetExceptionCode();
    }
    return result;
}

AdvancedAntiDebugSensor::DebugDetectionResult AdvancedAntiDebugSensor::CheckProcessDebugPort_Internal()
{
    DebugDetectionResult result = {false, nullptr, 0};
    __try
    {
        if (SystemUtils::g_pNtQueryInformationProcess)
        {
            DWORD_PTR debugPort = 0;
            if (NT_SUCCESS(SystemUtils::g_pNtQueryInformationProcess(
                    GetCurrentProcess(), InternalProcessDebugPort, &debugPort, sizeof(debugPort), NULL)))
            {
                if (debugPort != 0)
                {
                    result.detected = true;
                    result.description = "ProcessDebugPort != 0";
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        result.exceptionCode = GetExceptionCode();
    }
    return result;
}

AdvancedAntiDebugSensor::DebugDetectionResult AdvancedAntiDebugSensor::CheckProcessDebugFlags_Internal()
{
    DebugDetectionResult result = {false, nullptr, 0};
    __try
    {
        if (SystemUtils::g_pNtQueryInformationProcess)
        {
            DWORD debugFlags = 0;
            if (NT_SUCCESS(SystemUtils::g_pNtQueryInformationProcess(
                    GetCurrentProcess(), InternalProcessDebugFlags, &debugFlags, sizeof(debugFlags), NULL)))
            {
                if (debugFlags == 0)
                {
                    result.detected = true;
                    result.description = "ProcessDebugFlags == 0";
                }
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        result.exceptionCode = GetExceptionCode();
    }
    return result;
}

void AdvancedAntiDebugSensor::CheckRemoteDebugger(ScanContext &context)
{
    auto result = CheckRemoteDebugger_Internal();
    if (result.detected)
    {
        context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, result.description);
    }
    else if (result.exceptionCode != 0)
    {
        LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "RemoteDebugger检测异常: 0x%08X", result.exceptionCode);
    }
}

void AdvancedAntiDebugSensor::CheckPEBBeingDebugged(ScanContext &context)
{
    auto result = CheckPEBBeingDebugged_Internal();
    if (result.detected)
    {
        context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, result.description);
    }
    else if (result.exceptionCode != 0)
    {
        LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "PEB检测异常: 0x%08X", result.exceptionCode);
    }
}

void AdvancedAntiDebugSensor::CheckCloseHandleDebugger(ScanContext &context)
{
    auto result = CheckCloseHandleDebugger_Internal();
    if (result.exceptionCode != 0)
    {
        LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "CloseHandle检测异常: 0x%08X", result.exceptionCode);
    }
}

void AdvancedAntiDebugSensor::CheckDebugRegisters(ScanContext &context)
{
    auto result = CheckDebugRegisters_Internal();
    if (result.detected)
    {
        context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, result.description);
    }
    else if (result.exceptionCode != 0)
    {
        LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "调试寄存器检测异常: 0x%08X", result.exceptionCode);
    }
}

void AdvancedAntiDebugSensor::CheckProcessHeapFlags(ScanContext &context)
{
    auto result = CheckProcessHeapFlags_Internal();
    if (result.detected)
    {
        context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, result.description);
    }
    else if (result.exceptionCode != 0)
    {
        LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "HeapFlags检测异常: 0x%08X", result.exceptionCode);
    }
}

void AdvancedAntiDebugSensor::CheckProcessDebugPort(ScanContext &context)
{
    auto result = CheckProcessDebugPort_Internal();
    if (result.detected)
    {
        context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, result.description);
    }
    else if (result.exceptionCode != 0)
    {
        LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "DebugPort检测异常: 0x%08X", result.exceptionCode);
    }
}

void AdvancedAntiDebugSensor::CheckProcessDebugFlags(ScanContext &context)
{
    auto result = CheckProcessDebugFlags_Internal();
    if (result.detected)
    {
        context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, result.description);
    }
    else if (result.exceptionCode != 0)
    {
        LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "DebugFlags检测异常: 0x%08X", result.exceptionCode);
    }
}

void AdvancedAntiDebugSensor::CheckKernelDebuggerNtQuery(ScanContext &context)
{
    auto result = CheckKernelDebuggerNtQuery_Internal();
    if (result.detected)
    {
        context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, result.description);
    }
    else if (result.exceptionCode != 0)
    {
        LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "内核调试器检测异常: 0x%08X", result.exceptionCode);
    }
}

SensorExecutionResult AdvancedAntiDebugSensor::CheckKernelDebuggerKUSER(ScanContext &context)
{
    auto result = CheckKernelDebuggerKUSER_Internal();
    if (result.detected)
    {
        context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, result.description);
    }
    else if (result.exceptionCode != 0)
    {
        LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "KUSER调试器检测异常: 0x%08X", result.exceptionCode);
    }

    return SensorExecutionResult::SUCCESS;
}
