#include <gtest/gtest.h>

#include "sensors/AdvancedAntiDebugSensor.h"
#include "utils/SystemUtils.h"

class AdvancedAntiDebugSensorTestAccess
{
public:
    static AdvancedAntiDebugSensor::DebugDetectionResult CheckProcessDebugFlags()
    {
        return AdvancedAntiDebugSensor::CheckProcessDebugFlags_Internal();
    }

    static AdvancedAntiDebugSensor::DebugDetectionResult CheckKernelNtQuery()
    {
        return AdvancedAntiDebugSensor::CheckKernelDebuggerNtQuery_Internal();
    }
};

namespace
{
NTSTATUS WINAPI MockNtQueryInformationProcess(
    HANDLE,
    PROCESS_INFO_CLASS_INTERNAL processInfoClass,
    PVOID buffer,
    ULONG,
    PULONG)
{
    if (processInfoClass == InternalProcessDebugFlags && buffer)
    {
        *reinterpret_cast<DWORD *>(buffer) = 0;
    }
    return 0;
}

NTSTATUS WINAPI MockNtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS,
    PVOID buffer,
    ULONG,
    PULONG)
{
    auto *info = reinterpret_cast<SYSTEM_KERNEL_DEBUGGER_INFORMATION *>(buffer);
    info->KernelDebuggerEnabled = TRUE;
    info->KernelDebuggerNotPresent = FALSE;
    return 0;
}

NTSTATUS WINAPI MockNtQueryInformationProcessNoDebug(
    HANDLE,
    PROCESS_INFO_CLASS_INTERNAL,
    PVOID buffer,
    ULONG,
    PULONG)
{
    if (buffer)
    {
        *reinterpret_cast<DWORD *>(buffer) = 1;
    }
    return 0;
}

NTSTATUS WINAPI MockNtQuerySystemInformationNoKernelDebugger(
    SYSTEM_INFORMATION_CLASS,
    PVOID buffer,
    ULONG,
    PULONG)
{
    auto *info = reinterpret_cast<SYSTEM_KERNEL_DEBUGGER_INFORMATION *>(buffer);
    info->KernelDebuggerEnabled = FALSE;
    info->KernelDebuggerNotPresent = TRUE;
    return 0;
}
} // namespace

TEST(SensorAdvancedAntiDebugTest, DetectsDebugFlagsSignalWithMockedNtApi)
{
    SystemUtils::NtApiBindings bindings = {};
    bindings.queryInformationProcess = &MockNtQueryInformationProcess;
    SystemUtils::SetNtApiBindingsForTesting(bindings);

    const auto result = AdvancedAntiDebugSensorTestAccess::CheckProcessDebugFlags();
    EXPECT_TRUE(result.detected);

    SystemUtils::ResetNtApiBindingsForTesting();
}

TEST(SensorAdvancedAntiDebugTest, DetectsKernelDebuggerSignalWithMockedNtApi)
{
    SystemUtils::NtApiBindings bindings = {};
    bindings.querySystemInformation = &MockNtQuerySystemInformation;
    SystemUtils::SetNtApiBindingsForTesting(bindings);

    const auto result = AdvancedAntiDebugSensorTestAccess::CheckKernelNtQuery();
    EXPECT_TRUE(result.detected);

    SystemUtils::ResetNtApiBindingsForTesting();
}

TEST(SensorAdvancedAntiDebugTest, NoDebugSignalsDoNotTriggerDetection)
{
    SystemUtils::NtApiBindings bindings = {};
    bindings.queryInformationProcess = &MockNtQueryInformationProcessNoDebug;
    bindings.querySystemInformation = &MockNtQuerySystemInformationNoKernelDebugger;
    SystemUtils::SetNtApiBindingsForTesting(bindings);

    const auto debugFlags = AdvancedAntiDebugSensorTestAccess::CheckProcessDebugFlags();
    const auto kernelDbg = AdvancedAntiDebugSensorTestAccess::CheckKernelNtQuery();

    EXPECT_FALSE(debugFlags.detected);
    EXPECT_FALSE(kernelDbg.detected);
    EXPECT_EQ(debugFlags.exceptionCode, 0u);
    EXPECT_EQ(kernelDbg.exceptionCode, 0u);

    SystemUtils::ResetNtApiBindingsForTesting();
}
