#include <gtest/gtest.h>

#include "sensors/ThreadActivitySensor.h"
#include "CheatMonitorEngine.h"
#include "utils/SystemUtils.h"

class ThreadActivitySensorTestAccess
{
public:
    static bool IsIgnorable(NTSTATUS status)
    {
        return ThreadActivitySensor::IsIgnorableNtStatus(status);
    }

    static bool HasBreakpoints(const CONTEXT &ctx)
    {
        return ThreadActivitySensor::HasHardwareBreakpoints(ctx);
    }
    static void AnalyzeIntegrity(ThreadActivitySensor &sensor, SensorRuntimeContext &context, DWORD tid)
    {
        sensor.AnalyzeThreadIntegrity(context, tid);
    }
};

namespace
{
NTSTATUS WINAPI MockThreadQueryFailure(
    HANDLE,
    THREADINFOCLASS threadInfoClass,
    PVOID,
    ULONG,
    PULONG)
{
    if (threadInfoClass == (THREADINFOCLASS)9 || threadInfoClass == (THREADINFOCLASS)17)
    {
        return (NTSTATUS)0xC0000005; // non-ignorable
    }
    return 0;
}
} // namespace

TEST(SensorThreadActivityTest, RecognizesIgnorableNtStatuses)
{
    EXPECT_TRUE(ThreadActivitySensorTestAccess::IsIgnorable(0xC000000D));
    EXPECT_TRUE(ThreadActivitySensorTestAccess::IsIgnorable(0xC0000022));
    EXPECT_TRUE(ThreadActivitySensorTestAccess::IsIgnorable(0xC0000003));
    EXPECT_TRUE(ThreadActivitySensorTestAccess::IsIgnorable(0xC0000002));
    EXPECT_TRUE(ThreadActivitySensorTestAccess::IsIgnorable(0xC0000004));
    EXPECT_FALSE(ThreadActivitySensorTestAccess::IsIgnorable(0));
    EXPECT_FALSE(ThreadActivitySensorTestAccess::IsIgnorable(0xC0000001));
}

TEST(SensorThreadActivityTest, DetectsHardwareBreakpointsFromContext)
{
    CONTEXT ctx = {};
    EXPECT_FALSE(ThreadActivitySensorTestAccess::HasBreakpoints(ctx));

    ctx.Dr2 = 0x1234;
    EXPECT_TRUE(ThreadActivitySensorTestAccess::HasBreakpoints(ctx));
}

TEST(SensorThreadActivityTest, AnalyzeIntegritySetsFailureOnNonIgnorableQueryError)
{
    CheatMonitorEngine engine;
    SensorRuntimeContext context(&engine);
    ThreadActivitySensor sensor;

    SystemUtils::NtApiBindings bindings = {};
    bindings.queryInformationThread = &MockThreadQueryFailure;
    SystemUtils::SetNtApiBindingsForTesting(bindings);

    ThreadActivitySensorTestAccess::AnalyzeIntegrity(sensor, context, GetCurrentThreadId());
    EXPECT_EQ(sensor.GetLastFailureReason(), anti_cheat::THREAD_MODULE_QUERY_THREAD_FAILED);

    SystemUtils::ResetNtApiBindingsForTesting();
}
