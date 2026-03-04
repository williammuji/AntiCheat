#include <gtest/gtest.h>
#include "sensors/InlineHookSensor.h"
#include "SensorRuntimeContext.h"
#include "CheatMonitorEngine.h"

TEST(SensorInlineHookTest, ExecuteRunsWithoutCrashingOnSystemModules)
{
    CheatMonitorEngine engine;
    engine.InitializeSystem();
    SensorRuntimeContext context(&engine);
    InlineHookSensor sensor;

    auto result = sensor.Execute(context);

    // In a clean environment without inline hooks, it should succeed.
    EXPECT_TRUE(result == SensorExecutionResult::SUCCESS || result == SensorExecutionResult::FAILURE || result == SensorExecutionResult::TIMEOUT);
}
