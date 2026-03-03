#include <gtest/gtest.h>
#include "sensors/VTableHookSensor.h"
#include "SensorRuntimeContext.h"
#include "CheatMonitorEngine.h"

TEST(SensorVTableHookTest, ExecuteRunsWithoutCrashingVTableHook)
{
    CheatMonitorEngine engine;
    engine.InitializeSystem();
    SensorRuntimeContext context(&engine);
    VTableHookSensor sensor;

    auto result = sensor.Execute(context);
    EXPECT_TRUE(result == SensorExecutionResult::SUCCESS || result == SensorExecutionResult::FAILURE);
}
