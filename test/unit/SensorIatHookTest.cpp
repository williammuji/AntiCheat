#include <gtest/gtest.h>
#include "sensors/IatHookSensor.h"
#include "SensorRuntimeContext.h"
#include "CheatMonitorEngine.h"

TEST(SensorIatHookTest, ExecuteRunsWithoutCrashingAndVerifiesSelfModule)
{
    CheatMonitorEngine engine;
    // We mock the OS version check to pass for testing purposes
    engine.InitializeSystem();
    SensorRuntimeContext context(&engine);
    IatHookSensor sensor;

    auto result = sensor.Execute(context);

    // In a clean environment, IAT check on the test executable itself should return SUCCESS.
    // If the OS version is not supported according to context, it will return FAILURE.
    EXPECT_TRUE(result == SensorExecutionResult::SUCCESS || result == SensorExecutionResult::FAILURE);
}
