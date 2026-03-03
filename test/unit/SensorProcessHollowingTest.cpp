#include <gtest/gtest.h>
#include "sensors/ProcessHollowingSensor.h"
#include "SensorRuntimeContext.h"
#include "CheatMonitorEngine.h"

TEST(SensorProcessHollowingTest, ExecuteRunsWithoutCrashingProcessHollowing)
{
    CheatMonitorEngine engine;
    engine.InitializeSystem();
    SensorRuntimeContext context(&engine);
    ProcessHollowingSensor sensor;

    auto result = sensor.Execute(context);
    EXPECT_TRUE(result == SensorExecutionResult::SUCCESS || result == SensorExecutionResult::FAILURE);
}
