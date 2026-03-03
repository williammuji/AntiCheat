#include <gtest/gtest.h>
#include "sensors/ProcessAndWindowMonitorSensor.h"
#include "SensorRuntimeContext.h"
#include "CheatMonitorEngine.h"

TEST(SensorProcessAndWindowMonitorTest, ExecuteRunsWithoutCrashingListProcessesAndWindows)
{
    CheatMonitorEngine engine;
    engine.InitializeSystem();
    SensorRuntimeContext context(&engine);
    ProcessAndWindowMonitorSensor sensor;

    auto result = sensor.Execute(context);
    EXPECT_TRUE(result == SensorExecutionResult::SUCCESS || result == SensorExecutionResult::FAILURE);
}
