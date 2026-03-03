#include <gtest/gtest.h>
#include "sensors/SystemCodeIntegritySensor.h"
#include "SensorRuntimeContext.h"
#include "CheatMonitorEngine.h"

TEST(SensorSystemCodeIntegrityTest, ExecuteRunsWithoutCrashingCheckCodeIntegrity)
{
    CheatMonitorEngine engine;
    engine.InitializeSystem();
    SensorRuntimeContext context(&engine);
    SystemCodeIntegritySensor sensor;

    auto result = sensor.Execute(context);
    EXPECT_TRUE(result == SensorExecutionResult::SUCCESS || result == SensorExecutionResult::FAILURE);
}
