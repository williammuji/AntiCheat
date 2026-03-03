#include <gtest/gtest.h>
#include "sensors/DriverIntegritySensor.h"
#include "SensorRuntimeContext.h"
#include "CheatMonitorEngine.h"

TEST(SensorDriverIntegrityTest, ExecuteRunsWithoutCrashing)
{
    CheatMonitorEngine engine;
    SensorRuntimeContext context(&engine);
    DriverIntegritySensor sensor;

    auto result = sensor.Execute(context);
    // Execute will either succeed or fail (e.g., if OS version is unsupported or EnumDeviceDrivers fails)
    EXPECT_TRUE(result == SensorExecutionResult::SUCCESS || result == SensorExecutionResult::FAILURE);
}
