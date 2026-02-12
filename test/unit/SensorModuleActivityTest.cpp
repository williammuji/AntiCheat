#include <gtest/gtest.h>

#include "sensors/ModuleActivitySensor.h"
#include "CheatMonitorEngine.h"

class ModuleActivitySensorTestAccess
{
public:
    static bool ShouldReport(bool isWhitelisted, const Utils::ModuleValidationResult &validation)
    {
        return ModuleActivitySensor::ShouldReportUnknownModule(isWhitelisted, validation);
    }

    static bool ScanWithTimeout(
        ModuleActivitySensor &sensor,
        SensorRuntimeContext &context,
        int budgetMs,
        const std::chrono::steady_clock::time_point &start)
    {
        return sensor.ScanModulesWithTimeout(context, budgetMs, start);
    }
};

TEST(SensorModuleActivityTest, UnknownModuleDecisionDependsOnWhitelistAndTrust)
{
    Utils::ModuleValidationResult trusted = {};
    trusted.isTrusted = true;
    Utils::ModuleValidationResult untrusted = {};
    untrusted.isTrusted = false;

    EXPECT_FALSE(ModuleActivitySensorTestAccess::ShouldReport(true, untrusted));
    EXPECT_FALSE(ModuleActivitySensorTestAccess::ShouldReport(false, trusted));
    EXPECT_TRUE(ModuleActivitySensorTestAccess::ShouldReport(false, untrusted));
}

TEST(SensorModuleActivityTest, EmptyCachePathFailsFast)
{
    CheatMonitorEngine engine;
    SensorRuntimeContext context(&engine);
    context.CachedModules.clear();

    ModuleActivitySensor sensor;
    const bool ok = ModuleActivitySensorTestAccess::ScanWithTimeout(
        sensor, context, 1, std::chrono::steady_clock::now());

    EXPECT_FALSE(ok);
    EXPECT_NE(sensor.GetLastFailureReason(), anti_cheat::UNKNOWN_FAILURE);
}

TEST(SensorModuleActivityTest, TimeoutBranchTriggersFailure)
{
    CheatMonitorEngine engine;
    SensorRuntimeContext context(&engine);
    context.CachedModules.push_back(GetModuleHandleW(nullptr));

    ModuleActivitySensor sensor;
    const auto oldStart = std::chrono::steady_clock::now() - std::chrono::seconds(10);
    const bool ok = ModuleActivitySensorTestAccess::ScanWithTimeout(sensor, context, 0, oldStart);

    EXPECT_FALSE(ok);
    EXPECT_EQ(sensor.GetLastFailureReason(), anti_cheat::MODULE_SCAN_TIMEOUT);
}

TEST(SensorModuleActivityTest, TrustedModuleGetsInsertedIntoKnownSet)
{
    CheatMonitorEngine engine;
    SensorRuntimeContext context(&engine);
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    ASSERT_NE(kernel32, nullptr);
    context.CachedModules.push_back(kernel32);

    ModuleActivitySensor sensor;
    const bool ok = ModuleActivitySensorTestAccess::ScanWithTimeout(
        sensor, context, 1000, std::chrono::steady_clock::now());

    EXPECT_TRUE(ok);
    EXPECT_TRUE(context.IsModuleKnown(kernel32));
}
