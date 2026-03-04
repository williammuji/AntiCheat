#include <gtest/gtest.h>

#include "sensors/ModuleIntegritySensor.h"
#include "CheatMonitorEngine.h"
#include "CheatConfigManager.h"

class ModuleIntegritySensorTestAccess
{
public:
    static bool IsWritableProtection(DWORD protect)
    {
        return ModuleIntegritySensor::IsWritableCodeProtection(protect);
    }
    static bool ShouldLearn(bool trusted)
    {
        return ModuleIntegritySensor::ShouldLearnTrustedBaseline(trusted);
    }
    static bool ShouldEmitTamper(bool isSelf, bool isWhitelisted)
    {
        return ModuleIntegritySensor::ShouldEmitTamperEvidence(isSelf, isWhitelisted);
    }
};

TEST(SensorModuleIntegrityTest, WritableProtectionClassification)
{
    EXPECT_TRUE(ModuleIntegritySensorTestAccess::IsWritableProtection(PAGE_READWRITE));
    EXPECT_TRUE(ModuleIntegritySensorTestAccess::IsWritableProtection(PAGE_EXECUTE_READWRITE));
    EXPECT_FALSE(ModuleIntegritySensorTestAccess::IsWritableProtection(PAGE_EXECUTE_READ));
    EXPECT_FALSE(ModuleIntegritySensorTestAccess::IsWritableProtection(PAGE_READONLY));
}

TEST(SensorModuleIntegrityTest, BaselineAndTamperDecisionHelpers)
{
    EXPECT_TRUE(ModuleIntegritySensorTestAccess::ShouldLearn(true));
    EXPECT_FALSE(ModuleIntegritySensorTestAccess::ShouldLearn(false));

    EXPECT_TRUE(ModuleIntegritySensorTestAccess::ShouldEmitTamper(true, true));
    EXPECT_TRUE(ModuleIntegritySensorTestAccess::ShouldEmitTamper(false, false));
    EXPECT_FALSE(ModuleIntegritySensorTestAccess::ShouldEmitTamper(false, true));
}

TEST(SensorModuleIntegrityTest, ExecuteHonorsTimeoutThreshold)
{
    CheatMonitorEngine engine;
    engine.InitializeSystem();
    SensorRuntimeContext context(&engine);

    context.IsModuleCacheValid = true;
    for (int i = 0; i < 50000; ++i) {
        context.CachedModules.push_back((HMODULE)(uintptr_t)(0x10000 + i * 0x1000));
    }

    CheatConfigManager::GetInstance().UpdateHeavyScanBudgetMs(1);

    ModuleIntegritySensor sensor;
    auto result = sensor.Execute(context);

    EXPECT_TRUE(result == SensorExecutionResult::TIMEOUT || result == SensorExecutionResult::FAILURE);
}
