#include <gtest/gtest.h>

#include "sensors/ModuleIntegritySensor.h"

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
