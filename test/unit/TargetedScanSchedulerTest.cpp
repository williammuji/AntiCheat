#include <gtest/gtest.h>

#include "CheatMonitorEngine.h"

namespace
{
class FakeSensor : public ISensor
{
   public:
    FakeSensor(const char *name, SensorWeight weight, bool emitEvidence)
        : m_name(name), m_weight(weight), m_emitEvidence(emitEvidence)
    {
    }

    const char *GetName() const override { return m_name.c_str(); }
    SensorWeight GetWeight() const override { return m_weight; }

    SensorExecutionResult Execute(SensorRuntimeContext &context) override
    {
        ++executeCount;
        if (m_emitEvidence) context.AddEvidence(anti_cheat::RUNTIME_ERROR, "target evidence: " + m_name);
        return SensorExecutionResult::SUCCESS;
    }

    int executeCount = 0;

   private:
    std::string m_name;
    SensorWeight m_weight;
    bool m_emitEvidence = false;
};
}

TEST(TargetedScanSchedulerTest, LegacyCommandFieldsCoalesceIntoSingleFullScanRequest)
{
    CheatMonitorEngine engine;

    engine.SubmitTargetedScanRequest("legacy-request-1", "ProcessHandleSensor");
    engine.SubmitTargetedScanRequest("legacy-request-1", "ModuleIntegritySensor");

    EXPECT_TRUE(engine.TryConsumeTargetedScanRequest());
    EXPECT_FALSE(engine.TryConsumeTargetedScanRequest());
}

TEST(TargetedScanSchedulerTest, TargetedScanRunsOnlyProductionSensorSet)
{
    CheatMonitorEngine engine;
    engine.m_isSessionActive = true;

    auto addSensor = [&](const char *name, SensorWeight weight) -> FakeSensor * {
        std::unique_ptr<FakeSensor> sensor(new FakeSensor(name, weight, true));
        FakeSensor *raw = sensor.get();
        if (weight == SensorWeight::LIGHT)
            engine.m_lightweightSensors.push_back(std::move(sensor));
        else
            engine.m_heavyweightSensors.push_back(std::move(sensor));
        return raw;
    };

    FakeSensor *advancedAntiDebug = addSensor("AdvancedAntiDebugSensor", SensorWeight::LIGHT);
    FakeSensor *systemCodeIntegrity = addSensor("SystemCodeIntegritySensor", SensorWeight::LIGHT);
    FakeSensor *iatHook = addSensor("IatHookSensor", SensorWeight::LIGHT);
    FakeSensor *vehHook = addSensor("VehHookSensor", SensorWeight::LIGHT);
    FakeSensor *vtableHook = addSensor("VTableHookSensor", SensorWeight::LIGHT);

    FakeSensor *threadActivity = addSensor("ThreadActivitySensor", SensorWeight::HEAVY);
    FakeSensor *moduleActivity = addSensor("ModuleActivitySensor", SensorWeight::HEAVY);
    FakeSensor *memorySecurity = addSensor("MemorySecuritySensor", SensorWeight::HEAVY);
    FakeSensor *driverIntegrity = addSensor("DriverIntegritySensor", SensorWeight::HEAVY);
    FakeSensor *inlineHook = addSensor("InlineHookSensor", SensorWeight::HEAVY);
    FakeSensor *processHollowing = addSensor("ProcessHollowingSensor", SensorWeight::HEAVY);
    FakeSensor *processHandle = addSensor("ProcessHandleSensor", SensorWeight::HEAVY);
    FakeSensor *moduleIntegrity = addSensor("ModuleIntegritySensor", SensorWeight::HEAVY);
    FakeSensor *processAndWindow = addSensor("ProcessAndWindowMonitorSensor", SensorWeight::HEAVY);

    engine.RunTargetedSensorScan();

    EXPECT_EQ(0, advancedAntiDebug->executeCount);
    EXPECT_EQ(1, systemCodeIntegrity->executeCount);
    EXPECT_EQ(0, iatHook->executeCount);
    EXPECT_EQ(1, vehHook->executeCount);
    EXPECT_EQ(1, vtableHook->executeCount);
    EXPECT_EQ(1, threadActivity->executeCount);
    EXPECT_EQ(1, moduleActivity->executeCount);
    EXPECT_EQ(1, memorySecurity->executeCount);
    EXPECT_EQ(1, driverIntegrity->executeCount);
    EXPECT_EQ(1, inlineHook->executeCount);
    EXPECT_EQ(0, processHollowing->executeCount);
    EXPECT_EQ(1, processHandle->executeCount);
    EXPECT_EQ(1, moduleIntegrity->executeCount);
    EXPECT_EQ(0, processAndWindow->executeCount);
}

TEST(TargetedScanSchedulerTest, SensorWithoutEvidenceDoesNotProduceTargetedReport)
{
    CheatMonitorEngine engine;
    engine.m_isSessionActive = true;
    FakeSensor cleanSensor("ProcessHandleSensor", SensorWeight::HEAVY, false);

    EXPECT_FALSE(engine.RunTargetedSensorScanForSensor(&cleanSensor));
    EXPECT_EQ(1, cleanSensor.executeCount);
}
