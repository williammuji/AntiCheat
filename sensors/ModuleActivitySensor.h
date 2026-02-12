#pragma once

#include "../ISensor.h"
#include "../utils/Utils.h"

#include <chrono>

class ModuleActivitySensor : public ISensor
{
public:
    const char *GetName() const override { return "ModuleActivitySensor"; }
    SensorWeight GetWeight() const override { return SensorWeight::HEAVY; } // 10-100ms: 模块活动监控
    SensorExecutionResult Execute(SensorRuntimeContext &context) override;

private:
   friend class ModuleActivitySensorTestAccess;

   static bool ShouldReportUnknownModule(bool isWhitelisted, const Utils::ModuleValidationResult &validation);

   bool ScanModulesWithTimeout(SensorRuntimeContext &context, int budget_ms, const std::chrono::steady_clock::time_point &startTime);
};
