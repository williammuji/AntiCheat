#pragma once

#include "ISensor.h"
#include <chrono>

class ModuleActivitySensor : public ISensor
{
public:
    const char *GetName() const override { return "ModuleActivitySensor"; }
    SensorWeight GetWeight() const override { return SensorWeight::HEAVY; } // 10-100ms: 模块活动监控
    SensorExecutionResult Execute(SensorRuntimeContext &context) override;

private:
   bool ScanModulesWithTimeout(SensorRuntimeContext &context, int budget_ms, const std::chrono::steady_clock::time_point &startTime);
};
