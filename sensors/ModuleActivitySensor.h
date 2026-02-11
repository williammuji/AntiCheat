#pragma once

#include "ISensor.h"
#include <chrono>

class ModuleActivitySensor : public ISensor
{
public:
    const char *GetName() const override { return "ModuleActivitySensor"; }
    SensorWeight GetWeight() const override { return SensorWeight::HEAVY; } // 10-100ms: 模块活动监控
    SensorExecutionResult Execute(ScanContext &context) override;

private:
   bool ScanModulesWithTimeout(ScanContext &context, int budget_ms, const std::chrono::steady_clock::time_point &startTime);
};
