#pragma once

#include "ISensor.h"

class ProcessHollowingSensor : public ISensor
{
public:
    const char *GetName() const override { return "ProcessHollowingSensor"; }
    SensorWeight GetWeight() const override { return SensorWeight::HEAVY; } // 涉及文件I/O
    SensorExecutionResult Execute(SensorRuntimeContext &context) override;
};
