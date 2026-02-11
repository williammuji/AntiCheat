#pragma once

#include "../include/ISensor.h"

class SystemCodeIntegritySensor : public ISensor
{
public:
    const char *GetName() const override { return "SystemCodeIntegritySensor"; }
    SensorWeight GetWeight() const override { return SensorWeight::LIGHT; } // < 1ms: 系统代码完整性检测
    SensorExecutionResult Execute(ScanContext &context) override;

private:
   static bool CheckKernelDebuggerPresent();
};
