#pragma once

#include "../ISensor.h"


class SystemCodeIntegritySensor : public ISensor
{
public:
    const char *GetName() const override { return "SystemCodeIntegritySensor"; }
    SensorWeight GetWeight() const override { return SensorWeight::LIGHT; } // < 1ms: System code integrity detection
    virtual SensorExecutionResult Execute(SensorRuntimeContext &context) override;

private:
   static bool CheckKernelDebuggerPresent();
};
