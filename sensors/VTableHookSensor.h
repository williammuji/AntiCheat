#pragma once

#include <windows.h>
#include "../include/ISensor.h"
#include <vector>

class VTableHookSensor : public ISensor
{
public:
    VTableHookSensor() = default;
    virtual ~VTableHookSensor() = default;

    virtual SensorExecutionResult Execute(ScanContext &context) override;
    virtual const char* GetName() const override { return "VTableHookSensor"; }
    virtual SensorWeight GetWeight() const override { return SensorWeight::LIGHT; }

private:
    void CheckVTable(ScanContext& context, PVOID vtableBase, const char* name, int entryCount);
};
