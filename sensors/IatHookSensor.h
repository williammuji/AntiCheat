#pragma once

#include <windows.h>
#include "ISensor.h"

class IatHookSensor : public ISensor
{
public:
    const char *GetName() const override { return "IatHookSensor"; }
    SensorWeight GetWeight() const override { return SensorWeight::LIGHT; } // < 1ms: IAT Hook检测
    SensorExecutionResult Execute(SensorRuntimeContext &context) override;

private:
    bool PerformIatIntegrityCheck(SensorRuntimeContext &context, HMODULE hSelf);
    bool ValidatePeStructure(const BYTE *baseAddress, SensorRuntimeContext &context);
    bool CheckImportTableIntegrity(SensorRuntimeContext &context, const BYTE *baseAddress);
    void CheckIatHooks(SensorRuntimeContext &context, const BYTE *baseAddress, const IMAGE_IMPORT_DESCRIPTOR *pImportDesc);
};
