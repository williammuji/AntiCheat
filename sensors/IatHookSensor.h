#pragma once

#include "../include/ISensor.h"

class IatHookSensor : public ISensor
{
public:
    const char *GetName() const override { return "IatHookSensor"; }
    SensorWeight GetWeight() const override { return SensorWeight::LIGHT; } // < 1ms: IAT Hook检测
    SensorExecutionResult Execute(ScanContext &context) override;

private:
    bool PerformIatIntegrityCheck(ScanContext &context, HMODULE hSelf);
    bool ValidatePeStructure(const BYTE *baseAddress, ScanContext &context);
    bool CheckImportTableIntegrity(ScanContext &context, const BYTE *baseAddress);
    void CheckIatHooks(ScanContext &context, const BYTE *baseAddress, const IMAGE_IMPORT_DESCRIPTOR *pImportDesc);
};
