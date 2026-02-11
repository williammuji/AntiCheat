#pragma once

#include <windows.h>
#include "ISensor.h"
#include <chrono>

class MemorySecuritySensor : public ISensor
{
public:
    const char *GetName() const override { return "MemorySecuritySensor"; }
    SensorWeight GetWeight() const override { return SensorWeight::HEAVY; } // 10-100ms: 内存安全检测
    SensorExecutionResult Execute(ScanContext &context) override;

private:
    struct HiddenMemoryCheckResult
    {
        bool shouldReport = false;
        bool accessible = false;
    };

    void DetectHiddenModule(ScanContext &context, const MEMORY_BASIC_INFORMATION &mbi);
    void DetectMappedExecutableMemory(ScanContext &context, const MEMORY_BASIC_INFORMATION &mbi);
    void DetectPrivateExecutableMemory(ScanContext &context, const MEMORY_BASIC_INFORMATION &mbi);
    static bool IsKnownSafeRegion(uintptr_t baseAddr, SIZE_T regionSize);
    HiddenMemoryCheckResult CheckHiddenMemoryRegion(PVOID baseAddress, SIZE_T regionSize);
};
