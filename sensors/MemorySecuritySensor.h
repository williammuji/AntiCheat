#pragma once

#include <windows.h>
#include "../ISensor.h"

#include <chrono>
#include <string>

class MemorySecuritySensor : public ISensor
{
public:
    const char *GetName() const override { return "MemorySecuritySensor"; }
    SensorWeight GetWeight() const override { return SensorWeight::HEAVY; } // 10-100ms: 内存安全检测
    SensorExecutionResult Execute(SensorRuntimeContext &context) override;

private:
    friend class MemorySecuritySensorTestAccess;
    static bool IsRwXProtection(DWORD protect);
    static bool IsRxOnlyProtection(DWORD protect);
    static bool ShouldSkipLowAddressSmallRwx(uintptr_t baseAddr, SIZE_T regionSize);

    struct HiddenMemoryCheckResult
    {
        bool shouldReport = false;
        bool accessible = false;
    };

    void DetectHiddenModule(SensorRuntimeContext &context, const MEMORY_BASIC_INFORMATION &mbi);
    void DetectMappedExecutableMemory(SensorRuntimeContext &context, const MEMORY_BASIC_INFORMATION &mbi);
    void DetectPrivateExecutableMemory(SensorRuntimeContext &context, const MEMORY_BASIC_INFORMATION &mbi);
    bool IsRegionInUnifiedWhitelist(PVOID baseAddress, SensorRuntimeContext &context) const;
    bool HasSecondaryConfirmation(SensorRuntimeContext &context, const MEMORY_BASIC_INFORMATION &mbi) const;
    bool HasThreadStartInRegion(const MEMORY_BASIC_INFORMATION &mbi) const;
    static bool IsKnownSafeRegion(uintptr_t baseAddr, SIZE_T regionSize);
    HiddenMemoryCheckResult CheckHiddenMemoryRegion(PVOID baseAddress, SIZE_T regionSize);
};
