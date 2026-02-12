#pragma once

#include <windows.h>
#include "../ISensor.h"

#include "utils/SystemUtils.h"

class VehHookSensor : public ISensor
{
public:
    const char *GetName() const override { return "VehHookSensor"; }
    SensorWeight GetWeight() const override { return SensorWeight::LIGHT; } // 0-10ms: VEH妫€娴?
    SensorExecutionResult Execute(SensorRuntimeContext &context) override;

private:
    friend class VehHookSensorTestAccess;
    static bool IsExecutableProtection(DWORD prot);
    static std::wstring ExtractLowerModuleFileName(const std::wstring &modulePath);

    struct VehTraverseResult
    {
        bool success;
        PVOID handlers[2048];
        int handlerCount;
        DWORD exceptionCode;
    };

    struct VehAccessResult
    {
        bool success = false;
        LIST_ENTRY *pHead = nullptr;
        DWORD exceptionCode = 0;
    };

    static VehAccessResult AccessVehStructSafe(uintptr_t base, SystemUtils::WindowsVersion winVer);
    static VehTraverseResult TraverseVehListSafe(LIST_ENTRY *pHead, int budget_ms);
    void AnalyzeHandlerSecurity(SensorRuntimeContext &context, PVOID handlerAddress, int index);
};
