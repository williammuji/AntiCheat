#pragma once

#include <windows.h>
#include "../ISensor.h"


class InlineHookSensor : public ISensor
{
public:
    const char *GetName() const override { return "InlineHookSensor"; }
    SensorWeight GetWeight() const override { return SensorWeight::HEAVY; } // 导出表遍历+反汇编
    virtual SensorExecutionResult Execute(SensorRuntimeContext &context) override;

private:
   bool IsModuleInUnifiedWhitelist(const std::wstring &modulePath, SensorRuntimeContext &context) const;
   bool IsAddressWhitelisted(PVOID address, SensorRuntimeContext &context) const;
   SensorExecutionResult CheckModuleExports(HMODULE hMod, SensorRuntimeContext& context,
                                            std::chrono::steady_clock::time_point startTime, int budgetMs);
   void CheckFunction(BYTE* pFunc, const char* funcName, SensorRuntimeContext& context);
   void CheckHotpatchPreamble(BYTE* pPreamble, const char* funcName, SensorRuntimeContext& context);
};
