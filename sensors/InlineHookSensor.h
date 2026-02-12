#pragma once

#include <windows.h>
#include "ISensor.h"

class InlineHookSensor : public ISensor
{
public:
    const char *GetName() const override { return "InlineHookSensor"; }
    SensorWeight GetWeight() const override { return SensorWeight::HEAVY; } // 导出表遍历+反汇编
    SensorExecutionResult Execute(SensorRuntimeContext &context) override;

private:
   bool IsModuleInUnifiedWhitelist(const std::wstring &modulePath, SensorRuntimeContext &context) const;
   bool IsAddressWhitelisted(PVOID address, SensorRuntimeContext &context) const;
   void CheckModuleExports(HMODULE hMod, SensorRuntimeContext& context);
   void CheckFunction(BYTE* pFunc, const char* funcName, SensorRuntimeContext& context);
   void CheckHotpatchPreamble(BYTE* pPreamble, const char* funcName, SensorRuntimeContext& context);
};
