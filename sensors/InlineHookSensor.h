#pragma once

#include <windows.h>
#include "ISensor.h"

class InlineHookSensor : public ISensor
{
public:
    const char *GetName() const override { return "InlineHookSensor"; }
    SensorWeight GetWeight() const override { return SensorWeight::HEAVY; } // 导出表遍历+反汇编
    SensorExecutionResult Execute(ScanContext &context) override;

private:
   bool IsModuleInUnifiedWhitelist(const std::wstring &modulePath, ScanContext &context) const;
   bool IsAddressWhitelisted(PVOID address, ScanContext &context) const;
   void CheckModuleExports(HMODULE hMod, ScanContext& context);
   void CheckFunction(BYTE* pFunc, const char* funcName, ScanContext& context);
   void CheckHotpatchPreamble(BYTE* pPreamble, const char* funcName, ScanContext& context);
};
