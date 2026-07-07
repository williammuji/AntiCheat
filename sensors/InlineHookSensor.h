#pragma once

#include <windows.h>
#include <string>
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
   static bool IsRvaInExecutableSection(HMODULE hMod, PIMAGE_NT_HEADERS pNt, DWORD rva);
   static bool IsCommittedExecutableMemory(PVOID address);
   SensorExecutionResult CheckModuleExports(HMODULE hMod, const std::string &moduleName, SensorRuntimeContext& context,
                                            std::chrono::steady_clock::time_point startTime, int budgetMs,
                                            bool targetedScan);
   void CheckFunction(BYTE* pFunc, const char* funcName, const std::string &moduleName, SensorRuntimeContext& context);
   void CheckHotpatchPreamble(BYTE* pPreamble, const char* funcName, const std::string &moduleName,
                              SensorRuntimeContext& context);
};
