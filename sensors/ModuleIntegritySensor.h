#pragma once

#include <windows.h>
#include "../ISensor.h"

#include <vector>
#include <unordered_map>
#include <unordered_set>

class ModuleIntegritySensor : public ISensor
{
public:
    const char *GetName() const override { return "ModuleIntegritySensor"; }
    SensorWeight GetWeight() const override { return SensorWeight::CRITICAL; } // ~1000ms: 模块代码完整性检测（分段扫描）
    SensorExecutionResult Execute(SensorRuntimeContext &context) override;

private:
   friend class ModuleIntegritySensorTestAccess;

   struct CachedModuleInfo
   {
       std::wstring modulePath;
       PVOID codeBase;
       DWORD codeSize;
       bool valid;
       bool isSpecial; // 缓存特殊模块标记
   };
   std::unordered_map<HMODULE, CachedModuleInfo> m_moduleCache;

   void ProcessModuleCodeIntegrity(HMODULE hModule, const CachedModuleInfo &info, SensorRuntimeContext &context,
                                   const std::unordered_map<std::wstring, std::vector<uint8_t>> &baselineHashes,
                                   size_t maxCodeSectionSize);
   void ValidateModuleCodeIntegrity(const wchar_t *modulePath_w, HMODULE hModule, PVOID codeBase, DWORD codeSize,
                                    SensorRuntimeContext &context,
                                    const std::unordered_map<std::wstring, std::vector<uint8_t>> &baselineHashes);
   static bool IsWritableCodeProtection(DWORD protect);
   static bool ShouldLearnTrustedBaseline(bool validationTrusted);
   static bool ShouldEmitTamperEvidence(bool isSelfModule, bool isWhitelisted);
};
