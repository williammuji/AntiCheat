#pragma once

#include <windows.h>
#include "../ISensor.h"

#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <chrono>

class ProcessHandleSensor : public ISensor
{
public:
    const char *GetName() const override { return "ProcessHandleSensor"; }
    SensorWeight GetWeight() const override { return SensorWeight::CRITICAL; } // 1000-10000ms: 杩涚▼鍙ユ焺鎵弿
    SensorExecutionResult Execute(SensorRuntimeContext &context) override;

private:
   friend class ProcessHandleSensorTestAccess;
   static bool HasSuspiciousProcessAccessMask(ULONG grantedAccess);
   static bool IsSevereHandleOverflow(ULONG_PTR totalHandles, ULONG maxHandlesToScan);
   static bool ShouldAbortDueToRetryCount(int retries);

   // 棰勫垎閰嶇紦鍐插尯绠＄悊锛圕椋庢牸锛屽吋瀹筍EH锛?
   struct HandleBufferManager
   {
       BYTE *buffer;
       size_t size;

       HandleBufferManager();
       ~HandleBufferManager();
       bool Resize(size_t newSize);
       void Reset();
   };

   // 鑾峰彇杩涚▼鍒涘缓鏃堕棿鏍囪瘑锛堢敤浜庣紦瀛橀獙璇侊級
   static uint32_t GetProcessCreationTime(DWORD pid);
   bool IsHandlePointingToUs_Safe(const void *pHandleEntry, DWORD ownPid);
};
