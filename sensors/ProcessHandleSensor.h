#pragma once

#include "../include/ISensor.h"
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <chrono>

class ProcessHandleSensor : public ISensor
{
public:
    const char *GetName() const override { return "ProcessHandleSensor"; }
    SensorWeight GetWeight() const override { return SensorWeight::CRITICAL; } // 1000-10000ms: 进程句柄扫描
    SensorExecutionResult Execute(ScanContext &context) override;

private:
   // 预分配缓冲区管理（C风格，兼容SEH）
   struct HandleBufferManager
   {
       BYTE *buffer;
       size_t size;

       HandleBufferManager();
       ~HandleBufferManager();
       bool Resize(size_t newSize);
       void Reset();
   };

   // 获取进程创建时间标识（用于缓存验证）
   static uint32_t GetProcessCreationTime(DWORD pid);
   bool IsHandlePointingToUs_Safe(const void *pHandleEntry, DWORD ownPid);
};
