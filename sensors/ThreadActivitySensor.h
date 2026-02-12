#pragma once

#include <windows.h>
#include "../ISensor.h"

#include <chrono>

class ThreadActivitySensor : public ISensor
{
public:
    const char *GetName() const override { return "ThreadActivitySensor"; }
    SensorWeight GetWeight() const override { return SensorWeight::HEAVY; } // 10-100ms: 线程和模块活动监控
    SensorExecutionResult Execute(SensorRuntimeContext &context) override;

private:
   friend class ThreadActivitySensorTestAccess;

   static bool IsIgnorableNtStatus(NTSTATUS status);
   static bool HasHardwareBreakpoints(const CONTEXT &ctx);

   bool ScanThreadsWithTimeout(SensorRuntimeContext &context, int budget_ms, const std::chrono::steady_clock::time_point &startTime);
   void AnalyzeNewThread(SensorRuntimeContext &context, DWORD threadId);
   void AnalyzeThreadIntegrity(SensorRuntimeContext &context, DWORD threadId);
   std::string GetThreadDetailedInfo(DWORD threadId, PVOID startAddress);
   DWORD GetProcessIdOfThread(HANDLE hThread);
};
