#pragma once

#include "../include/ISensor.h"
#include <chrono>

class ThreadActivitySensor : public ISensor
{
public:
    const char *GetName() const override { return "ThreadActivitySensor"; }
    SensorWeight GetWeight() const override { return SensorWeight::HEAVY; } // 10-100ms: 线程和模块活动监控
    SensorExecutionResult Execute(ScanContext &context) override;

private:
   bool ScanThreadsWithTimeout(ScanContext &context, int budget_ms, const std::chrono::steady_clock::time_point &startTime);
   void AnalyzeNewThread(ScanContext &context, DWORD threadId);
   void AnalyzeThreadIntegrity(ScanContext &context, DWORD threadId);
   std::string GetThreadDetailedInfo(DWORD threadId, PVOID startAddress);
   DWORD GetProcessIdOfThread(HANDLE hThread);
};
