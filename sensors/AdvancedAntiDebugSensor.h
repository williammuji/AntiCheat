#pragma once

#include <windows.h>
#include "ISensor.h"

class AdvancedAntiDebugSensor : public ISensor
{
public:
    const char *GetName() const override { return "AdvancedAntiDebugSensor"; }
    SensorWeight GetWeight() const override { return SensorWeight::LIGHT; } // < 1ms: 轻量级反调试检测
    SensorExecutionResult Execute(ScanContext &context) override;

private:
   struct DebugDetectionResult
   {
       bool detected;
       const char *description;
       DWORD exceptionCode;
   };

   static DebugDetectionResult CheckRemoteDebugger_Internal();
   static DebugDetectionResult CheckPEBBeingDebugged_Internal();
   static DebugDetectionResult CheckCloseHandleDebugger_Internal();
   static DebugDetectionResult CheckDebugRegisters_Internal();
   static DebugDetectionResult CheckKernelDebuggerNtQuery_Internal();
   static DebugDetectionResult CheckKernelDebuggerKUSER_Internal();
   static DebugDetectionResult CheckProcessHeapFlags_Internal();
   static DebugDetectionResult CheckProcessDebugPort_Internal();
   static DebugDetectionResult CheckProcessDebugFlags_Internal();

   void CheckRemoteDebugger(ScanContext &context);
   void CheckPEBBeingDebugged(ScanContext &context);
   void CheckCloseHandleDebugger(ScanContext &context);
   void CheckDebugRegisters(ScanContext &context);
   void CheckProcessHeapFlags(ScanContext &context);
   void CheckProcessDebugPort(ScanContext &context);
   void CheckProcessDebugFlags(ScanContext &context);
   void CheckKernelDebuggerNtQuery(ScanContext &context);
   SensorExecutionResult CheckKernelDebuggerKUSER(ScanContext &context);
};
