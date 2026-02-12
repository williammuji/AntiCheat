#pragma once

#include <windows.h>
#include "../ISensor.h"


class AdvancedAntiDebugSensor : public ISensor
{
public:
    const char *GetName() const override { return "AdvancedAntiDebugSensor"; }
    SensorWeight GetWeight() const override { return SensorWeight::LIGHT; } // < 1ms: 轻量级反调试检测
    SensorExecutionResult Execute(SensorRuntimeContext &context) override;

private:
   friend class AdvancedAntiDebugSensorTestAccess;

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

   void CheckRemoteDebugger(SensorRuntimeContext &context);
   void CheckPEBBeingDebugged(SensorRuntimeContext &context);
   void CheckCloseHandleDebugger(SensorRuntimeContext &context);
   void CheckDebugRegisters(SensorRuntimeContext &context);
   void CheckProcessHeapFlags(SensorRuntimeContext &context);
   void CheckProcessDebugPort(SensorRuntimeContext &context);
   void CheckProcessDebugFlags(SensorRuntimeContext &context);
   void CheckKernelDebuggerNtQuery(SensorRuntimeContext &context);
   SensorExecutionResult CheckKernelDebuggerKUSER(SensorRuntimeContext &context);
};
