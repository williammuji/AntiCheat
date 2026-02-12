#pragma once

#include <windows.h>
#include "../ISensor.h"


class ProcessAndWindowMonitorSensor : public ISensor
{
public:
    const char *GetName() const override { return "ProcessAndWindowMonitorSensor"; }
    SensorWeight GetWeight() const override { return SensorWeight::CRITICAL; } // 枚举所有进程/窗口，非常耗时
    SensorExecutionResult Execute(SensorRuntimeContext &context) override;

private:
   // Helper functions if any
   void CheckWindow(HWND hwnd, SensorRuntimeContext &context);
   void CheckProcess(DWORD pid, const std::wstring& processName, SensorRuntimeContext &context);
};
