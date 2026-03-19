#pragma once

#include <windows.h>
#include "../ISensor.h"


class ProcessAndWindowMonitorSensor : public ISensor
{
public:
    const char *GetName() const override { return "ProcessAndWindowMonitorSensor"; }
    SensorWeight GetWeight() const override { return SensorWeight::CRITICAL; } // Enumerate all processes/windows, extremely time-consuming
    virtual SensorExecutionResult Execute(SensorRuntimeContext &context) override;

private:
   // Helper functions if any
   void CheckWindow(HWND hwnd, SensorRuntimeContext &context);
   void CheckProcess(DWORD pid, const std::wstring& processName, SensorRuntimeContext &context);
};
