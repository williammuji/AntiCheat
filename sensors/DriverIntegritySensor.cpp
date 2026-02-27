#include <windows.h>
#include "DriverIntegritySensor.h"
#include "SensorRuntimeContext.h"
#include "../utils/SystemUtils.h"
#include "../Logger.h"
#include "../utils/Utils.h"
#include <string>
#include <vector>
#include <psapi.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "psapi.lib")

SensorExecutionResult DriverIntegritySensor::Execute(SensorRuntimeContext &context)
{
    m_lastFailureReason = anti_cheat::UNKNOWN_FAILURE;

    LPVOID drivers[1024];
    DWORD cbNeeded;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded))
    {
        int cDrivers = cbNeeded / sizeof(drivers[0]);
        if (cDrivers == 0)
        {
             LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "DriverIntegritySensor: No drivers found");
             RecordFailure(anti_cheat::SYSTEM_API_CALL_FAILED);
             return SensorExecutionResult::FAILURE;
        }

        SystemUtils::WindowsVersion winVer = SystemUtils::GetWindowsVersion();

        for (int i = 0; i < cDrivers; i++)
        {
            WCHAR szDriver[MAX_PATH];
            if (GetDeviceDriverFileNameW(drivers[i], szDriver, MAX_PATH))
            {
                std::wstring driverPath = SystemUtils::NormalizeKernelPathToWinPath(szDriver);

                // Use unified ValidateModule logic
                auto validation = Utils::ValidateModule(driverPath, winVer);

                if (!validation.isTrusted)
                {
                    std::string u8Path = Utils::WideToString(driverPath);
                    context.AddEvidence(anti_cheat::ENVIRONMENT_SUSPICIOUS_DRIVER,
                        "Suspicious driver (Reason: " + validation.reason + "): " + u8Path);
                }
            }
        }
    }
    else
    {
         RecordFailure(anti_cheat::SYSTEM_API_CALL_FAILED);
         return SensorExecutionResult::FAILURE;
    }

    return SensorExecutionResult::SUCCESS;
}
