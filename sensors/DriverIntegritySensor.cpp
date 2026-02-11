#include <windows.h>
#include "DriverIntegritySensor.h"
#include "../include/ScanContext.h"
#include "../utils/SystemUtils.h"
#include "../Logger.h"
#include "../utils/Utils.h"
#include <string>
#include <vector>
#include <algorithm>
#include <psapi.h>
#include <wintrust.h>
#include <softpub.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "psapi.lib")

SensorExecutionResult DriverIntegritySensor::Execute(ScanContext &context)
{
    m_lastFailureReason = anti_cheat::UNKNOWN_FAILURE;

    LPVOID drivers[1024];
    DWORD cbNeeded;
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded))
    {
        int cDrivers = cbNeeded / sizeof(drivers[0]);
        if (cDrivers == 0)
        {
             LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "DriverIntegritySensor: No drivers found (Insufficient privileges?)");
             RecordFailure(anti_cheat::SYSTEM_API_CALL_FAILED);
             return SensorExecutionResult::FAILURE;
        }
        for (int i = 0; i < cDrivers; i++)
        {
             // Throttling check? Original code didn't have it in the snippet 2737-2829.
             // Maybe it was short enough.

            WCHAR szDriver[MAX_PATH];
            if (GetDeviceDriverFileNameW(drivers[i], szDriver, MAX_PATH))
            {
                std::wstring driverPath = szDriver;
                // Normalize path if it starts with \SystemRoot or ?? (backslashed path)
                if (driverPath.find(L"\\SystemRoot\\") == 0)
                {
                     WCHAR winDir[MAX_PATH];
                     GetWindowsDirectoryW(winDir, MAX_PATH);
                     driverPath.replace(0, 12, std::wstring(winDir) + L"\\");
                }
                else if (driverPath.find(L"\\??\\") == 0)
                {
                     driverPath.replace(0, 4, L"");
                }

                // Simple logic: verify signature
                if (!VerifyDriverSignature(driverPath))
                {
                    std::string u8Path = Utils::WideToString(driverPath);
                    context.AddEvidence(anti_cheat::ENVIRONMENT_SUSPICIOUS_DRIVER, "Unsigned or untrusted driver: " + u8Path);
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

bool DriverIntegritySensor::VerifyDriverSignature(const std::wstring& filePath)
{
   LONG lStatus;
   WINTRUST_FILE_INFO FileData;
   memset(&FileData, 0, sizeof(FileData));
   FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
   FileData.pcwszFilePath = filePath.c_str();
   FileData.hFile = NULL;
   FileData.pgKnownSubject = NULL;

   GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
   WINTRUST_DATA WinTrustData;
   memset(&WinTrustData, 0, sizeof(WinTrustData));
   WinTrustData.cbStruct = sizeof(WinTrustData);
   WinTrustData.pPolicyCallbackData = NULL;
   WinTrustData.pSIPClientData = NULL;
   WinTrustData.dwUIChoice = WTD_UI_NONE;
   WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
   WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;
   WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
   WinTrustData.hWVTStateData = NULL;
   // WinTrustData.pwszURLReference = NULL; // Removing this line as it might be problematic if not zeroed (it is zeroed by memset)
   WinTrustData.dwProvFlags = WTD_SAFER_FLAG;
   WinTrustData.dwUIContext = 0;
   WinTrustData.pFile = &FileData;

   lStatus = WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

   bool isTrusted = (lStatus == ERROR_SUCCESS);

   WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
   WinVerifyTrust(NULL, &WVTPolicyGUID, &WinTrustData);

   return isTrusted;
}
