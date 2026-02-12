#include <windows.h>
#include "DriverIntegritySensor.h"
#include "SensorRuntimeContext.h"
#include "../utils/SystemUtils.h"
#include "../Logger.h"
#include "../utils/Utils.h"
#include "../CheatConfigManager.h"
#include <string>
#include <vector>
#include <algorithm>
#include <psapi.h>
#include <wintrust.h>
#include <softpub.h>

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
                std::wstring driverPath = SystemUtils::NormalizeKernelPathToWinPath(szDriver);

                // Simple logic: verify signature
                std::wstring normalizedPath = driverPath;
                std::transform(normalizedPath.begin(), normalizedPath.end(), normalizedPath.begin(), ::towlower);
                const std::wstring driverName = Utils::GetFileName(normalizedPath);

                // Coarse-grained unified whitelist:
                // 1) Global module whitelist policy (dirs/files/system)
                // 2) Existing "system modules" name whitelist
                bool isWhitelisted = Utils::IsWhitelistedModule(normalizedPath);
                if (!isWhitelisted)
                {
                    auto systemModules = CheatConfigManager::GetInstance().GetWhitelistedSystemModules();
                    if (systemModules && systemModules->count(driverName) > 0)
                    {
                        isWhitelisted = true;
                    }
                }

                if (isWhitelisted)
                {
                    continue;
                }

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
