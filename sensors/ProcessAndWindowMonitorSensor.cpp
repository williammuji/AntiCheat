#include "ProcessAndWindowMonitorSensor.h"
#include "SensorRuntimeContext.h"
#include "utils/SystemUtils.h"
#include "Logger.h"
#include "utils/Utils.h"
#include <psapi.h>
#include <tlhelp32.h>

SensorExecutionResult ProcessAndWindowMonitorSensor::Execute(SensorRuntimeContext &context)
{
    m_lastFailureReason = anti_cheat::UNKNOWN_FAILURE;

    // 1. 枚举窗口
    struct EnumContext {
        ProcessAndWindowMonitorSensor* sensor;
        SensorRuntimeContext* context;
    };
    EnumContext enumCtx = {this, &context};

    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        EnumContext* ctx = (EnumContext*)lParam;
        ctx->sensor->CheckWindow(hwnd, *(ctx->context));
        return TRUE;
    }, (LPARAM)&enumCtx);

    // 2. 枚举进程 (使用ToolHelp32，因其比PSAPI更轻量且信息全)
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        if (Process32FirstW(hSnapshot, &pe32))
        {
            do
            {
                 CheckProcess(pe32.th32ProcessID, pe32.szExeFile, context);
            } while (Process32NextW(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    else
    {
         this->RecordFailure(anti_cheat::PROCESS_ENUM_FAILED);
         return SensorExecutionResult::FAILURE;
    }

    return SensorExecutionResult::SUCCESS;
}

void ProcessAndWindowMonitorSensor::CheckWindow(HWND hwnd, SensorRuntimeContext &context)
{
    if (!IsWindowVisible(hwnd)) return;

    wchar_t windowTitle[256];
    GetWindowTextW(hwnd, windowTitle, 256);
    if (wcslen(windowTitle) == 0) return;

    std::wstring title = windowTitle;
    std::transform(title.begin(), title.end(), title.begin(), ::towlower);

    auto harmfulKeywords = context.GetHarmfulKeywords();
    if (harmfulKeywords)
    {
         for (const auto& keyword : *harmfulKeywords)
         {
              if (title.find(keyword) != std::wstring::npos)
              {
                   // Check whitelist
                   auto whitelisted = context.GetWhitelistedWindowKeywords();
                   bool isWhitelisted = false;
                   if (whitelisted)
                   {
                        for (const auto& wl : *whitelisted)
                        {
                             if (title.find(wl) != std::wstring::npos)
                             {
                                  isWhitelisted = true;
                                  break;
                             }
                        }
                   }

                   if (!isWhitelisted)
                   {
                        context.AddEvidence(anti_cheat::ENVIRONMENT_HARMFUL_PROCESS, "Detected window: " + Utils::WideToString(title));
                   }
              }
         }
    }
}

void ProcessAndWindowMonitorSensor::CheckProcess(DWORD pid, const std::wstring& processName, SensorRuntimeContext &context)
{
    if (pid == GetCurrentProcessId()) return; // Skip self

    std::wstring nameLower = processName;
    std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::towlower);

    auto harmfulProcessNames = context.GetHarmfulProcessNames();
    if (harmfulProcessNames)
    {
         for (const auto& harmful : *harmfulProcessNames)
         {
              if (nameLower == harmful)
              {
                   // Double check context for whitelisted process paths if needed,
                   // but usually name match is enough for blacklisting known cheats.
                   context.AddEvidence(anti_cheat::ENVIRONMENT_HARMFUL_PROCESS, "Detected process: " + Utils::WideToString(nameLower));
              }
         }
    }
}
