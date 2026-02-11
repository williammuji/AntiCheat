#include "ProcessAndWindowMonitorSensor.h"
#include "ScanContext.h"
#include "utils/SystemUtils.h"
#include "Logger.h"
#include "utils/Utils.h"
#include <psapi.h>
#include <tlhelp32.h>

SensorExecutionResult ProcessAndWindowMonitorSensor::Execute(ScanContext &context)
{
    m_lastFailureReason = anti_cheat::UNKNOWN_FAILURE;

    // 1. 鏋氫妇绐楀彛
    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        auto *pSensor = (ProcessAndWindowMonitorSensor *)lParam;
        // ScanContext is not passed directly to callback, we need to pass it via lParam struct or use member if possible.
        // Wait, I cannot pass member to static callback nicely without struct.
        // Let's assume I cast lParam to a struct containing pSensor and context.
        // Or cleaner: pass struct { ProcessAndWindowMonitorSensor* sensor; ScanContext* context; };
        return TRUE;
    }, (LPARAM)this);

    // Correcting implementations:
    // The original code likely used a lambda with context capture if it was inside a method,
    // OR it passed a struct to EnumWindows.
    // BUT EnumWindows C-API doesn't allow capturing lambdas unless they are convertible to function pointer (no captures).
    // So distinct struct is needed.

    struct EnumContext {
        ProcessAndWindowMonitorSensor* sensor;
        ScanContext* context;
    };
    EnumContext enumCtx = {this, &context};

    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        EnumContext* ctx = (EnumContext*)lParam;
        ctx->sensor->CheckWindow(hwnd, *(ctx->context));
        return TRUE;
    }, (LPARAM)&enumCtx);

    // 2. 鏋氫妇杩涚▼ (浣跨敤ToolHelp32锛屽洜鍏舵瘮PSAPI鏇磋交閲忎笖淇℃伅鍏?
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

void ProcessAndWindowMonitorSensor::CheckWindow(HWND hwnd, ScanContext &context)
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

void ProcessAndWindowMonitorSensor::CheckProcess(DWORD pid, const std::wstring& processName, ScanContext &context)
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
