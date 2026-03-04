#include "ProcessAndWindowMonitorSensor.h"
#include "SensorRuntimeContext.h"
#include "utils/SystemUtils.h"
#include "Logger.h"
#include "utils/Utils.h"
#include "CheatConfigManager.h"
#include <psapi.h>
#include <tlhelp32.h>

SensorExecutionResult ProcessAndWindowMonitorSensor::Execute(SensorRuntimeContext &context)
{
    auto startTime = std::chrono::steady_clock::now();
    int budget_ms = CheatConfigManager::GetInstance().GetHeavyScanBudgetMs();
    if (budget_ms <= 0) budget_ms = 10;

    size_t cursor = context.GetWindowCursorOffset();

    m_lastFailureReason = anti_cheat::UNKNOWN_FAILURE;

    // 1. 枚举窗口
    std::vector<HWND> windows;
    EnumWindows([](HWND hwnd, LPARAM lp) -> BOOL {
        auto* vec = reinterpret_cast<std::vector<HWND>*>(lp);
        vec->push_back(hwnd);
        return TRUE;
    }, reinterpret_cast<LPARAM>(&windows));

    // 2. 枚举进程 (Snapshot)，同时收集进程名，避免后续 CheckProcess 拿不到名称
    struct ProcessEntry {
        DWORD pid;
        std::wstring name;
    };
    std::vector<ProcessEntry> processes;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32W pe = {sizeof(pe)};
        if (Process32FirstW(snapshot, &pe))
        {
            do
            {
                processes.push_back({pe.th32ProcessID, std::wstring(pe.szExeFile)});
            } while (Process32NextW(snapshot, &pe));
        }
        CloseHandle(snapshot);
    }
    else
    {
        // 枚举失败，记录错误并返回
        this->RecordFailure(anti_cheat::PROCESS_ENUM_FAILED);
        return SensorExecutionResult::FAILURE;
    }

    size_t totalItems = windows.size() + processes.size();
    if (cursor >= totalItems) cursor = 0;

    while (cursor < totalItems)
    {
        if (cursor < windows.size())
        {
            CheckWindow(windows[cursor], context);
        }
        else
        {
            const auto& proc = processes[cursor - windows.size()];
            CheckProcess(proc.pid, proc.name, context);
        }

        cursor++;

        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count() >= budget_ms)
        {
            context.SetWindowCursorOffset(cursor);
            LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "ProcessAndWindowMonitorSensor: 扫描超时，已处理 %zu/%zu 个项", cursor, totalItems);
            return SensorExecutionResult::TIMEOUT;
        }
    }

    context.SetWindowCursorOffset(0);
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
