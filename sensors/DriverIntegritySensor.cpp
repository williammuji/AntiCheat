#include <windows.h>
#include "DriverIntegritySensor.h"
#include "SensorRuntimeContext.h"
#include "../utils/SystemUtils.h"
#include "../Logger.h"
#include "../utils/Utils.h"
#include "../CheatConfigManager.h"
#include <string>
#include <vector>
#include <unordered_set>
#include <algorithm>
#include <psapi.h>

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "psapi.lib")

namespace
{
    // Windows 内核组件基名白名单：这些模块只有内核/会话管理器会加载，
    // 即便路径归一化在极端环境（双系统 / Ghost 还原 / 非典型盘符）下解析不到真实文件，
    // 导致 WinVerifyTrust 以 TRUST_E_NOSIGNATURE 失败，也不应该作为"可疑驱动"上报。
    const std::unordered_set<std::wstring> &GetKernelComponentBaseNames()
    {
        static const std::unordered_set<std::wstring> kNames = {
            // NT 内核及其变体
            L"ntoskrnl.exe", L"ntkrnlpa.exe", L"ntkrnlmp.exe", L"ntkrpamp.exe",
            // HAL 及其变体
            L"hal.dll", L"halmacpi.dll", L"halacpi.dll", L"halaacpi.dll", L"halx86.dll",
            // 启动/会话管理
            L"smss.exe", L"csrss.exe", L"winload.exe", L"winload.efi", L"winresume.exe", L"winresume.efi",
            // 其它核心子系统
            L"ci.dll", L"clfs.sys", L"cng.sys", L"fltmgr.sys", L"ksecdd.sys",
            L"msrpc.sys", L"ndis.sys", L"netio.sys", L"pshed.dll", L"tm.sys",
            L"werkernel.sys", L"win32k.sys",
        };
        return kNames;
    }

    std::wstring ToLowerCopy(std::wstring s)
    {
        std::transform(s.begin(), s.end(), s.begin(), ::towlower);
        return s;
    }
}

SensorExecutionResult DriverIntegritySensor::Execute(SensorRuntimeContext &context)
{
    auto startTime = std::chrono::steady_clock::now();
    int budgetMs = CheatConfigManager::GetInstance().GetHeavyScanBudgetMs();
    if (budgetMs <= 0) budgetMs = 1500; // Default fallback

    m_lastFailureReason = anti_cheat::UNKNOWN_FAILURE;

    LPVOID drivers[1024];
    DWORD cbNeeded;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded))
    {
        RecordFailure(anti_cheat::SYSTEM_API_CALL_FAILED);
        return SensorExecutionResult::FAILURE;
    }

    int cDrivers = cbNeeded / sizeof(drivers[0]);
    if (cDrivers == 0)
    {
        LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "DriverIntegritySensor: No drivers found");
        RecordFailure(anti_cheat::SYSTEM_API_CALL_FAILED);
        return SensorExecutionResult::FAILURE;
    }

    SystemUtils::WindowsVersion winVer = SystemUtils::GetWindowsVersion();

    // 游标使用「驱动基地址（uintptr_t）」而非数组下标，保证驱动列表顺序变化时不偏移。
    // GetDriverCursorOffset() 保存的是上次超时时 drivers[i] 的地址值，0 表示从头开始。
    uintptr_t resumeAddr = static_cast<uintptr_t>(context.GetDriverCursorOffset());
    bool resumeFound = (resumeAddr == 0); // 若为 0，从第一个开始

    for (int i = 0; i < cDrivers; i++)
    {
        // 定位续扫起始点：找到上次保存的驱动地址
        if (!resumeFound)
        {
            if (reinterpret_cast<uintptr_t>(drivers[i]) == resumeAddr)
                resumeFound = true;
            else
                continue; // 跳过已处理的
        }

        // 性能控制：每处理10个驱动检查一次时间
        if (i % 10 == 0)
        {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime).count();
            if (elapsed > budgetMs)
            {
                // 保存当前驱动的基地址作为游标
                context.SetDriverCursorOffset(static_cast<size_t>(reinterpret_cast<uintptr_t>(drivers[i])));
                LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                           "DriverIntegritySensor 扫描超时: 索引=%d/%d，已保存驱动地址游标", i, cDrivers);
                return SensorExecutionResult::TIMEOUT;
            }
        }

        // 先以文件基名匹配 Windows 内核组件白名单：这些模块由内核 / SMSS 加载，
        // 路径归一化失败时不应被误判为可疑驱动。
        WCHAR szBaseName[MAX_PATH] = {0};
        if (GetDeviceDriverBaseNameW(drivers[i], szBaseName, MAX_PATH))
        {
            std::wstring baseName = ToLowerCopy(szBaseName);
            const auto &kernelWhitelist = GetKernelComponentBaseNames();
            if (kernelWhitelist.find(baseName) != kernelWhitelist.end())
            {
                LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                           "DriverIntegritySensor: 跳过已知 Windows 内核组件: %s",
                           Utils::WideToString(baseName).c_str());
                continue;
            }
        }

        WCHAR szDriver[MAX_PATH];
        if (GetDeviceDriverFileNameW(drivers[i], szDriver, MAX_PATH))
        {
            std::wstring driverPath = SystemUtils::NormalizeKernelPathToWinPath(szDriver);

            // Use unified ValidateModule logic
            auto validation = Utils::ValidateModule(driverPath, winVer);

            if (!validation.isTrusted)
            {
                // [User Request] 增加对显式配置的白名单检查，排除如电脑管家等已知的正常驱动误报
                if (Utils::IsExplicitlyWhitelistedModule(driverPath))
                {
                    LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                               "DriverIntegritySensor: 忽略显式白名单中的非信任驱动: %s",
                               Utils::WideToString(driverPath).c_str());
                    continue;
                }

                std::string u8Path = Utils::WideToString(driverPath);
                context.AddEvidence(anti_cheat::ENVIRONMENT_SUSPICIOUS_DRIVER,
                    "Suspicious driver (Reason: " + validation.reason + "): " + u8Path);
            }
        }
    }

    // 如果 resumeFound 仍为 false，说明上次保存的驱动地址已经不存在（驱动已卸载），
    // 视为正常情况，从头再来一轮（游标已重置为 0）。
    if (!resumeFound)
    {
        LOG_DEBUG(AntiCheatLogger::LogCategory::SENSOR,
                  "DriverIntegritySensor: 上次游标对应驱动已卸载，本轮从头扫描");
    }

    // 全部扫描完成，重置游标
    context.SetDriverCursorOffset(0);
    return SensorExecutionResult::SUCCESS;
}
