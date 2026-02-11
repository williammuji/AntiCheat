#pragma once

#include "SystemUtils.h"
#include "../Logger.h"
#include <functional>
#include <vector>
#include <psapi.h>
#include <algorithm>
#include <tlhelp32.h>

// ---- 公共扫描器类 ----
// 用于统一内存、模块、线程扫描逻辑，减少代码重复

class MemoryScanner
{
public:
    // 内存区域扫描回调函数类型（返回 bool：true=继续，false=停止）
    using MemoryRegionCallback = std::function<bool(const MEMORY_BASIC_INFORMATION &)>;

    // 扫描所有内存区域（支持提前退出）
    static void ScanMemoryRegions(MemoryRegionCallback callback)
    {
        LPBYTE address = nullptr;
        MEMORY_BASIC_INFORMATION mbi;

        // 生产环境优化：32位系统地址空间保护
        const uintptr_t maxAddress = sizeof(void *) == 4 ? 0x7FFFFFFF : 0x7FFFFFFFFFFF;

        while (VirtualQuery(address, &mbi, sizeof(mbi)))
        {
            // 调用回调函数处理内存区域，如果返回 false 则提前退出
            if (!callback(mbi))
            {
                break;
            }

            address = reinterpret_cast<LPBYTE>(mbi.BaseAddress) + mbi.RegionSize;

            // 生产环境优化：地址溢出保护
            if (address < reinterpret_cast<LPBYTE>(mbi.BaseAddress) ||
                reinterpret_cast<uintptr_t>(address) > maxAddress)
            {
                break;
            }
        }
    }

    // 扫描私有可执行内存区域
    static void ScanPrivateExecutableMemory(MemoryRegionCallback callback)
    {
        ScanMemoryRegions([&callback](const MEMORY_BASIC_INFORMATION &mbi) -> bool {
            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
                (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
            {
                return callback(mbi);
            }
            return true;  // 继续扫描
        });
    }

    // 扫描可执行内存区域
    static void ScanExecutableMemory(MemoryRegionCallback callback)
    {
        ScanMemoryRegions([&callback](const MEMORY_BASIC_INFORMATION &mbi) -> bool {
            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
            {
                return callback(mbi);
            }
            return true;  // 继续扫描
        });
    }
};

class ModuleScanner
{
public:
    // 模块扫描回调函数类型
    using ModuleCallback = std::function<void(HMODULE)>;

    // 枚举所有模块
    static void EnumerateModules(ModuleCallback callback)
    {
        std::vector<HMODULE> hMods(1024);  // 使用合理的默认值
        DWORD cbNeeded = 0;

        if (!EnumProcessModules(GetCurrentProcess(), hMods.data(), hMods.size() * sizeof(HMODULE), &cbNeeded))
        {
            DWORD error = GetLastError();
            LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR, "ModuleScanner: EnumProcessModules失败，错误码: 0x%08X",
                        error);
            return;
        }

        size_t moduleCount_actual = cbNeeded / sizeof(HMODULE);

        // 处理第一批模块
        for (size_t i = 0; i < std::min(moduleCount_actual, hMods.size()); ++i)
        {
            callback(hMods[i]);
        }

        // 如果还有更多模块，继续枚举
        while (moduleCount_actual > hMods.size())
        {
            if (!EnumProcessModules(GetCurrentProcess(), hMods.data(), hMods.size() * sizeof(HMODULE), &cbNeeded))
            {
                break;
            }

            moduleCount_actual = cbNeeded / sizeof(HMODULE);
            size_t startIndex = hMods.size();

            for (size_t i = 0; i < std::min(moduleCount_actual - startIndex, hMods.size()); ++i)
            {
                callback(hMods[i]);
            }
        }
    }

    // 获取所有模块句柄
    static std::vector<HMODULE> GetAllModules()
    {
        std::vector<HMODULE> modules;
        modules.reserve(1000);  // 预分配合理大小

        EnumerateModules([&modules](HMODULE hModule) { modules.push_back(hModule); });

        return modules;
    }
};

class ThreadScanner
{
public:
    // 线程扫描回调函数类型
    using ThreadCallback = std::function<void(DWORD)>;

    // 枚举所有线程
    static void EnumerateThreads(ThreadCallback callback, DWORD targetProcessId = 0)
    {
        if (targetProcessId == 0)
            targetProcessId = GetCurrentProcessId();

        HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hThreadSnapshot == INVALID_HANDLE_VALUE)
        {
            DWORD error = GetLastError();
            LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR,
                        "ThreadScanner: CreateToolhelp32Snapshot失败，错误码: 0x%08X", error);
            return;
        }

        auto snapshot_closer = [](HANDLE h) { CloseHandle(h); };
        std::unique_ptr<void, decltype(snapshot_closer)> snapshot_handle(hThreadSnapshot, snapshot_closer);

        THREADENTRY32 te;
        te.dwSize = sizeof(te);

        if (Thread32First(hThreadSnapshot, &te))
        {
            do
            {
                if (te.th32OwnerProcessID == targetProcessId)
                {
                    callback(te.th32ThreadID);
                }
            } while (Thread32Next(hThreadSnapshot, &te));
        }
    }

    // 获取所有线程ID
    static std::vector<DWORD> GetAllThreads(DWORD targetProcessId = 0)
    {
        std::vector<DWORD> threads;
        threads.reserve(100);  // 预分配合理大小

        EnumerateThreads([&threads](DWORD threadId) { threads.push_back(threadId); }, targetProcessId);

        return threads;
    }

    // 获取线程起始地址
    static PVOID GetThreadStartAddress(DWORD threadId)
    {
        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
        if (!hThread)
            hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, threadId); // Fallback

        if (!hThread)
            return nullptr;

        auto thread_closer = [](HANDLE h) { CloseHandle(h); };
        std::unique_ptr<void, decltype(thread_closer)> thread_handle(hThread, thread_closer);

        PVOID startAddress = nullptr;
        if (SystemUtils::g_pNtQueryInformationThread &&
            NT_SUCCESS(SystemUtils::g_pNtQueryInformationThread(hThread,
                                                                (THREADINFOCLASS)9,  // ThreadQuerySetWin32StartAddress
                                                                &startAddress, sizeof(startAddress), nullptr)))
        {
            return startAddress;
        }

        return nullptr;
    }
};
