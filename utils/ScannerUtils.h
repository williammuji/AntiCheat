#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <functional>
#include <memory>
#include <algorithm>
#include "../Logger.h"
#include "SystemUtils.h"

// Common Scanner Utilities
class MemoryScanner
{
   public:
    using MemoryRegionCallback = std::function<bool(const MEMORY_BASIC_INFORMATION &)>;

    static void ScanMemoryRegions(MemoryRegionCallback callback)
    {
        LPBYTE address = nullptr;
        MEMORY_BASIC_INFORMATION mbi;
        const uintptr_t maxAddress = sizeof(void *) == 4 ? 0x7FFFFFFF : 0x7FFFFFFFFFFF;

        while (VirtualQuery(address, &mbi, sizeof(mbi)))
        {
            if (!callback(mbi))
            {
                break;
            }

            address = reinterpret_cast<LPBYTE>(mbi.BaseAddress) + mbi.RegionSize;

            if (address < reinterpret_cast<LPBYTE>(mbi.BaseAddress) ||
                reinterpret_cast<uintptr_t>(address) > maxAddress)
            {
                break;
            }
        }
    }

    static void ScanPrivateExecutableMemory(MemoryRegionCallback callback)
    {
        ScanMemoryRegions([&callback](const MEMORY_BASIC_INFORMATION &mbi) -> bool {
            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
                (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
            {
                return callback(mbi);
            }
            return true;
        });
    }

    static void ScanExecutableMemory(MemoryRegionCallback callback)
    {
        ScanMemoryRegions([&callback](const MEMORY_BASIC_INFORMATION &mbi) -> bool {
            if (mbi.State == MEM_COMMIT &&
                (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
            {
                return callback(mbi);
            }
            return true;
        });
    }
};

class ModuleScanner
{
   public:
    using ModuleCallback = std::function<void(HMODULE)>;

    static void EnumerateModules(ModuleCallback callback)
    {
        std::vector<HMODULE> hMods(1024);
        DWORD cbNeeded = 0;

        if (!EnumProcessModules(GetCurrentProcess(), hMods.data(), hMods.size() * sizeof(HMODULE), &cbNeeded))
        {
            DWORD error = GetLastError();
            LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR, "ModuleScanner: EnumProcessModules失败，错误码: 0x%08X",
                        error);
            return;
        }

        size_t moduleCount_actual = cbNeeded / sizeof(HMODULE);

        for (size_t i = 0; i < std::min(moduleCount_actual, hMods.size()); ++i)
        {
            callback(hMods[i]);
        }

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

    static std::vector<HMODULE> GetAllModules()
    {
        std::vector<HMODULE> modules;
        modules.reserve(1000);
        EnumerateModules([&modules](HMODULE hModule) { modules.push_back(hModule); });
        return modules;
    }
};

class ThreadScanner
{
   public:
    using ThreadCallback = std::function<void(DWORD)>;

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

    static std::vector<DWORD> GetAllThreads(DWORD targetProcessId = 0)
    {
        std::vector<DWORD> threads;
        threads.reserve(100);
        EnumerateThreads([&threads](DWORD threadId) { threads.push_back(threadId); }, targetProcessId);
        return threads;
    }

    static PVOID GetThreadStartAddress(DWORD threadId)
    {
        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
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
