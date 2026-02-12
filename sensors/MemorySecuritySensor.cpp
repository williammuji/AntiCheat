#include "MemorySecuritySensor.h"
#include "SensorRuntimeContext.h"
#include "utils/SystemUtils.h"
#include "Logger.h"
#include "CheatConfigManager.h"
#include "utils/Utils.h"
#include <vector>
#include <sstream>
#include <algorithm>
#include <tlhelp32.h>

bool MemorySecuritySensor::IsRwXProtection(DWORD protect)
{
    return (protect & PAGE_EXECUTE_READWRITE) || (protect & PAGE_EXECUTE_WRITECOPY);
}

bool MemorySecuritySensor::IsRxOnlyProtection(DWORD protect)
{
    return (protect & PAGE_EXECUTE_READ) && !IsRwXProtection(protect);
}

bool MemorySecuritySensor::ShouldSkipLowAddressSmallRwx(uintptr_t baseAddr, SIZE_T regionSize)
{
    const SIZE_T lowAddressThreshold = 0x200000;
    const SIZE_T smallRwxThreshold = 64 * 1024;
    return baseAddr < lowAddressThreshold && regionSize < smallRwxThreshold;
}

SensorExecutionResult MemorySecuritySensor::Execute(SensorRuntimeContext &context)
{
    // 重置失败原因
    m_lastFailureReason = anti_cheat::UNKNOWN_FAILURE;

    // 策略1：配置版本门控 - 检查当前OS版本是否满足配置的最低要求
    if (!IsOsSupported(context))
    {
        LOG_DEBUG(AntiCheatLogger::LogCategory::SENSOR, "内存安全检测已禁用：当前OS版本低于配置最低要求");
        RecordFailure(anti_cheat::MEMORY_OS_VERSION_UNSUPPORTED);
        return SensorExecutionResult::FAILURE;
    }

    const int budget_ms = CheatConfigManager::GetInstance().GetHeavyScanBudgetMs();
    const auto startTime = std::chrono::steady_clock::now();

    // 4. 使用公共扫描器进行内存遍历（支持超时提前退出）
    bool timeoutOccurred = false;
    size_t regionsScanned = 0;

    // 如果缓存无效，尝试重新刷新
    if (!context.IsMemoryCacheValid)
    {
        LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "MemorySecuritySensor: 内存缓存无效, 尝试刷新");
        context.RefreshMemoryCache();
    }

    // 使用缓存的内存区域进行遍历
    for (const auto &mbi : context.CachedMemoryRegions)
    {
        // 优化：每100个内存区域检查一次超时（降低检查开销）
        if (regionsScanned++ % 100 == 0)
        {
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count() > budget_ms)
            {
                LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                              "MemorySecuritySensor: 内存扫描超时，已扫描%zu个区域", regionsScanned);
                RecordFailure(anti_cheat::MEMORY_SCAN_TIMEOUT);
                timeoutOccurred = true;
                break;
            }
        }

        // 性能优化：跳过已知安全区域
        uintptr_t currentAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        if (IsKnownSafeRegion(currentAddr, mbi.RegionSize))
        {
            continue;
        }

        // 核心检测逻辑：统一处理所有可执行内存
        if (mbi.State == MEM_COMMIT)
        {
            const bool isExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                                      PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));

            if (isExecutable)
            {
                // 【优化】统一模块检查，避免DetectHiddenModule内部重复调用
                HMODULE hMod = nullptr;
                BOOL inModule = GetModuleHandleExW(
                    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                    (LPCWSTR)mbi.BaseAddress, &hMod);

                DWORD lastError = GetLastError();
                bool belongsToModule = (inModule && hMod != nullptr);

                // 只对不在模块中的可执行内存进行深度检测
                if (!belongsToModule && (lastError == ERROR_MOD_NOT_FOUND || lastError == ERROR_INVALID_ADDRESS))
                {
                    // A. 检测隐藏模块（大尺寸或包含MZ头）
                    DetectHiddenModule(context, mbi);

                    // B. 检测私有可执行内存（RWX权限）
                    if (mbi.Type == MEM_PRIVATE)
                    {
                        DetectPrivateExecutableMemory(context, mbi);
                    }

                    // C. 【新增】检测内存映射文件（反序列化攻击、FileLess恶意代码）
                    if (mbi.Type == MEM_MAPPED)
                    {
                        DetectMappedExecutableMemory(context, mbi);
                    }
                }
            }
        }
    }

    // 如果发生超时，直接返回失败
    if (timeoutOccurred)
    {
        return SensorExecutionResult::FAILURE;
    }

    // 统一的执行结果判断逻辑
    // 成功条件：没有失败原因记录（包括超时）
    if (m_lastFailureReason != anti_cheat::UNKNOWN_FAILURE)
    {
        return SensorExecutionResult::FAILURE;
    }

    return SensorExecutionResult::SUCCESS;
}

void MemorySecuritySensor::DetectHiddenModule(SensorRuntimeContext &context, const MEMORY_BASIC_INFORMATION &mbi)
{
    uintptr_t baseAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    SIZE_T regionSize = mbi.RegionSize;

    const uint32_t minRegionSize = CheatConfigManager::GetInstance().GetMinMemoryRegionSize();
    const uint32_t maxRegionSize = CheatConfigManager::GetInstance().GetMaxMemoryRegionSize();

    // 过滤掉过小或超大的区域
    if (baseAddr < 0x200000 || regionSize < minRegionSize || regionSize > maxRegionSize)
    {
        return;
    }

    // 检查是否包含PE头（MZ标识）
    auto peCheckResult = CheckHiddenMemoryRegion(mbi.BaseAddress, regionSize);
    if (peCheckResult.shouldReport)
    {
        std::ostringstream oss;
        if (peCheckResult.accessible)
        {
            oss << "检测到隐藏的可执行模块 (MZ头): 0x" << std::hex << baseAddr
                << " 大小: " << std::dec << regionSize << " 字节";
        }
        else
        {
            oss << "检测到隐藏的可执行模块 (不可读): 0x" << std::hex << baseAddr
                << " 大小: " << std::dec << regionSize << " 字节";
        }
        context.AddEvidence(anti_cheat::INTEGRITY_MEMORY_PATCH, oss.str());
    }
}

void MemorySecuritySensor::DetectMappedExecutableMemory(SensorRuntimeContext &context, const MEMORY_BASIC_INFORMATION &mbi)
{
    const uint32_t minRegionSize = CheatConfigManager::GetInstance().GetMinMemoryRegionSize();
    const uint32_t maxRegionSize = CheatConfigManager::GetInstance().GetMaxMemoryRegionSize();

    if (mbi.RegionSize < minRegionSize || mbi.RegionSize > maxRegionSize)
    {
        return;
    }

    const uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    const bool isRWX = (mbi.Protect & PAGE_EXECUTE_READWRITE) || (mbi.Protect & PAGE_EXECUTE_WRITECOPY);

    // MEM_MAPPED + RWX = 高度可疑（FileLess攻击常用手法）
    if (isRWX)
    {
        std::ostringstream oss;
        oss << "检测到可疑的内存映射可执行区域 (RWX). 地址: 0x" << std::hex << base
            << ", 大小: " << std::dec << mbi.RegionSize << " 字节";
        context.AddEvidence(anti_cheat::RUNTIME_MEMORY_EXEC_MAPPED, oss.str());
    }
}

void MemorySecuritySensor::DetectPrivateExecutableMemory(SensorRuntimeContext &context, const MEMORY_BASIC_INFORMATION &mbi)
{
    // 使用配置化的检测阈值
    const uint32_t minRegionSize = CheatConfigManager::GetInstance().GetMinMemoryRegionSize();
    const uint32_t maxRegionSize = CheatConfigManager::GetInstance().GetMaxMemoryRegionSize();

    // 【专家级降噪策略】：基于大量误报分析，RX-only内存通常来自合法来源：
    // - JIT编译器 (.NET CLR, V8/Chromium, Lua JIT等)
    // - 系统trampolines/thunks (DEP, COM, ATL)
    // - 覆盖层软件 (Steam, Discord, 录屏软件)
    // - 显卡驱动的shader编译器
    // 真正的外挂通常需要RWX权限（可写可执行）来动态修改代码
    const bool isRWX = IsRwXProtection(mbi.Protect);
    const bool isRXOnly = IsRxOnlyProtection(mbi.Protect);

    // 【核心策略】：完全忽略RX-only内存，只检测RWX内存
    // RWX是真正危险的权限组合，合法软件极少使用
    if (isRXOnly)
    {
        return;  // 跳过所有RX-only内存，避免海量误报
    }

    if (mbi.RegionSize >= minRegionSize && mbi.RegionSize <= maxRegionSize)
    {
        if (!context.IsAddressInLegitimateModule(mbi.BaseAddress))
        {
            if (IsRegionInUnifiedWhitelist(mbi.BaseAddress, context))
            {
                return;
            }

            const uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);

            // 【高级降噪】：过滤低地址小块 RWX 内存（系统 trampolines/DEP）
            // Windows DEP 机制和系统 thunks 常在低地址（< 2MB）分配单页或多页的 RWX
            // 真正的外挂通常在高地址分配较大区域
            if (ShouldSkipLowAddressSmallRwx(base, mbi.RegionSize))
            {
                // 低地址小块 RWX，很可能是系统合法分配，跳过
                LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                            "跳过低地址小块RWX内存 (系统trampolines): 0x%zx, 大小=%zu", base, mbi.RegionSize);
                return;
            }

            // 【进一步降噪】：检查初始分配保护（AllocationProtect）
            // 如果区域最初分配时就是可执行的，通常是合法的（如 JIT 编译器）
            // 可疑的外挂通常会先分配 RW，再通过 VirtualProtect 改为 RWX
            if (mbi.AllocationProtect &
                (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
            {
                // 初始分配时就包含执行权限，认为是合法用途
                LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                            "跳过初始即可执行的RWX内存 (合法JIT/系统): 0x%zx, AllocationProtect=0x%X", base,
                            mbi.AllocationProtect);
                return;
            }

            // 二次确认：仅在"线程起点异常/模块签名异常"二次信号成立时升级
            if (!HasSecondaryConfirmation(context, mbi))
            {
                LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                            "跳过RWX区域上报（未满足二次确认）: 0x%zx, 大小=%zu", base, mbi.RegionSize);
                return;
            }

            // 只有RWX内存且通过白名单与二次确认过滤才会到达这里
            std::ostringstream oss;

            // 进一步检查是否包含PE头，区分Shellcode和手动映射模块
            auto peCheck = CheckHiddenMemoryRegion(mbi.BaseAddress, mbi.RegionSize);
            if (peCheck.shouldReport && peCheck.accessible)
            {
                oss << "检测到手动映射的可执行模块 (RWX+PE头). 地址: 0x" << std::hex << base;
                // 使用更准确的分类
                context.AddEvidence(anti_cheat::MODULE_UNTRUSTED_DYNAMIC_LOAD, oss.str());
                return;
            }

            oss << "检测到RWX私有可执行内存 (极度可疑). 地址: 0x" << std::hex << base << ", 大小: " << std::dec
                << mbi.RegionSize << " 字节, 权限: ";

            // 记录具体权限
            if (mbi.Protect & PAGE_EXECUTE_READWRITE)
                oss << "PAGE_EXECUTE_READWRITE";
            else if (mbi.Protect & PAGE_EXECUTE_WRITECOPY)
                oss << "PAGE_EXECUTE_WRITECOPY";

            oss << ", 初始分配保护: 0x" << std::hex << mbi.AllocationProtect;

            context.AddEvidence(anti_cheat::RUNTIME_MEMORY_EXEC_PRIVATE, oss.str());
        }
    }
}

bool MemorySecuritySensor::IsRegionInUnifiedWhitelist(PVOID baseAddress, SensorRuntimeContext &context) const
{
    HMODULE hMod = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(baseAddress), &hMod) ||
        !hMod)
    {
        return false;
    }

    wchar_t modulePath[MAX_PATH] = {0};
    if (GetModuleFileNameW(hMod, modulePath, MAX_PATH) == 0)
    {
        return false;
    }

    std::wstring normalized = modulePath;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), ::towlower);
    if (Utils::IsWhitelistedModule(normalized))
    {
        return true;
    }

    auto ignoreList = context.GetWhitelistedIntegrityIgnoreList();
    if (ignoreList)
    {
        const std::wstring name = Utils::GetFileName(normalized);
        if (ignoreList->count(name) > 0)
        {
            return true;
        }
    }
    return false;
}

bool MemorySecuritySensor::HasSecondaryConfirmation(SensorRuntimeContext &context, const MEMORY_BASIC_INFORMATION &mbi) const
{
    if (HasThreadStartInRegion(mbi))
    {
        return true;
    }

    HMODULE hMod = nullptr;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(mbi.BaseAddress), &hMod) &&
        hMod)
    {
        wchar_t modulePath[MAX_PATH] = {0};
        if (GetModuleFileNameW(hMod, modulePath, MAX_PATH) > 0)
        {
            if (!Utils::IsWhitelistedModule(modulePath))
            {
                Utils::SignatureStatus sig = Utils::VerifyFileSignature(modulePath, context.GetWindowsVersion());
                if (sig == Utils::SignatureStatus::UNTRUSTED)
                {
                    return true;
                }
            }
        }
    }
    return false;
}

bool MemorySecuritySensor::HasThreadStartInRegion(const MEMORY_BASIC_INFORMATION &mbi) const
{
    const uintptr_t regionStart = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
    const uintptr_t regionEnd = regionStart + mbi.RegionSize;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    const DWORD currentPid = GetCurrentProcessId();
    THREADENTRY32 te = {};
    te.dwSize = sizeof(te);
    bool hit = false;

    if (Thread32First(hSnapshot, &te))
    {
        do
        {
            if (te.th32OwnerProcessID != currentPid)
            {
                continue;
            }

            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (!hThread)
            {
                continue;
            }

            PVOID startAddress = nullptr;
            if (SystemUtils::g_pNtQueryInformationThread &&
                NT_SUCCESS(SystemUtils::g_pNtQueryInformationThread(
                        hThread, (THREADINFOCLASS)9, &startAddress, sizeof(startAddress), nullptr)) &&
                startAddress)
            {
                const uintptr_t addr = reinterpret_cast<uintptr_t>(startAddress);
                if (addr >= regionStart && addr < regionEnd)
                {
                    hit = true;
                }
            }
            CloseHandle(hThread);
            if (hit)
            {
                break;
            }
        } while (Thread32Next(hSnapshot, &te));
    }

    CloseHandle(hSnapshot);
    return hit;
}

bool MemorySecuritySensor::IsKnownSafeRegion(uintptr_t baseAddr, SIZE_T regionSize)
{
    // 跳过系统保留区域
    if (baseAddr < 0x10000)
        return true;  // 64KB以下

    // 跳过大内存池（通常由内存分配器管理）
    if (regionSize > CheatConfigManager::GetInstance().GetMaxMemoryRegionSize())
        return true;  // 超过配置的最大内存区域大小

    // 跳过特定地址范围（根据系统特性调整）
    if (baseAddr >= 0x7FFE0000 && baseAddr < 0x7FFF0000)
        return true;  // 系统保留

    return false;
}

MemorySecuritySensor::HiddenMemoryCheckResult MemorySecuritySensor::CheckHiddenMemoryRegion(PVOID baseAddress, SIZE_T regionSize)
{
    HiddenMemoryCheckResult result;

    // 配置的最小尺寸检查
    if (regionSize < CheatConfigManager::GetInstance().GetMinMemoryRegionSize())
    {
        return result;
    }

    // 使用 ReadProcessMemory 安全读取内存
    // 读取至少 1024 字节以包含DOS头和部分NT头
    std::vector<BYTE> headerBuffer(1024);
    SIZE_T bytesRead = 0;
    HANDLE hProcess = GetCurrentProcess();

    if (ReadProcessMemory(hProcess, baseAddress, headerBuffer.data(), headerBuffer.size(), &bytesRead) &&
        bytesRead >= sizeof(IMAGE_DOS_HEADER))
    {
        result.accessible = true;

        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)headerBuffer.data();
        bool hasDos = (pDos->e_magic == IMAGE_DOS_SIGNATURE);
        bool hasNt = false;

        if (hasDos && pDos->e_lfanew > 0 && pDos->e_lfanew < (LONG)bytesRead - (LONG)sizeof(IMAGE_NT_HEADERS))
        {
            PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(headerBuffer.data() + pDos->e_lfanew);
            if (pNt->Signature == IMAGE_NT_SIGNATURE)
            {
                hasNt = true;
            }
        }

        // Eraser PE Header Check: Scan for NT header if DOS header is missing or broken
        if (!hasNt)
        {
            // Align scan to 4 bytes for performance
            for (size_t i = 0; i < bytesRead - sizeof(IMAGE_NT_HEADERS); i += 4)
            {
                PIMAGE_NT_HEADERS pPotentialNt = (PIMAGE_NT_HEADERS)(headerBuffer.data() + i);
                if (pPotentialNt->Signature == IMAGE_NT_SIGNATURE)
                {
                    // Verify Machine type to reduce false positives
#ifdef _WIN64
                    if (pPotentialNt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
#else
                    if (pPotentialNt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386)
#endif
                    {
                        hasNt = true;
                        break;
                    }
                }
            }
        }

        if (hasNt)
        {
            // 确认检测到隐藏模块
            result.shouldReport = true;
        }
    }
    else
    {
        // 读取内存失败，可能是 PAGE_NOACCESS / PAGE_GUARD
        result.accessible = false;
        // 读取失败且是可执行区域，非常可疑（恶意隐藏）
        result.shouldReport = true;

        this->RecordFailure(anti_cheat::MEMORY_ACCESS_EXCEPTION);
    }

    return result;
}
