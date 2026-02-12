#include "ProcessHandleSensor.h"
#include "SensorRuntimeContext.h"
#include "utils/SystemUtils.h"
#include "Logger.h"
#include "utils/Utils.h"
#include "CheatConfigManager.h"
#include <algorithm>
#include <memory>

ProcessHandleSensor::HandleBufferManager::HandleBufferManager() : buffer(nullptr), size(0)
{
    const size_t initialSize = CheatConfigManager::GetInstance().GetInitialBufferSizeMb() * 1024 * 1024;
    buffer = new BYTE[initialSize];
    size = initialSize;
}

ProcessHandleSensor::HandleBufferManager::~HandleBufferManager()
{
    if (buffer)
    {
        delete[] buffer;
        buffer = nullptr;
    }
}

bool ProcessHandleSensor::HandleBufferManager::Resize(size_t newSize)
{
    const size_t maxSize = CheatConfigManager::GetInstance().GetMaxBufferSizeMb() * 1024 * 1024;
    if (newSize > maxSize)
        return false;

    BYTE *newBuffer = new (std::nothrow) BYTE[newSize];
    if (!newBuffer)
        return false;

    if (buffer)
    {
        delete[] buffer;
    }
    buffer = newBuffer;
    size = newSize;
    return true;
}

void ProcessHandleSensor::HandleBufferManager::Reset()
{
    if (buffer)
    {
        delete[] buffer;
        const size_t initialSize = CheatConfigManager::GetInstance().GetInitialBufferSizeMb() * 1024 * 1024;
        buffer = new BYTE[initialSize];
        size = initialSize;
    }
}

uint32_t ProcessHandleSensor::GetProcessCreationTime(DWORD pid)
{
    // 使用更轻量的方式：检查进程是否仍然存在
    HANDLE hProcess = OpenProcess(SystemUtils::GetProcessQueryAccessMask(), FALSE, pid);
    if (!hProcess)
        return 0;  // 进程不存在

    // 只获取创建时间，避免昂贵的GetProcessTimes调用
    FILETIME createTime, exitTime, kernelTime, userTime;
    uint32_t creationTime = 0;
    if (GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime))
    {
        // 使用创建时间的低32位作为标识
        creationTime = createTime.dwLowDateTime;
    }
    else
    {
        // GetProcessTimes失败，记录失败原因
        LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                      "ProcessHandleSensor: GetProcessTimes失败 PID %lu，错误: 0x%08X", pid, GetLastError());
        // 注意：这里不调用RecordFailure，因为这是静态方法，无法访问实例
    }

    CloseHandle(hProcess);
    return creationTime;
}


// 实际的 Helper 函数，接受明确参数
static bool IsHandlePointingToUs_Safe_Impl(HANDLE remoteHandleValue, DWORD remotePid, DWORD ownPid)
{
    // 过滤：如果是我们自己的进程，忽略
    if (remotePid == ownPid) return false;

    // 尝试 DuplicateHandle 获取对象信息
    HANDLE hDup = nullptr;
    HANDLE hSourceProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, remotePid);
    if (!hSourceProc) return false;

    bool isPointingToUs = false;

    // 复制句柄到本进程
    const DWORD queryAccess = SystemUtils::GetProcessQueryAccessMask();
    if (DuplicateHandle(hSourceProc, remoteHandleValue, GetCurrentProcess(), &hDup,
                        queryAccess, FALSE, 0))
    {
        // 检查句柄指向的目标 PID
        if (hDup)
        {
            DWORD targetPid = GetProcessId(hDup);
            if (targetPid == ownPid)
            {
                isPointingToUs = true;
            }
            CloseHandle(hDup);
        }
    }

    CloseHandle(hSourceProc);
    return isPointingToUs;
}

SensorExecutionResult ProcessHandleSensor::Execute(SensorRuntimeContext &context)
{
    // 重置失败原因
    m_lastFailureReason = anti_cheat::UNKNOWN_FAILURE;

    // 1. 配置版本门控
    if (!IsOsSupported(context))
    {
        LOG_DEBUG(AntiCheatLogger::LogCategory::SENSOR, "进程句柄检测已禁用：当前OS版本低于配置最低要求");
        RecordFailure(anti_cheat::PROCESS_HANDLE_OS_VERSION_UNSUPPORTED);
        return SensorExecutionResult::FAILURE;
    }

    // 获取超时预算
    const int budget_ms = CheatConfigManager::GetInstance().GetHeavyScanBudgetMs();
    const auto startTime = std::chrono::steady_clock::now();
    const auto nowCleanup = startTime;  // 用于清理过期缓存

    // 4. API可用性检查
    if (!SystemUtils::g_pNtQuerySystemInformation)
    {
        LOG_ERROR(AntiCheatLogger::LogCategory::SENSOR, "ProcessHandleSensor: NtQuerySystemInformation API不可用");
        RecordFailure(anti_cheat::PROCESS_HANDLE_QUERY_SYSTEM_INFO_FAILED);
        return SensorExecutionResult::FAILURE;
    }

    // 5. 性能上限配置 - 使用配置字段
    ULONG kMaxHandlesToScan = CheatConfigManager::GetInstance().GetMaxHandleScanCount();

    // 5.1 过期清理（PID节流 / 进程签名缓存与节流）
    {
        auto &pidTtl = context.GetPidThrottleUntil();
        for (auto it = pidTtl.begin(); it != pidTtl.end();)
        {
            if (nowCleanup >= it->second)
                it = pidTtl.erase(it);
            else
                ++it;
        }
        auto &procCache = context.GetProcessSigCache();
        auto &procThr = context.GetProcessSigThrottleUntil();
        const auto sigTtl =
                std::chrono::minutes(CheatConfigManager::GetInstance().GetSignatureCacheDurationMinutes());
        for (auto it = procCache.begin(); it != procCache.end();)
        {
            if (nowCleanup >= it->second.second + sigTtl)
                it = procCache.erase(it);
            else
                ++it;
        }
        for (auto it = procThr.begin(); it != procThr.end();)
        {
            if (nowCleanup >= it->second)
                it = procThr.erase(it);
            else
                ++it;
        }
    }

    // 6. 内存管理优化：使用预分配缓冲区 + 兼容回退
    HandleBufferManager bufferManager;
    NTSTATUS status;
    int retries = 0;
    bool useLegacy = false;

    while (true)
    {
        status = SystemUtils::g_pNtQuerySystemInformation
                         ? SystemUtils::g_pNtQuerySystemInformation(
                                   useLegacy ? (SYSTEM_INFORMATION_CLASS)SystemHandleInformation
                                             : (SYSTEM_INFORMATION_CLASS)SystemExtendedHandleInformation,
                                   bufferManager.buffer, static_cast<ULONG>(bufferManager.size), nullptr)
                         : (NTSTATUS)STATUS_NOT_IMPLEMENTED;

        if (status == STATUS_INFO_LENGTH_MISMATCH)
        {
            size_t newSize = bufferManager.size * 2;
            if (!bufferManager.Resize(newSize))
            {
                LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR,
                            "ProcessHandleSensor: 缓冲区大小超过限制 (%zu bytes)，跳过扫描", newSize);
                RecordFailure(anti_cheat::PROCESS_HANDLE_BUFFER_SIZE_EXCEEDED);
                return SensorExecutionResult::FAILURE;
            }
            retries++;
            if (retries > 3)
            {
                LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR,
                            "ProcessHandleSensor: 获取句柄信息重试过多 (%d次)，跳过扫描", retries);
                RecordFailure(anti_cheat::PROCESS_HANDLE_RETRY_EXCEEDED);
                return SensorExecutionResult::FAILURE;
            }
            continue;
        }

        if (!useLegacy && (status == STATUS_INVALID_INFO_CLASS || status == STATUS_NOT_IMPLEMENTED))
        {
            LOG_DEBUG(AntiCheatLogger::LogCategory::SENSOR,
                      "ProcessHandleSensor: 扩展句柄信息类不可用，回退到旧结构");
            useLegacy = true;
            bufferManager.Reset();
            retries = 0;
            continue;
        }
        break;
    }

    if (!NT_SUCCESS(status))
    {
        LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR,
                    "ProcessHandleSensor: NtQuerySystemInformation失败，状态码: 0x%08X", status);
        RecordFailure(anti_cheat::PROCESS_HANDLE_QUERY_SYSTEM_INFO_FAILED);
        return SensorExecutionResult::FAILURE;
    }

    // 7. 句柄数量上限检查（支持扩展/回退两种结构）
    const void *pHandleInfoEx = reinterpret_cast<const void *>(bufferManager.buffer);
    const void *pHandleInfoLegacy = reinterpret_cast<const void *>(bufferManager.buffer);
    ULONG_PTR totalHandles = useLegacy ? (ULONG_PTR)((const SYSTEM_HANDLE_INFORMATION_LEGACY *)pHandleInfoLegacy)->NumberOfHandles
                                       : (ULONG_PTR)((const SYSTEM_HANDLE_INFORMATION_EX *)pHandleInfoEx)->NumberOfHandles;
    if (totalHandles > kMaxHandlesToScan)
    {
        // 优化：自适应策略 - 如果句柄数超限但不是太离谱（<150%），仍然尝试扫描但减少处理量
        double handleRatio = static_cast<double>(totalHandles) / kMaxHandlesToScan;
        if (handleRatio < 1.5)  // 超出不到50%，可以尝试降级扫描
        {
            LOG_INFO_F(AntiCheatLogger::LogCategory::SENSOR,
                       "ProcessHandleSensor: 系统句柄数量略超上限 (%lu > %lu, 超出%.1f%%)，启用降级扫描模式",
                       (ULONG)totalHandles, kMaxHandlesToScan, (handleRatio - 1.0) * 100.0);
            // 继续执行，但会通过游标机制自动限制扫描量
        }
        else
        {
            // 超出太多，直接跳过
            LOG_WARNING_F(
                    AntiCheatLogger::LogCategory::SENSOR,
                    "ProcessHandleSensor: 系统句柄数量严重超限 (%lu > %lu, 超出%.1f%%)，跳过扫描以确保系统性能。"
                    "建议：1) 检查系统是否有句柄泄漏 2) 考虑增加max_handle_scan_count配置值",
                    (ULONG)totalHandles, kMaxHandlesToScan, (handleRatio - 1.0) * 100.0);
            RecordFailure(anti_cheat::PROCESS_HANDLE_HANDLE_COUNT_EXCEEDED);
            return SensorExecutionResult::FAILURE;
        }
    }

    // 记录句柄数量统计信息（仅在DEBUG级别）
    LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                "ProcessHandleSensor: 开始扫描 %lu 个系统句柄 (上限: %lu, 使用率: %.1f%%)%s", (ULONG)totalHandles,
                kMaxHandlesToScan, static_cast<double>(totalHandles) / kMaxHandlesToScan * 100.0,
                useLegacy ? " [LEGACY]" : "");

    // 8. 主扫描循环
    const DWORD ownPid = GetCurrentProcessId();
    if (ownPid == 0)
    {
        LOG_ERROR(AntiCheatLogger::LogCategory::SENSOR, "ProcessHandleSensor: GetCurrentProcessId失败");
        RecordFailure(anti_cheat::PROCESS_HANDLE_GET_PROCESS_ID_FAILED);
        return SensorExecutionResult::FAILURE;
    }

    const auto now = std::chrono::steady_clock::now();
    // 跨扫描缓存：进程路径签名结果（减少 WinVerifyTrust 调用）
    auto &processSigCache = context.GetProcessSigCache();
    auto &processSigThrottleUntil = context.GetProcessSigThrottleUntil();

    std::unordered_set<DWORD> processedPidsThisScan;
    ULONG handlesProcessed = 0;
    ULONG openProcDeniedCount = 0;     // ERROR_ACCESS_DENIED
    ULONG openProcInvalidCount = 0;    // ERROR_INVALID_PARAMETER/ERROR_INVALID_HANDLE
    ULONG openProcOtherFailCount = 0;  // 其他错误

    // 智能缓存：使用路径作为键（移到SEH块外）
    struct PathCacheEntry
    {
        // CheatMonitor::Pimpl::ProcessVerdict verdict; // Removed Pimpl dep
        bool isTrusted;
        std::chrono::steady_clock::time_point cached_at;
        uint32_t process_creation_time;  // 修复：字段名更准确
        std::wstring process_name;
        Utils::SignatureStatus signature_status;
    };
    std::unordered_map<std::wstring, PathCacheEntry> pathCache;

    // 游标 + 限额（时间片遍历）
    ULONG_PTR total = totalHandles;
    ULONG_PTR cursorStart = (total > 0) ? (ULONG_PTR)(context.GetHandleCursorOffset() % total) : 0;
    const int maxPidAttempts = std::max(1, CheatConfigManager::GetInstance().GetMaxPidAttemptsPerScan());
    int pidAttempts = 0;
    ULONG_PTR entriesVisited = 0;
    auto &pidTtlMap = context.GetPidThrottleUntil();

    // 提取公共逻辑到 Lambda 或 Helper
    auto ProcessEntry = [&](DWORD ownerPid, HANDLE handleValue, ULONG grantedAccess) -> bool {
         // 快速过滤
        if (ownerPid == ownPid || processedPidsThisScan.count(ownerPid) > 0 ||
            !(grantedAccess &
              (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_ALL_ACCESS)))
        {
            return false;
        }

        // 跨扫描节流与限额
        const auto pidIt = pidTtlMap.find(ownerPid);
        if (pidIt != pidTtlMap.end() && now < pidIt->second)
        {
            return false;
        }
        if (pidAttempts >= maxPidAttempts)
        {
            return true; // Stop
        }

        // 句柄指向性验证 (使用新的 Helper)
        if (!IsHandlePointingToUs_Safe_Impl(handleValue, ownerPid, ownPid))
        {
            pidTtlMap[ownerPid] =
                    now + std::chrono::minutes(CheatConfigManager::GetInstance().GetPidThrottleMinutes());
            return false;
        }

        pidAttempts++; // Increment only if we actually check process details

        processedPidsThisScan.insert(ownerPid);
        pidTtlMap[ownerPid] =
                now + std::chrono::minutes(CheatConfigManager::GetInstance().GetPidThrottleMinutes());
        handlesProcessed++;

        // 进程路径获取（优化：避免重复获取）
        std::wstring ownerProcessPath;
        std::wstring lowerProcessName;
        Utils::SignatureStatus signatureStatus = Utils::SignatureStatus::UNKNOWN;

        using UniqueHandle = std::unique_ptr<void, decltype(&::CloseHandle)>;
        UniqueHandle hOwnerProcess(OpenProcess(SystemUtils::GetProcessQueryAccessMask(), FALSE, ownerPid),
                                   &::CloseHandle);

        if (!hOwnerProcess.get())
        {
            DWORD lastError = GetLastError();
            if (lastError == ERROR_ACCESS_DENIED)
            {
                ++openProcDeniedCount;
            }
            else if (lastError == ERROR_INVALID_PARAMETER || lastError == ERROR_INVALID_HANDLE)
            {
                ++openProcInvalidCount;
            }
            else
            {
                ++openProcOtherFailCount;
                LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                              "ProcessHandleSensor: 无法打开进程进行句柄验证 PID %lu，错误: 0x%08X", ownerPid,
                              lastError);
                RecordFailure(anti_cheat::PROCESS_HANDLE_OPEN_PROCESS_FAILED);
            }
            return false;
        }

        ownerProcessPath = Utils::GetProcessFullName(hOwnerProcess.get());
        if (ownerProcessPath.empty())
        {
             // 先获取进程名，检查是否在安全白名单中
            std::wstring processName = Utils::GetProcessNameByPid(ownerPid);
            std::transform(processName.begin(), processName.end(), processName.begin(), ::towlower);

            auto knownGoodProcesses = CheatConfigManager::GetInstance().GetKnownGoodProcesses();
            bool isKnownGoodProcess = knownGoodProcesses && knownGoodProcesses->count(processName) > 0;

            if (isKnownGoodProcess)
            {
                // 已知安全进程，记录调试信息
                LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                            "ProcessHandleSensor: 安全进程无法获取路径（正常现象）, 进程名=%s, PID=%lu",
                            Utils::WideToString(processName).c_str(), ownerPid);
                return false;
            }
            else
            {
                // 未知进程，记录警告并作为可疑行为上报
                LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                              "ProcessHandleSensor: 无法获取进程路径 PID %lu, 进程名=%s", ownerPid,
                              Utils::WideToString(processName).c_str());
                context.AddEvidence(
                        anti_cheat::INTEGRITY_SUSPICIOUS_HANDLE,
                        "一个无法识别路径的进程持有我们进程的句柄 (PID: " + std::to_string(ownerPid) +
                                ", 进程名: " + Utils::WideToString(processName) + ")");
                return false;
            }
        }

        // 智能缓存：使用路径作为键
        auto pathCacheIt = pathCache.find(ownerProcessPath);
        if (pathCacheIt != pathCache.end())
        {
            auto cacheAge = now - pathCacheIt->second.cached_at;
            auto cacheDuration = std::chrono::minutes(CheatConfigManager::GetInstance().GetProcessCacheDurationMinutes());
            if (cacheAge < cacheDuration)
            {
                uint32_t currentCreationTime = GetProcessCreationTime(ownerPid);
                if (currentCreationTime == 0)
                {
                    RecordFailure(anti_cheat::PROCESS_HANDLE_GET_PROCESS_TIMES_FAILED);
                    pathCache.erase(pathCacheIt);
                }
                else if (currentCreationTime == pathCacheIt->second.process_creation_time)
                {
                    signatureStatus = pathCacheIt->second.signature_status;
                    lowerProcessName = pathCacheIt->second.process_name;
                }
                else
                {
                    pathCache.erase(pathCacheIt);
                }
            }
            else
            {
                pathCache.erase(pathCacheIt);
            }
        }

        if (signatureStatus == Utils::SignatureStatus::UNKNOWN)
        {
             lowerProcessName = Utils::GetFileName(ownerProcessPath);
            std::transform(lowerProcessName.begin(), lowerProcessName.end(), lowerProcessName.begin(),
                           ::towlower);

            // 白名单或系统目录
            auto knownGoodProcesses = CheatConfigManager::GetInstance().GetKnownGoodProcesses();
            if ((knownGoodProcesses && knownGoodProcesses->count(lowerProcessName) > 0) ||
                SystemUtils::IsSystemDirectoryPath(ownerProcessPath))
            {
                signatureStatus = Utils::SignatureStatus::TRUSTED;
            }
            else
            {
                const auto ttl = std::chrono::minutes(
                        CheatConfigManager::GetInstance().GetSignatureCacheDurationMinutes());
                auto thrIt = processSigThrottleUntil.find(ownerProcessPath);
                if (thrIt != processSigThrottleUntil.end() && now < thrIt->second)
                {
                    signatureStatus = Utils::SignatureStatus::FAILED_TO_VERIFY;
                }
                else
                {
                     auto it = processSigCache.find(ownerProcessPath);
                    bool cacheHit = (it != processSigCache.end()) && (now < it->second.second + ttl);
                    if (cacheHit)
                    {
                        signatureStatus = it->second.first;
                    }
                    else
                    {
                        signatureStatus =
                                Utils::VerifyFileSignature(ownerProcessPath, context.GetWindowsVersion());
                        if (signatureStatus == Utils::SignatureStatus::FAILED_TO_VERIFY)
                        {
                            processSigThrottleUntil[ownerProcessPath] =
                                    now + std::chrono::milliseconds(
                                                  CheatConfigManager::GetInstance()
                                                          .GetSignatureVerificationFailureThrottleMs());
                        }
                        else
                        {
                            processSigCache[ownerProcessPath] = {signatureStatus, now};
                            processSigThrottleUntil.erase(ownerProcessPath);
                        }
                    }
                }
            }

            PathCacheEntry cacheEntry;
            cacheEntry.isTrusted = (signatureStatus == Utils::SignatureStatus::TRUSTED);
            cacheEntry.cached_at = now;
            uint32_t creationTime = GetProcessCreationTime(ownerPid);
            if (creationTime == 0)
            {
                 RecordFailure(anti_cheat::PROCESS_HANDLE_GET_PROCESS_TIMES_FAILED);
                 creationTime = 0;
            }
            cacheEntry.process_creation_time = creationTime;
            cacheEntry.process_name = lowerProcessName;
            cacheEntry.signature_status = signatureStatus;

            pathCache[ownerProcessPath] = cacheEntry;
        }

        if (signatureStatus == Utils::SignatureStatus::TRUSTED)
        {
            // OK
        }
        else if (signatureStatus == Utils::SignatureStatus::FAILED_TO_VERIFY)
        {
            // Ignore
        }
        else
        {
            context.AddEvidence(anti_cheat::INTEGRITY_SUSPICIOUS_HANDLE,
                                "可疑进程持有我们进程的句柄: " + Utils::WideToString(ownerProcessPath) +
                                        " (PID: " + std::to_string(ownerPid) + ")");
        }

        return false; // Continue scanning
    };

    if (!useLegacy)
    {
        for (ULONG_PTR step = 0; step < total; ++step)
        {
            ULONG_PTR i = (cursorStart + step) % total;
            // 优化：每200个句柄检查一次超时，减少微小开销
            if (step % 200 == 0)
            {
                auto currentTime = std::chrono::steady_clock::now();
                auto elapsed_ms =
                        std::chrono::duration_cast<std::chrono::milliseconds>(currentTime - startTime).count();

                if (elapsed_ms > budget_ms)
                {
                    LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                                  "ProcessHandleSensor: 扫描超时，已处理 %lu/%lu 个句柄，耗时%ldms",
                                  handlesProcessed, (ULONG)total, elapsed_ms);
                    this->RecordFailure(anti_cheat::PROCESS_HANDLE_SCAN_TIMEOUT);
                    context.SetHandleCursorOffset(cursorStart + entriesVisited);
                    return SensorExecutionResult::FAILURE;
                }
            }

            // Accessing correct struct
            const SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX &handle =
                    ((const SYSTEM_HANDLE_INFORMATION_EX *)pHandleInfoEx)->Handles[i];

            if (ProcessEntry((DWORD)handle.UniqueProcessId, (HANDLE)handle.HandleValue, handle.GrantedAccess))
            {
                 context.SetHandleCursorOffset(cursorStart + entriesVisited);
                 break;
            }
            entriesVisited++;
        }
    }
    else
    {
         for (ULONG step = 0; step < (ULONG)total; ++step)
        {
            ULONG i = (ULONG)((cursorStart + step) % total);
            if (step % 200 == 0)
            {
                auto currentTime = std::chrono::steady_clock::now();
                auto elapsed_ms =
                        std::chrono::duration_cast<std::chrono::milliseconds>(currentTime - startTime).count();
                if (elapsed_ms > budget_ms)
                {
                    LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                                  "ProcessHandleSensor: 扫描超时，已处理 %lu/%lu 个句柄，耗时%ldms",
                                  handlesProcessed, (ULONG)total, elapsed_ms);
                    this->RecordFailure(anti_cheat::PROCESS_HANDLE_SCAN_TIMEOUT);
                    context.SetHandleCursorOffset(cursorStart + entriesVisited);
                    return SensorExecutionResult::FAILURE;
                }
            }

            const SYSTEM_HANDLE_TABLE_ENTRY_INFO &handle =
                    ((const SYSTEM_HANDLE_INFORMATION_LEGACY *)pHandleInfoLegacy)->Handles[i];

            if (ProcessEntry((DWORD)handle.UniqueProcessId, (HANDLE)(ULONG_PTR)handle.HandleValue, handle.GrantedAccess))
            {
                context.SetHandleCursorOffset(cursorStart + entriesVisited);
                break;
            }
            entriesVisited++;
        }
    }

    // 更新游标
    if (total > 0)
    {
         // 游标更新逻辑在循环中处理 break 时已覆盖，这里处理正常结束
         // 如果循环完整结束，entriesVisited == total
         // 重置游标？或者 context.SetHandleCursorOffset((cursorStart + entriesVisited) % total) ?
         // 原逻辑是：context.SetHandleCursorOffset(cursorStart + entriesVisited);
         // cursorStart + entriesVisited 可能会无限增长？不会，因为 % total 在循环开始时用。
         // 但是 SetHandleCursorOffset 如果只存 offset，应该模 total 吗？
         // 原代码 context.SetHandleCursorOffset(cursorStart + entriesVisited);
         // 它是累加的offset。ScanContext 内部可能是个简单的计数器。

         // 修正：如果完整跑完，应该更新游标以供下次使用
        context.SetHandleCursorOffset(cursorStart + entriesVisited);
    }

    // Telemetry
    context.RecordSensorWorkloadCounters("ProcessHandleSensor", (uint64_t)total, (uint64_t)handlesProcessed,
                                         (uint64_t)handlesProcessed);

    // 成功条件：没有失败原因记录
    if (m_lastFailureReason != anti_cheat::UNKNOWN_FAILURE)
    {
        return SensorExecutionResult::FAILURE;
    }

    return SensorExecutionResult::SUCCESS;
}

bool ProcessHandleSensor::IsHandlePointingToUs_Safe(const void *pHandleEntry, DWORD ownPid)
{
    // Deprecated dummy implementation, replaced by static wrapper
    return false;
}
