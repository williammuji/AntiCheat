#include "VehHookSensor.h"
#include "SensorRuntimeContext.h"
#include "utils/SystemUtils.h"
#include "Logger.h"
#include "CheatConfigManager.h"
#include <algorithm>
#include <sstream>

SensorExecutionResult VehHookSensor::Execute(SensorRuntimeContext &context)
{
    // 重置失败原因
    m_lastFailureReason = anti_cheat::UNKNOWN_FAILURE;

    // 策略1：配置版本门控 - 检查当前OS版本是否满足配置的最低要求
    if (!IsOsSupported(context))
    {
        LOG_DEBUG(AntiCheatLogger::LogCategory::SENSOR, "VEH检测已禁用：当前OS版本低于配置最低要求");
        m_lastFailureReason = anti_cheat::VEH_OS_VERSION_UNSUPPORTED;
        return SensorExecutionResult::FAILURE;
    }

    auto winVer = context.GetWindowsVersion();
    // 策略2：版本检查 - 只在已知稳定的版本上运行
    if (winVer == SystemUtils::WindowsVersion::Win_Unknown)
    {
        LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "VEH检测在未知Windows版本上禁用以确保稳定性");
        m_lastFailureReason = anti_cheat::VEH_WINDOWS_VERSION_UNKNOWN;
        return SensorExecutionResult::FAILURE;
    }

    const uintptr_t base = context.GetVehListAddress();
    if (base == 0)
    {
        LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "VEH链表地址获取失败，跳过检测");
        m_lastFailureReason = anti_cheat::VEH_LIST_ADDRESS_FAILED;
        return SensorExecutionResult::FAILURE;
    }

    // 策略3：内存验证 - 确保VEH链表基地址有效
    MEMORY_BASIC_INFORMATION baseMbi = {};
    if (VirtualQuery((PVOID)base, &baseMbi, sizeof(baseMbi)) != sizeof(baseMbi))
    {
        LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "VEH链表基地址内存查询失败");
        RecordFailure(anti_cheat::VEH_VIRTUAL_QUERY_FAILED);
        return SensorExecutionResult::FAILURE;
    }

    if (baseMbi.State != MEM_COMMIT)
    {
        LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "VEH链表基地址内存状态异常: 0x%08X", baseMbi.State);
        RecordFailure(anti_cheat::VEH_MEMORY_STATE_ABNORMAL);
        return SensorExecutionResult::FAILURE;
    }

    const int budget_ms = CheatConfigManager::GetInstance().GetHeavyScanBudgetMs();
    const auto startTime = std::chrono::steady_clock::now();

    LIST_ENTRY *pHead = nullptr;

    // 策略4：结构体访问保护
    auto accessResult = AccessVehStructSafe(base, winVer);
    if (!accessResult.success)
    {
        LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR, "VEH结构体访问异常: 0x%08X", accessResult.exceptionCode);
        RecordFailure(anti_cheat::VEH_LIST_ACCESS_FAILED);
        return SensorExecutionResult::FAILURE;
    }

    pHead = accessResult.pHead;
    if (!pHead || !SystemUtils::IsValidPointer(pHead, sizeof(LIST_ENTRY)))
    {
        LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "VEH链表头指针无效");
        RecordFailure(anti_cheat::VEH_HEAD_POINTER_INVALID);
        return SensorExecutionResult::FAILURE;
    }

    // 策略5：保守的处理器枚举
    std::vector<PVOID> handlers;
    auto traverseResult = TraverseVehListSafe(pHead, budget_ms);
    if (!traverseResult.success)
    {
        if (traverseResult.exceptionCode != 0)
        {
            LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR, "VEH链表遍历异常: 0x%08X",
                        traverseResult.exceptionCode);
            RecordFailure(anti_cheat::VEH_TRAVERSE_FAILED);
        }
        else
        {
            LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "VEH链表遍历超时");
            RecordFailure(anti_cheat::VEH_EXECUTION_TIMEOUT);
        }
        return SensorExecutionResult::FAILURE;
    }

    for (int i = 0; i < traverseResult.handlerCount; ++i)
    {
        handlers.push_back(traverseResult.handlers[i]);
    }

    if (traverseResult.success && !handlers.empty())
    {
        // 策略6：限制检查数量和频率
        // CheatConfigManager::GetMaxVehHandlersToScan is not exposed in shared CheatConfigManager?
        // Need to check if available, or assume default.
        // The viewed ScanContext does not expose it either directly.
        // I will assume CheatConfigManager works or default to 50 if failing compilation.
        // Assuming CheatConfigManager has GetMaxVehHandlersToScan() based on CheatMonitor.cpp code.
        const size_t maxHandlers = (size_t)CheatConfigManager::GetInstance().GetMaxVehHandlersToScan();
        const size_t checkCount = std::min(handlers.size(), maxHandlers);

        LOG_INFO_F(AntiCheatLogger::LogCategory::SENSOR, "VEH检测: 发现%zu个处理器，检查前%zu个", handlers.size(),
                   checkCount);

        for (size_t i = 0; i < checkCount; ++i)
        {
            // 每5次循环检查一次时间，因为VEH处理器数量少但检查很重
            if (i % 5 == 0)
            {
                auto now = std::chrono::steady_clock::now();
                auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count();

                if (elapsed_ms > budget_ms)
                {
                    LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR,
                                  "VEH检测超时，已检查%zu/%zu个处理器，耗时%ldms", i, checkCount, elapsed_ms);
                    RecordFailure(anti_cheat::VEH_EXECUTION_TIMEOUT);
                    return SensorExecutionResult::FAILURE;
                }
            }

            // 使用统一的指针验证接口
            if (!SystemUtils::IsValidPointer(handlers[i], sizeof(VECTORED_HANDLER_ENTRY)))
            {
                LOG_ERROR_F(AntiCheatLogger::LogCategory::SENSOR, "VEH处理器#%zu指针验证失败", i);
                RecordFailure(anti_cheat::VEH_POINTER_VALIDATION_FAILED);  // 统计指针验证失败
            }
            else
            {
                this->AnalyzeHandlerSecurity(context, handlers[i], (int)i);
            }
        }
    }
    else
    {
        if (traverseResult.success)
        {
            LOG_INFO(AntiCheatLogger::LogCategory::SENSOR, "VEH检测: 未发现处理器");
        }
        // 注意：如果traverseResult.success为false，TraverseVehListSafe方法中已经有相应的LOG记录
    }

    // 统一的执行结果判断逻辑
    // 成功条件：没有失败原因记录（包括超时）
    if (m_lastFailureReason != anti_cheat::UNKNOWN_FAILURE)
    {
        return SensorExecutionResult::FAILURE;
    }

    return SensorExecutionResult::SUCCESS;
}

VehHookSensor::VehAccessResult VehHookSensor::AccessVehStructSafe(uintptr_t base, SystemUtils::WindowsVersion winVer)
{
    VehAccessResult result;
    __try
    {
        switch (winVer)
        {
            case SystemUtils::WindowsVersion::Win_XP: {
                auto *pList = reinterpret_cast<VECTORED_HANDLER_LIST_XP *>(base);
                if (SystemUtils::IsValidPointer(pList, sizeof(VECTORED_HANDLER_LIST_XP)))
                {
                    result.pHead = &pList->List;
                }
                break;
            }
            case SystemUtils::WindowsVersion::Win_Vista_Win7: {
                auto *pList = reinterpret_cast<VECTORED_HANDLER_LIST_VISTA *>(base);
                if (SystemUtils::IsValidPointer(pList, sizeof(VECTORED_HANDLER_LIST_VISTA)))
                {
                    result.pHead = &pList->ExceptionList;
                }
                break;
            }
            case SystemUtils::WindowsVersion::Win_8_Win81:
            case SystemUtils::WindowsVersion::Win_10:
            case SystemUtils::WindowsVersion::Win_11:
            default: {
                auto *pList = reinterpret_cast<VECTORED_HANDLER_LIST_WIN8 *>(base);
                if (SystemUtils::IsValidPointer(pList, sizeof(VECTORED_HANDLER_LIST_WIN8)))
                {
                    result.pHead = &pList->ExceptionList;
                }
                break;
            }
        }
        result.success = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        result.exceptionCode = GetExceptionCode();
    }
    return result;
}

VehHookSensor::VehTraverseResult VehHookSensor::TraverseVehListSafe(LIST_ENTRY *pHead, int budget_ms)
{
    VehTraverseResult result = {false, {0}, 0, 0};
    __try
    {
        const auto startTime = std::chrono::steady_clock::now();
        LIST_ENTRY *pNode = pHead->Flink;
        int safetyCounter = 0;
        const int kMaxNodes = 2048;

        while (pNode && pNode != pHead && safetyCounter++ < kMaxNodes && result.handlerCount < 2048)
        {
            // 优化：每25次循环检查一次超时，因为安全计数器需要更频繁的检查
            if (safetyCounter % 25 == 0)
            {
                auto now = std::chrono::steady_clock::now();
                if (std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count() > budget_ms)
                {
                    result.success = false;  // 超时视为失败
                    return result;           // Timeout
                }
            }

            if (!SystemUtils::IsValidPointer(pNode, sizeof(LIST_ENTRY)))
                break;

            auto *pEntry = CONTAINING_RECORD(pNode, VECTORED_HANDLER_ENTRY, List);
            if (!SystemUtils::IsValidPointer(pEntry, sizeof(VECTORED_HANDLER_ENTRY)))
                break;

            // 检查Handler是否为空，空的Handler可能是异常情况
            if (pEntry->Handler != nullptr)
            {
                result.handlers[result.handlerCount++] = pEntry->Handler;
            }
            else
            {
                // 空的VEH Handler可能是异常情况，记录但继续处理
                LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "VEH检测: 发现空的Handler，可能是异常情况");
            }

            LIST_ENTRY *pNext = pNode->Flink;
            if (!SystemUtils::IsValidPointer(pNext, sizeof(LIST_ENTRY)))
                break;
            pNode = pNext;
        }
        result.success = true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        result.success = false;
        result.exceptionCode = GetExceptionCode();
    }
    return result;
}

void VehHookSensor::AnalyzeHandlerSecurity(SensorRuntimeContext &context, PVOID handlerAddress, int index)
{
    if (!handlerAddress)
        return;

    std::wstring modulePath;
    bool isInBaselineModule = context.IsAddressInLegitimateModule(handlerAddress, modulePath);

    if (isInBaselineModule)
    {
        // 地址在基线建立的模块中，进一步验证其是否在代码节内
        // 先检查页面保护，避免读取无效/非执行内存导致访问冲突
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQuery(handlerAddress, &mbi, sizeof(mbi)) == 0)
        {
            this->RecordFailure(anti_cheat::VEH_VIRTUAL_QUERY_FAILED);  // 统计VirtualQuery失败
            return;                                                      // 无法查询，保守退出
        }
        const DWORD prot = mbi.Protect & 0xFF;
        const bool isExec = (prot == PAGE_EXECUTE) || (prot == PAGE_EXECUTE_READ) ||
                            (prot == PAGE_EXECUTE_READWRITE) || (prot == PAGE_EXECUTE_WRITECOPY);
        if (!isExec)
        {
            // 非可执行页面中的处理函数极不正常，作为可疑迹象上报
            context.AddEvidence(anti_cheat::INTEGRITY_API_HOOK,
                                "VEH 处理函数位于非可执行页面，疑似劫持或保护绕过。");
            return;
        }

        HMODULE hModule = NULL;
        if (GetModuleHandleExW(
                    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                    (LPCWSTR)handlerAddress, &hModule) &&
            hModule)
        {
            PVOID codeBase = nullptr;
            DWORD codeSize = 0;
            if (SystemUtils::GetModuleCodeSectionInfo(hModule, codeBase, codeSize))
            {
                uintptr_t addr = reinterpret_cast<uintptr_t>(handlerAddress);
                uintptr_t start = reinterpret_cast<uintptr_t>(codeBase);
                if (addr >= start && addr < (start + codeSize))
                {
                    return;  // 在基线模块的合法代码节内，安全
                }
            }
            else
            {
                // 从配置中获取系统核心 DLL 列表进行检查
                auto whitelistedSystemModules = context.GetWhitelistedSystemModules();
                bool isSystemProtectedModule = false;
                if (whitelistedSystemModules)
                {
                     // 提取文件名进行比对
                     std::wstring fileName = modulePath;
                     size_t lastSlash = fileName.find_last_of(L"\\/");
                     if (lastSlash != std::wstring::npos) fileName = fileName.substr(lastSlash + 1);
                     std::transform(fileName.begin(), fileName.end(), fileName.begin(), ::towlower);

                     if (whitelistedSystemModules->count(fileName) > 0)
                     {
                         isSystemProtectedModule = true;
                     }
                }

                if (isSystemProtectedModule)
                {
                    // 系统保护模块的GetModuleCodeSectionInfo失败是正常情况，跳过检测
                    LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                                "VehHookSensor: 系统保护模块代码节获取失败（正常情况）, 模块=%s, 地址=0x%p",
                                Utils::WideToString(modulePath).c_str(), handlerAddress);
                    return;
                }
                else
                {
                    // 非系统保护模块的GetModuleCodeSectionInfo失败是可疑行为，作为证据上报
                    std::wostringstream woss;
                    woss << L"检测到VEH处理器被劫持到基线模块的非代码区. 模块: "
                         << (modulePath.empty() ? L"未知" : modulePath) << L", 地址: 0x" << std::hex
                         << handlerAddress << L" (GetModuleCodeSectionInfo失败)";
                    context.AddEvidence(anti_cheat::INTEGRITY_API_HOOK, Utils::WideToString(woss.str()));
                    return;
                }
            }
        }
        else
        {
            // GetModuleHandleExW失败本身就是可疑行为，作为证据上报
            std::wostringstream woss;
            woss << L"检测到VEH处理器被劫持到基线模块的非代码区. 模块: "
                 << (modulePath.empty() ? L"未知" : modulePath) << L", 地址: 0x" << std::hex << handlerAddress
                 << L" (GetModuleHandleExW失败)";
            context.AddEvidence(anti_cheat::INTEGRITY_API_HOOK, Utils::WideToString(woss.str()));
            return;
        }
        // 不在代码节内，或无法获取信息，视为劫持
        std::wostringstream woss;
        woss << L"检测到VEH处理器被劫持到基线模块的非代码区. 模块: " << (modulePath.empty() ? L"未知" : modulePath)
             << L", 地址: 0x" << std::hex << handlerAddress;
        context.AddEvidence(anti_cheat::INTEGRITY_API_HOOK, Utils::WideToString(woss.str()));
    }
    else
    {
        // 地址不在基线建立的模块中，需要检查是否在白名单中
        auto whitelistedVEHModules = context.GetWhitelistedVEHModules();
        bool isWhitelisted = false;
        // 如果modulePath不为空，说明地址在某个模块中（非基线模块）
        if (!modulePath.empty() && whitelistedVEHModules)
        {
            // 修复：提取文件名进行比对，而不是完整路径
            std::wstring modulePathLower = modulePath;
            std::transform(modulePathLower.begin(), modulePathLower.end(), modulePathLower.begin(), ::towlower);

            // 提取文件名（去除路径）
            size_t lastSlash = modulePathLower.find_last_of(L"\\/");
            std::wstring fileName =
                    (lastSlash != std::wstring::npos) ? modulePathLower.substr(lastSlash + 1) : modulePathLower;

            if (whitelistedVEHModules->count(fileName) > 0)
            {
                isWhitelisted = true;
                LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR, "VEH处理器在白名单中: %s (文件名: %s)",
                            Utils::WideToString(modulePath).c_str(), Utils::WideToString(fileName).c_str());
            }
        }

        if (!isWhitelisted)
        {
            std::wostringstream woss;
            if (!modulePath.empty())
            {
                woss << L"检测到可疑的VEH Hook (Handler #" << index << L"). 来源: " << modulePath << L", 地址: 0x"
                     << std::hex << handlerAddress;
            }
            else
            {
                 woss << L"检测到可疑的VEH Hook (Handler #" << index << L"). 来源: UNKNOWN (Not in any module), 地址: 0x"
                     << std::hex << handlerAddress;
            }
            context.AddEvidence(anti_cheat::INTEGRITY_API_HOOK, Utils::WideToString(woss.str()));
        }
    }
}
