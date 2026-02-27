#include "ThreadActivitySensor.h"
#include "SensorRuntimeContext.h"
#include "CheatConfigManager.h"
#include "utils/SystemUtils.h"
#include "Logger.h"
#include "utils/Utils.h"
#include "utils/Scanners.h"
#include <sstream>
#include <iomanip>
#include <vector>
#include <memory>

bool ThreadActivitySensor::IsIgnorableNtStatus(NTSTATUS status)
{
    return status == 0xC000000D || status == 0xC0000022 || status == 0xC0000003 || status == 0xC0000002 ||
           status == 0xC0000004;
}

bool ThreadActivitySensor::HasHardwareBreakpoints(const CONTEXT &ctx)
{
    return ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0;
}

SensorExecutionResult ThreadActivitySensor::Execute(SensorRuntimeContext &context)
{
    m_lastFailureReason = anti_cheat::UNKNOWN_FAILURE;

    if (!IsOsSupported(context))
    {
        LOG_DEBUG(AntiCheatLogger::LogCategory::SENSOR, "线程活动监控检测已禁用：当前OS版本低于配置最低要求");
        RecordFailure(anti_cheat::THREAD_MODULE_OS_VERSION_UNSUPPORTED);
        return SensorExecutionResult::FAILURE;
    }

    const int budget_ms = CheatConfigManager::GetInstance().GetHeavyScanBudgetMs();
    const auto startTime = std::chrono::steady_clock::now();

    if (!SystemUtils::g_pNtQueryInformationThread)
    {
        LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "ThreadActivitySensor: 系统API不可用");
        RecordFailure(anti_cheat::THREAD_MODULE_SYSTEM_API_FAILED);
        return SensorExecutionResult::FAILURE;
    }

    if (!ScanThreadsWithTimeout(context, budget_ms, startTime))
    {
        return SensorExecutionResult::FAILURE;
    }

    if (m_lastFailureReason != anti_cheat::UNKNOWN_FAILURE)
    {
        return SensorExecutionResult::FAILURE;
    }

    return SensorExecutionResult::SUCCESS;
}

bool ThreadActivitySensor::ScanThreadsWithTimeout(SensorRuntimeContext &context, int budget_ms,
                                                  const std::chrono::steady_clock::time_point &startTime)
{
    int threadCount = 0;
    bool hasSystemFailure = false;
    bool timeoutOccurred = false;

    DWORD currentPid = GetCurrentProcessId();
    if (currentPid == 0)
    {
        LOG_ERROR(AntiCheatLogger::LogCategory::SENSOR, "ThreadActivitySensor: GetCurrentProcessId失败");
        RecordFailure(anti_cheat::THREAD_MODULE_GET_PROCESS_ID_FAILED);
        return false;
    }

    ThreadScanner::EnumerateThreads(
            [&](DWORD threadId) {
                if (threadCount % 25 == 0)
                {
                    auto now = std::chrono::steady_clock::now();
                    if (std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count() > budget_ms)
                    {
                        LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR,
                                    "ThreadActivitySensor: 线程扫描超时");
                        RecordFailure(anti_cheat::THREAD_SCAN_TIMEOUT);
                        timeoutOccurred = true;
                        return;
                    }
                }
                threadCount++;

                bool isNewThread = context.InsertKnownThreadId(threadId);
                if (isNewThread)
                {
                    AnalyzeNewThread(context, threadId);
                }

                AnalyzeThreadIntegrity(context, threadId);
            },
            currentPid);

    if (timeoutOccurred)
    {
        return false;
    }

    if (context.GetKnownThreadIds().empty())
    {
        HANDLE hTest = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hTest == INVALID_HANDLE_VALUE)
        {
            LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "ThreadActivitySensor: 线程快照创建失败");
            RecordFailure(anti_cheat::THREAD_MODULE_CREATE_SNAPSHOT_FAILED);
            hasSystemFailure = true;
        }
        else
        {
            CloseHandle(hTest);
            RecordFailure(anti_cheat::THREAD_MODULE_THREAD_SCAN_FAILED);
            hasSystemFailure = true;
        }
    }

    return !hasSystemFailure;
}

void ThreadActivitySensor::AnalyzeNewThread(SensorRuntimeContext &context, DWORD threadId)
{
    if (!SystemUtils::g_pNtQueryInformationThread) return;

    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
    if (!hThread) hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, threadId);

    if (hThread)
    {
        auto thread_closer = [](HANDLE h) { CloseHandle(h); };
        std::unique_ptr<void, decltype(thread_closer)> thread_handle(hThread, thread_closer);

        PVOID startAddress = nullptr;
        NTSTATUS status = SystemUtils::g_pNtQueryInformationThread(hThread, (THREADINFOCLASS)9, &startAddress, sizeof(startAddress), nullptr);

        if (NT_SUCCESS(status))
        {
            if (startAddress)
            {
                std::wstring modulePath;
                if (!context.IsAddressInLegitimateModule(startAddress, modulePath))
                {
                    std::string threadDetails = GetThreadDetailedInfo(threadId, startAddress);
                    std::ostringstream oss;
                    oss << "【检测到可疑线程】新线程的起始地址不在任何已知模块中\n" << threadDetails;
                    context.AddEvidence(anti_cheat::RUNTIME_THREAD_NEW_UNKNOWN, oss.str());
                }
                else
                {
                    LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                              "AnalyzeNewThread: 新线程 (TID=%lu) 起始地址 0x%p 位于合法模块 %s", threadId,
                              startAddress, Utils::WideToString(modulePath).c_str());
                }
            }
            else
            {
                LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR, "AnalyzeNewThread: 新线程 (TID=%lu) 起始地址为nullptr", threadId);
            }
        }
        else
        {
             if (!IsIgnorableNtStatus(status))
             {
                 LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "NtQueryInformationThread失败: NTSTATUS=0x%08X, TID=%lu", status, threadId);
                 RecordFailure(anti_cheat::THREAD_MODULE_QUERY_THREAD_FAILED);
             }
        }
    }
    else
    {
         LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR, "AnalyzeNewThread: 无法打开新线程句柄 (TID=%lu)", threadId);
    }
}

void ThreadActivitySensor::AnalyzeThreadIntegrity(SensorRuntimeContext &context, DWORD threadId)
{
    if (!SystemUtils::g_pNtQueryInformationThread) return;

    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
    if (!hThread) return;

    auto thread_closer = [](HANDLE h) { CloseHandle(h); };
    std::unique_ptr<void, decltype(thread_closer)> thread_handle(hThread, thread_closer);

    PVOID startAddress = nullptr;
    NTSTATUS qsaStatus = SystemUtils::g_pNtQueryInformationThread(hThread, (THREADINFOCLASS)9, &startAddress, sizeof(startAddress), nullptr);
    if (NT_SUCCESS(qsaStatus))
    {
        if (startAddress)
        {
            std::wstring modulePath;
            if (!context.IsAddressInLegitimateModule(startAddress, modulePath))
            {
                std::string threadDetails = GetThreadDetailedInfo(threadId, startAddress);
                std::ostringstream oss;
                oss << "【检测到可疑线程】线程的起始地址不在任何已知模块中\n" << threadDetails;
                context.AddEvidence(anti_cheat::RUNTIME_THREAD_NEW_UNKNOWN, oss.str());
            }
        }
    }
    else
    {
        if (!IsIgnorableNtStatus(qsaStatus))
        {
             RecordFailure(anti_cheat::THREAD_MODULE_QUERY_THREAD_FAILED);
        }
    }

    ULONG isHidden = 0;
    NTSTATUS hideStatus = SystemUtils::g_pNtQueryInformationThread(hThread, (THREADINFOCLASS)17, &isHidden, sizeof(isHidden), nullptr);
    if (NT_SUCCESS(hideStatus) && isHidden)
    {
        std::ostringstream oss;
        oss << "检测到线程(TID: " << threadId << ") 被设置为对调试器隐藏。";
        context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, oss.str());
    }
    else if (!NT_SUCCESS(hideStatus))
    {
         if (!IsIgnorableNtStatus(hideStatus))
         {
             RecordFailure(anti_cheat::THREAD_MODULE_QUERY_THREAD_FAILED);
         }
    }

    if (threadId != GetCurrentThreadId())
    {
        if (SuspendThread(hThread) != (DWORD)-1)
        {
            CONTEXT ctx = {};
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            BOOL getCtxSuccess = GetThreadContext(hThread, &ctx);
            ResumeThread(hThread);

            if (getCtxSuccess)
            {
                if (HasHardwareBreakpoints(ctx))
                {
                    std::ostringstream oss;
                    oss << "检测到硬件断点 (TID: " << threadId << "): Dr0=" << (void*)ctx.Dr0 << " ...";
                    context.AddEvidence(anti_cheat::ENVIRONMENT_DEBUGGER_DETECTED, oss.str());
                }
            }
        }
    }
}

DWORD ThreadActivitySensor::GetProcessIdOfThread(HANDLE hThread)
{
    if (SystemUtils::g_pNtQueryInformationThread)
    {
        THREAD_BASIC_INFORMATION tbi = {0};
        NTSTATUS status = SystemUtils::g_pNtQueryInformationThread(hThread, (THREADINFOCLASS)0, &tbi, sizeof(tbi), nullptr);
        if (NT_SUCCESS(status))
        {
            return (DWORD)(uintptr_t)tbi.ClientId.UniqueProcess;
        }
    }
    return 0;
}

std::string ThreadActivitySensor::GetThreadDetailedInfo(DWORD threadId, PVOID startAddress)
{
    std::ostringstream oss;
    oss << std::hex << std::uppercase;

    if (!SystemUtils::g_pNtQueryInformationThread)
    {
        oss << "警告: NtQueryInformationThread API不可用，部分信息可能缺失\n";
    }

    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
    if (!hThread) hThread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, threadId);

    auto thread_closer = [](HANDLE h) { if (h) CloseHandle(h); };
    std::unique_ptr<void, decltype(thread_closer)> thread_handle(hThread, thread_closer);

    DWORD ownerPid = 0;
    std::wstring processName;
    std::string suspectedOrigin = "未知";

    if (hThread)
    {
        FILETIME creationTime, exitTime, kernelTime, userTime;
        if (GetThreadTimes(hThread, &creationTime, &exitTime, &kernelTime, &userTime))
        {
            SYSTEMTIME st;
            FileTimeToSystemTime(&creationTime, &st);
            oss << "创建时间: " << std::dec << st.wYear << "-" << std::setfill('0') << std::setw(2) << st.wMonth
                << "-" << std::setw(2) << st.wDay << " " << std::setw(2) << st.wHour << ":" << std::setw(2)
                << st.wMinute << ":" << std::setw(2) << st.wSecond << "\n";
        }

        typedef HRESULT(WINAPI * PGetThreadDescription)(HANDLE, PWSTR *);
        static PGetThreadDescription pGetThreadDescription =
                (PGetThreadDescription)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetThreadDescription");
        if (pGetThreadDescription)
        {
            PWSTR threadName = nullptr;
            if (SUCCEEDED(pGetThreadDescription(hThread, &threadName)) && threadName && wcslen(threadName) > 0)
            {
                oss << "线程名称: " << Utils::WideToString(threadName) << "\n";
                LocalFree(threadName);
            }
        }

        ownerPid = GetProcessIdOfThread(hThread);
    }

    if (ownerPid != 0)
    {
        processName = Utils::GetProcessNameByPid(ownerPid);
    }

    MEMORY_BASIC_INFORMATION mbi = {0};
    bool hasMemoryInfo = (VirtualQuery(startAddress, &mbi, sizeof(mbi)) != 0);

    // 威胁分析
    if (ownerPid != 0 && ownerPid != GetCurrentProcessId())
    {
        suspectedOrigin = "[CRITICAL] 远程线程注入 (来自 PID: " + std::to_string(ownerPid);
        if (!processName.empty()) suspectedOrigin += ", 进程: " + Utils::WideToString(processName);
        suspectedOrigin += ")";
    }
    else if (hasMemoryInfo)
    {
        bool isExecutable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        bool isWritable = (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0;

        if (mbi.Type == MEM_PRIVATE && isExecutable)
        {
            suspectedOrigin = isWritable ? "[CRITICAL] Shellcode (私有可写可执行内存)" : "[WARNING] Shellcode (私有可执行内存)";
        }
        else if (mbi.Type == MEM_MAPPED && isExecutable)
        {
            suspectedOrigin = "[WARNING] 可能的反射DLL注入 (映射文件可执行内存)";
        }

        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll)
        {
            if (startAddress == GetProcAddress(hNtdll, "KiUserApcDispatcher") ||
                startAddress == GetProcAddress(hNtdll, "AsmKiUserApcDispatcher"))
            {
                suspectedOrigin = "[CRITICAL] APC注入 (起始于 ntdll APC分发函数)";
            }
            else if (startAddress == GetProcAddress(hNtdll, "RtlUserThreadStart"))
            {
                suspectedOrigin = "备注: 正常线程入口 (RtlUserThreadStart)";
            }
        }
    }

    oss << "\n【威胁评估】" << suspectedOrigin << "\n";
    oss << "  线程ID (TID): " << std::dec << threadId << "\n";
    oss << "  起始地址: 0x" << std::hex << reinterpret_cast<uintptr_t>(startAddress) << "\n";
    if (ownerPid != 0) oss << "  所属进程PID: " << std::dec << ownerPid << "\n";

    if (hasMemoryInfo)
    {
        oss << "\n【内存详细信息】\n";
        oss << "  区域大小: 0x" << std::hex << mbi.RegionSize << "\n";
        oss << "  当前保护: 0x" << mbi.Protect << " (";
        if (mbi.Protect & PAGE_EXECUTE_READWRITE) oss << "RWX ";
        else if (mbi.Protect & PAGE_EXECUTE_READ) oss << "RX ";
        else if (mbi.Protect & PAGE_READWRITE) oss << "RW ";
        else if (mbi.Protect & PAGE_READONLY) oss << "R ";
        oss << ")\n";

        if (mbi.AllocationProtect != 0 && mbi.AllocationProtect != mbi.Protect)
        {
            oss << "  初始保护: 0x" << mbi.AllocationProtect << " [检测到属性变更]\n";
        }

        oss << "  内存类型: " << (mbi.Type == MEM_IMAGE ? "IMAGE" : (mbi.Type == MEM_MAPPED ? "MAPPED" : "PRIVATE")) << "\n";

        HMODULE hMod = nullptr;
        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)startAddress, &hMod) && hMod)
        {
            wchar_t modPath[MAX_PATH] = {0};
            if (GetModuleFileNameW(hMod, modPath, MAX_PATH))
            {
                auto validation = Utils::ValidateModule(modPath, SystemUtils::GetWindowsVersion());
                oss << "  关联模块: " << Utils::WideToString(modPath) << "\n";
                oss << "  验证状态: " << validation.reason << (validation.isTrusted ? "" : " [UNTRUSTED!]") << "\n";
            }
        }

        BYTE features[16] = {0};
        auto readRes = SystemUtils::ReadProcessMemorySafe(startAddress, features, sizeof(features));
        if (readRes.success && readRes.bytesRead > 0)
        {
            oss << "  特征(16B): ";
            for (size_t i = 0; i < readRes.bytesRead; i++) oss << std::setfill('0') << std::setw(2) << (int)features[i] << " ";
            oss << "\n";

            if (features[0] == 0x4D && features[1] == 0x5A) oss << "  [!] 检测到 PE 文件头 (MZ)\n";
            else if (features[0] == 0x55 && features[1] == 0x8B && features[2] == 0xEC) oss << "  [!] 检测到标准函数序言 (Push EBP...)\n";
        }
    }

    return oss.str();
}
