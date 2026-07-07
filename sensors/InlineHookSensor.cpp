#include "InlineHookSensor.h"
#include "SensorRuntimeContext.h"
#include "utils/SystemUtils.h"
#include "Logger.h"
#include "utils/Utils.h"
#include "CheatConfigManager.h"
#include <vector>
#include <sstream>
#include <set>
#include <algorithm>
#include <limits>

extern "C" {
#include "hde/hde32.h"
}

SensorExecutionResult InlineHookSensor::Execute(SensorRuntimeContext &context)
{
    const bool targetedScan = context.IsTargetedScan();
    auto startTime = std::chrono::steady_clock::now();
    int budgetMs = targetedScan ? std::numeric_limits<int>::max()
                                : CheatConfigManager::GetInstance().GetHeavyScanBudgetMs();
    if (budgetMs <= 0) budgetMs = 1500;

    m_lastFailureReason = anti_cheat::UNKNOWN_FAILURE;

    // Base system module list + system module whitelist from config
    static const wchar_t* kDefaultSystemModules[] = {
        L"ntdll.dll",
        L"kernel32.dll",
        L"kernelbase.dll",
        L"user32.dll",
        L"gdi32.dll", // Common game rendering API
        L"ws2_32.dll" // Network API
    };

    std::set<std::wstring> moduleNames;
    for (const auto &modName : kDefaultSystemModules)
    {
        moduleNames.insert(modName);
    }
    auto configuredSystemModules = context.GetWhitelistedSystemModules();
    if (configuredSystemModules)
    {
        moduleNames.insert(configuredSystemModules->begin(), configuredSystemModules->end());
    }

    std::vector<std::wstring> targetModules(moduleNames.begin(), moduleNames.end());
    // Add main module check (NULL)
    targetModules.push_back(L"__SELF__");

    size_t startModIdx = targetedScan ? 0 : context.GetInlineHookModuleCursorOffset();
    if (startModIdx >= targetModules.size()) startModIdx = 0;

    for (size_t i = startModIdx; i < targetModules.size(); i++)
    {
        const auto& modName = targetModules[i];
        HMODULE hMod = nullptr;
        std::string moduleDisplayName;
        if (modName == L"__SELF__")
        {
            hMod = GetModuleHandleW(NULL);
            wchar_t exePath[MAX_PATH] = {0};
            if (hMod && GetModuleFileNameW(hMod, exePath, MAX_PATH) > 0)
            {
                moduleDisplayName = Utils::WideToString(Utils::GetFileName(exePath));
            }
            else
            {
                moduleDisplayName = "__SELF__";
            }
        }
        else
        {
            hMod = GetModuleHandleW(modName.c_str());
            moduleDisplayName = Utils::WideToString(modName);
        }

        if (hMod)
        {
            auto result = CheckModuleExports(hMod, moduleDisplayName, context, startTime, budgetMs, targetedScan);
            if (result == SensorExecutionResult::TIMEOUT)
            {
                if (!targetedScan) context.SetInlineHookModuleCursorOffset(i);
                LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                           "InlineHookSensor scan timeout: Module=%ls (Index: %zu/%zu)",
                           modName.c_str(), i, targetModules.size());
                return SensorExecutionResult::TIMEOUT;
            }
        }
        // Successfully processed a module, reset export cursor
        if (!targetedScan) context.SetExportCursorOffset(0);
    }

    // All scanning completed, reset cursors
    context.SetInlineHookModuleCursorOffset(0);
    context.SetExportCursorOffset(0);
    return SensorExecutionResult::SUCCESS;
}

bool InlineHookSensor::IsModuleInUnifiedWhitelist(const std::wstring &modulePath, SensorRuntimeContext &context) const
{
    std::wstring lowered = modulePath;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), ::towlower);
    if (Utils::IsWhitelistedModule(lowered))
    {
        return true;
    }

    auto ignoreList = context.GetWhitelistedIntegrityIgnoreList();
    if (ignoreList)
    {
        const std::wstring name = Utils::GetFileName(lowered);
        if (ignoreList->count(name) > 0)
        {
            return true;
        }
    }

    return false;
}

bool InlineHookSensor::IsAddressWhitelisted(PVOID address, SensorRuntimeContext &context) const
{
    HMODULE hModule = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(address), &hModule) ||
        !hModule)
    {
        return false;
    }

    wchar_t modulePath[MAX_PATH] = {0};
    if (GetModuleFileNameW(hModule, modulePath, MAX_PATH) == 0)
    {
        return false;
    }
    return IsModuleInUnifiedWhitelist(modulePath, context);
}

bool InlineHookSensor::IsRvaInExecutableSection(HMODULE hMod, PIMAGE_NT_HEADERS pNt, DWORD rva)
{
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    const WORD sectionCount = pNt->FileHeader.NumberOfSections;
    if (sectionCount == 0 ||
        !SystemUtils::IsReadableMemory(pSection, sizeof(IMAGE_SECTION_HEADER) * sectionCount))
    {
        return false;
    }

    for (WORD s = 0; s < sectionCount; s++)
    {
        DWORD sectionSize = pSection[s].Misc.VirtualSize ? pSection[s].Misc.VirtualSize
                                                         : pSection[s].SizeOfRawData;
        if (rva >= pSection[s].VirtualAddress && rva - pSection[s].VirtualAddress < sectionSize)
        {
            return (pSection[s].Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        }
    }
    // RVA 不落在任何节内（如 PE 头区域）：同样不是代码
    return false;
}

bool InlineHookSensor::IsCommittedExecutableMemory(PVOID address)
{
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(address, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
    return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

SensorExecutionResult InlineHookSensor::CheckModuleExports(HMODULE hMod, const std::string &moduleName,
                                               SensorRuntimeContext& context,
                                               std::chrono::steady_clock::time_point startTime, int budgetMs,
                                               bool targetedScan)
{
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hMod;
    if (!SystemUtils::IsReadableMemory(pDos, sizeof(IMAGE_DOS_HEADER)) || pDos->e_magic != IMAGE_DOS_SIGNATURE) return SensorExecutionResult::SUCCESS;

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + pDos->e_lfanew);
    if (!SystemUtils::IsReadableMemory(pNt, sizeof(IMAGE_NT_HEADERS)) || pNt->Signature != IMAGE_NT_SIGNATURE) return SensorExecutionResult::SUCCESS;

    DWORD exportDirRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportDirRVA == 0) return SensorExecutionResult::SUCCESS;

    DWORD exportDirSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hMod + exportDirRVA);
    if (!SystemUtils::IsReadableMemory(pExport, sizeof(IMAGE_EXPORT_DIRECTORY))) return SensorExecutionResult::SUCCESS;

    DWORD* pAddressOfFunctions = (DWORD*)((BYTE*)hMod + pExport->AddressOfFunctions);
    DWORD* pAddressOfNames = (DWORD*)((BYTE*)hMod + pExport->AddressOfNames);
    WORD* pAddressOfNameOrdinals = (WORD*)((BYTE*)hMod + pExport->AddressOfNameOrdinals);

    size_t startExportIdx = targetedScan ? 0 : context.GetExportCursorOffset();

    for (DWORD i = (DWORD)startExportIdx; i < pExport->NumberOfNames; i++)
    {
        // Performance control: Check time every 100 export items
        if (i % 100 == 0)
        {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - startTime).count();
            if (!targetedScan && elapsed > budgetMs)
            {
                context.SetExportCursorOffset(i);
                return SensorExecutionResult::TIMEOUT;
            }
        }
        if (!SystemUtils::IsReadableMemory(&pAddressOfNames[i], sizeof(DWORD)) ||
            !SystemUtils::IsReadableMemory(&pAddressOfNameOrdinals[i], sizeof(WORD))) break;

        const char* funcName = (const char*)((BYTE*)hMod + pAddressOfNames[i]);
        if (!SystemUtils::IsReadableMemory(funcName, 1)) continue;

        WORD ordinal = pAddressOfNameOrdinals[i];
        if (ordinal >= pExport->NumberOfFunctions) continue;

        if (!SystemUtils::IsReadableMemory(&pAddressOfFunctions[ordinal], sizeof(DWORD))) break;

        DWORD funcRVA = pAddressOfFunctions[ordinal];

        // Ignore Forwarder RVA
        if (funcRVA >= exportDirRVA && funcRVA < exportDirRVA + exportDirSize)
        {
            continue;
        }

        // 数据导出（如导出的全局变量 gCookie、ntdll!NlsAnsiCodePage）位于非可执行节，
        // 其内容是数据而非指令，反汇编会产生虚假的 JMP/PUSH+RET "钩子"
        if (!IsRvaInExecutableSection(hMod, pNt, funcRVA))
        {
            continue;
        }

        BYTE* pFunc = (BYTE*)hMod + funcRVA;
        if (!SystemUtils::IsReadableMemory(pFunc, 16)) continue;

        CheckFunction(pFunc, funcName, moduleName, context);
    }

    return SensorExecutionResult::SUCCESS;
}

void InlineHookSensor::CheckFunction(BYTE* pFunc, const char* funcName, const std::string &moduleName,
                                     SensorRuntimeContext& context)
{
    hde32s hs;
    unsigned int len = hde32_disasm(pFunc, &hs);

    if (hs.flags & F_ERROR) return;

    bool isHooked = false;
    PVOID targetAddr = nullptr;

    // E9: JMP REL32
    if (hs.opcode == 0xE9)
    {
        targetAddr = (PVOID)(pFunc + hs.len + hs.imm.imm32);
        isHooked = true;
    }
    // EB: JMP REL8 (Short jump)
    else if (hs.opcode == 0xEB)
    {
        targetAddr = (PVOID)(pFunc + hs.len + (int8_t)hs.imm.imm8);
        if ((BYTE*)targetAddr == pFunc - 5)
        {
            CheckHotpatchPreamble((BYTE*)targetAddr, funcName, moduleName, context);
            return;
        }
        else
        {
             isHooked = true;
        }
    }
    // 68 xx xx xx xx C3 (PUSH imm32 + RET)
    else if (hs.opcode == 0x68 && pFunc[hs.len] == 0xC3)
    {
         targetAddr = (PVOID)(uintptr_t)hs.imm.imm32;
         isHooked = true;
    }

    if (isHooked && targetAddr)
    {
        std::wstring modulePath;
        if (context.IsAddressInLegitimateModule(targetAddr, modulePath))
        {
             return;
        }
        if (IsAddressWhitelisted(targetAddr, context))
        {
            return;
        }
        // 真实 inline hook 的跳转目标必然是已提交的可执行内存，否则钩子一执行就会崩溃；
        // 不可执行的目标只能是把数据误解码成跳转指令的产物
        if (!IsCommittedExecutableMemory(targetAddr))
        {
            LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                        "InlineHookSensor: 忽略不可执行跳转目标 %s!%s -> 0x%p", moduleName.c_str(), funcName,
                        targetAddr);
            return;
        }

        std::ostringstream oss;
        oss << "Inline Hook Detected: " << moduleName << "!" << funcName << " -> 0x" << std::hex
            << (uintptr_t)targetAddr;
        if (!modulePath.empty())
        {
            oss << " (target module: " << Utils::WideToString(modulePath) << ")";
        }
        else
        {
            oss << " (target in private executable memory)";
        }
        context.AddEvidence(anti_cheat::INTEGRITY_SYSTEM_API_HOOKED, oss.str());
    }
}

void InlineHookSensor::CheckHotpatchPreamble(BYTE* pPreamble, const char* funcName, const std::string &moduleName,
                                             SensorRuntimeContext& context)
{
    if (!SystemUtils::IsReadableMemory(pPreamble, 5)) return;

    // Hotpatch preamble is usually 5 NOPs or mov edi, edi...
    // But here we are checking for hook.
    // E9 xx xx xx xx  (JMP REL32)
    if (pPreamble[0] == 0xE9)
    {
        int32_t rel = *(int32_t*)(pPreamble + 1);
        PVOID targetAddr = (PVOID)(pPreamble + 1 + 4 + rel);

        std::wstring modulePath;
        if (context.IsAddressInLegitimateModule(targetAddr, modulePath))
        {
             return;
        }
        if (IsAddressWhitelisted(targetAddr, context))
        {
            return;
        }
        if (!IsCommittedExecutableMemory(targetAddr))
        {
            LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                        "InlineHookSensor: 忽略不可执行 Hotpatch 跳转目标 %s!%s -> 0x%p", moduleName.c_str(),
                        funcName, targetAddr);
            return;
        }

        std::ostringstream oss;
        oss << "Inline Hook (Hotpatch) Detected: " << moduleName << "!" << funcName << " -> 0x" << std::hex
            << (uintptr_t)targetAddr;
        if (!modulePath.empty())
        {
            oss << " (target module: " << Utils::WideToString(modulePath) << ")";
        }
        else
        {
            oss << " (target in private executable memory)";
        }
        context.AddEvidence(anti_cheat::INTEGRITY_SYSTEM_API_HOOKED, oss.str());
    }
}
