#include "InlineHookSensor.h"
#include "../include/ScanContext.h"
#include "../utils/SystemUtils.h"
#include "../Logger.h"
#include "../utils/Utils.h"
#include <vector>
#include <sstream>

extern "C" {
#include "../hde/hde32.h"
}

SensorExecutionResult InlineHookSensor::Execute(ScanContext &context)
{
    m_lastFailureReason = anti_cheat::UNKNOWN_FAILURE;

    // 关键系统模块列表
    static const wchar_t* kSystemModules[] = {
        L"ntdll.dll",
        L"kernel32.dll",
        L"kernelbase.dll",
        L"user32.dll",
        L"gdi32.dll", // 游戏常用渲染API
        L"ws2_32.dll" // 网络API
    };

    for (const auto& modName : kSystemModules)
    {
        HMODULE hMod = GetModuleHandleW(modName);
        if (hMod)
        {
            CheckModuleExports(hMod, context);
        }
    }

    // 也可以检查主模块
    HMODULE hSelf = GetModuleHandleW(NULL);
    if (hSelf) CheckModuleExports(hSelf, context);

    return SensorExecutionResult::SUCCESS;
}

void InlineHookSensor::CheckModuleExports(HMODULE hMod, ScanContext& context)
{
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hMod;
    if (IsBadReadPtr(pDos, sizeof(IMAGE_DOS_HEADER)) || pDos->e_magic != IMAGE_DOS_SIGNATURE) return;

    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + pDos->e_lfanew);
    if (IsBadReadPtr(pNt, sizeof(IMAGE_NT_HEADERS)) || pNt->Signature != IMAGE_NT_SIGNATURE) return;

    DWORD exportDirRVA = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportDirRVA == 0) return;

    DWORD exportDirSize = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hMod + exportDirRVA);
    if (IsBadReadPtr(pExport, sizeof(IMAGE_EXPORT_DIRECTORY))) return;

    DWORD* pAddressOfFunctions = (DWORD*)((BYTE*)hMod + pExport->AddressOfFunctions);
    DWORD* pAddressOfNames = (DWORD*)((BYTE*)hMod + pExport->AddressOfNames);
    WORD* pAddressOfNameOrdinals = (WORD*)((BYTE*)hMod + pExport->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExport->NumberOfNames; i++)
    {
        if (IsBadReadPtr(&pAddressOfNames[i], sizeof(DWORD)) ||
            IsBadReadPtr(&pAddressOfNameOrdinals[i], sizeof(WORD))) break;

        const char* funcName = (const char*)((BYTE*)hMod + pAddressOfNames[i]);
        if (IsBadReadPtr(funcName, 1)) continue;

        WORD ordinal = pAddressOfNameOrdinals[i];
        if (ordinal >= pExport->NumberOfFunctions) continue;

        if (IsBadReadPtr(&pAddressOfFunctions[ordinal], sizeof(DWORD))) break;

        DWORD funcRVA = pAddressOfFunctions[ordinal];

        // 忽略 Forwarder RVA
        if (funcRVA >= exportDirRVA && funcRVA < exportDirRVA + exportDirSize)
        {
            continue;
        }

        BYTE* pFunc = (BYTE*)hMod + funcRVA;
        if (IsBadReadPtr(pFunc, 16)) continue;

        CheckFunction(pFunc, funcName, context);
    }
}

void InlineHookSensor::CheckFunction(BYTE* pFunc, const char* funcName, ScanContext& context)
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
            CheckHotpatchPreamble((BYTE*)targetAddr, funcName, context);
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

        std::ostringstream oss;
        oss << "Inline Hook Detected: " << funcName << " -> 0x" << std::hex << (uintptr_t)targetAddr;
        context.AddEvidence(anti_cheat::INTEGRITY_SYSTEM_API_HOOKED, oss.str());
    }
}

void InlineHookSensor::CheckHotpatchPreamble(BYTE* pPreamble, const char* funcName, ScanContext& context)
{
    if (IsBadReadPtr(pPreamble, 5)) return;

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

        std::ostringstream oss;
        oss << "Inline Hook (Hotpatch) Detected: " << funcName << " -> 0x" << std::hex << (uintptr_t)targetAddr;
        context.AddEvidence(anti_cheat::INTEGRITY_SYSTEM_API_HOOKED, oss.str());
    }
}
