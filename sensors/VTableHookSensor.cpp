#include <windows.h>
#include "VTableHookSensor.h"
#include "SensorRuntimeContext.h"
#include "../Logger.h"
#include "../utils/Utils.h"
#include <string>
#include <sstream>
#include <algorithm>

SensorExecutionResult VTableHookSensor::Execute(SensorRuntimeContext &context)
{
    m_lastFailureReason = anti_cheat::UNKNOWN_FAILURE;

    // Check IDirect3D9 VTable if d3d9.dll is loaded
    HMODULE hD3D9 = GetModuleHandleA("d3d9.dll");
    if (hD3D9)
    {
        typedef PVOID(WINAPI * PDirect3DCreate9)(UINT);
        PDirect3DCreate9 pDirect3DCreate9 = (PDirect3DCreate9)GetProcAddress(hD3D9, "Direct3DCreate9");
        if (pDirect3DCreate9)
        {
            // SDK Version 32 (D3D_SDK_VERSION)
            PVOID pD3D9 = pDirect3DCreate9(32);
            if (pD3D9 && SystemUtils::IsReadableMemory(pD3D9, sizeof(PVOID)))
            {
                PVOID* vtable = *(PVOID**)pD3D9;
                if (vtable && SystemUtils::IsReadableMemory(vtable, 16 * sizeof(PVOID)))
                {
                    CheckVTable(context, vtable, "IDirect3D9", 16);
                }

                // Release: VTable index 2
                typedef ULONG(WINAPI * PRelease)(PVOID);
                PRelease pRelease =
                        (vtable && SystemUtils::IsReadableMemory(vtable + 2, sizeof(PVOID))) ? (PRelease)vtable[2] : nullptr;
                if (pRelease)
                {
                    pRelease(pD3D9);
                }
            }
        }
    }

    // Check IDXGIFactory VTable if dxgi.dll is loaded
    HMODULE hDXGI = GetModuleHandleA("dxgi.dll");
    if (hDXGI)
    {
        typedef HRESULT(WINAPI * PCreateDXGIFactory)(REFIID, void**);
        PCreateDXGIFactory pCreateDXGIFactory = (PCreateDXGIFactory)GetProcAddress(hDXGI, "CreateDXGIFactory");
        if (pCreateDXGIFactory)
        {
            const GUID IID_IDXGIFactory = {0x7b7166ec, 0x21c7, 0x44ae, {0xb2, 0x1a, 0xc9, 0xae, 0x32, 0x1a, 0xe3, 0x69}};
            PVOID pFactory = nullptr;
            if (SUCCEEDED(pCreateDXGIFactory(IID_IDXGIFactory, &pFactory)) && pFactory)
            {
                PVOID* vtable = nullptr;
                if (SystemUtils::IsReadableMemory(pFactory, sizeof(PVOID)))
                {
                    vtable = *(PVOID**)pFactory;
                }
                if (vtable && SystemUtils::IsReadableMemory(vtable, 10 * sizeof(PVOID)))
                {
                    // IDXGIFactory vtable check
                    CheckVTable(context, vtable, "IDXGIFactory", 10);
                }

                // Release: VTable index 2
                typedef ULONG(WINAPI * PRelease)(PVOID);
                PRelease pRelease =
                        (vtable && SystemUtils::IsReadableMemory(vtable + 2, sizeof(PVOID))) ? (PRelease)vtable[2] : nullptr;
                if (pRelease)
                {
                    pRelease(pFactory);
                }
            }
        }
    }

    return SensorExecutionResult::SUCCESS;
}

void VTableHookSensor::CheckVTable(SensorRuntimeContext& context, PVOID vtableBase, const char* name, int entryCount)
{
    if (!SystemUtils::IsReadableMemory(vtableBase, entryCount * sizeof(PVOID)))
    {
        return;
    }

    PVOID* pVTable = (PVOID*)vtableBase;
    for (int i = 0; i < entryCount; i++)
    {
        PVOID funcAddr = pVTable[i];
        if (!funcAddr) continue;

        std::wstring modulePath;
        if (!context.IsAddressInLegitimateModule(funcAddr, modulePath))
        {
            if (modulePath.empty())
            {
                HMODULE hMod = nullptr;
                if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                               GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                       reinterpret_cast<LPCWSTR>(funcAddr), &hMod) &&
                    hMod)
                {
                    wchar_t pathBuf[MAX_PATH] = {0};
                    if (GetModuleFileNameW(hMod, pathBuf, MAX_PATH) > 0)
                    {
                        modulePath = pathBuf;
                    }
                }
            }

            if (!modulePath.empty() && Utils::IsWhitelistedModule(modulePath))
            {
                continue;
            }

            auto ignoreList = context.GetWhitelistedIntegrityIgnoreList();
            if (ignoreList)
            {
                std::wstring lowerPath = modulePath;
                std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
                std::wstring fileName = Utils::GetFileName(lowerPath);
                if (ignoreList->count(fileName) > 0)
                {
                    continue;
                }
            }

            auto systemModules = context.GetWhitelistedSystemModules();
            if (systemModules && !modulePath.empty())
            {
                std::wstring lowerPath = modulePath;
                std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);
                std::wstring fileName = Utils::GetFileName(lowerPath);
                if (systemModules->count(fileName) > 0)
                {
                    continue;
                }
            }

            // 地址不在任何合法模块中，极可是 Hook
            std::ostringstream oss;
            oss << "VTable Hook Detected: " << name << " [Index " << i << "] -> 0x"
                << std::hex << (uintptr_t)funcAddr << " (Address not in any module)";
            context.AddEvidence(anti_cheat::INTEGRITY_API_HOOK, oss.str());
        }
    }
}
