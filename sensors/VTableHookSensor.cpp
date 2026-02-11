#include <windows.h>
#include "VTableHookSensor.h"
#include "../include/ScanContext.h"
#include "../Logger.h"
#include "../utils/Utils.h"
#include <string>
#include <sstream>
#include <algorithm>

SensorExecutionResult VTableHookSensor::Execute(ScanContext &context)
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
            if (pD3D9)
            {
                PVOID* vtable = *(PVOID**)pD3D9;
                CheckVTable(context, vtable, "IDirect3D9", 16);

                // Release: VTable index 2
                typedef ULONG(WINAPI * PRelease)(PVOID);
                PRelease pRelease = (PRelease)vtable[2];
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
                PVOID* vtable = *(PVOID**)pFactory;
                // IDXGIFactory vtable check
                CheckVTable(context, vtable, "IDXGIFactory", 10);

                // Release: VTable index 2
                typedef ULONG(WINAPI * PRelease)(PVOID);
                PRelease pRelease = (PRelease)vtable[2];
                if (pRelease)
                {
                    pRelease(pFactory);
                }
            }
        }
    }

    return SensorExecutionResult::SUCCESS;
}

void VTableHookSensor::CheckVTable(ScanContext& context, PVOID vtableBase, const char* name, int entryCount)
{
    if (IsBadReadPtr(vtableBase, entryCount * sizeof(PVOID)))
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
            // 地址不在任何合法模块中，极可是 Hook
            std::ostringstream oss;
            oss << "VTable Hook Detected: " << name << " [Index " << i << "] -> 0x"
                << std::hex << (uintptr_t)funcAddr << " (Address not in any module)";
            context.AddEvidence(anti_cheat::INTEGRITY_API_HOOK, oss.str());
        }
    }
}
