#include "HardwareInfoCollector.h"

#define NOMINMAX
#include <windows.h>
#include <Iphlpapi.h>
#include <intrin.h>

#include <sstream>

#pragma comment(lib, "iphlpapi.lib")

namespace anti_cheat
{

namespace
{
static std::string WideToUtf8(const std::wstring& w)
{
    if (w.empty())
        return {};
    int len = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string out(len, '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), out.data(), len, nullptr, nullptr);
    return out;
}

// 生产环境优化：过滤虚拟和无效的MAC地址
static bool IsVirtualOrInvalidMac(const std::string& mac)
{
    // 过滤全零MAC
    if (mac == "00:00:00:00:00:00")
        return true;

    // 过滤广播MAC
    if (mac == "FF:FF:FF:FF:FF:FF")
        return true;

    // 过滤常见的虚拟MAC前缀
    const char* virtualPrefixes[] = {
            "00:05:69",  // VMware
            "00:0C:29",  // VMware
            "00:1C:14",  // VMware
            "00:50:56",  // VMware
            "08:00:27",  // VirtualBox
            "0A:00:27",  // VirtualBox
            "00:03:FF",  // Microsoft Virtual PC
            "00:15:5D",  // Hyper-V
            "00:17:FA",  // Xen
            "00:16:3E",  // Xen
            "52:54:00",  // QEMU/KVM
            "02:00:4C",  // Docker
    };

    for (const char* prefix : virtualPrefixes)
    {
        if (mac.substr(0, 8) == prefix)
        {
            return true;
        }
    }

    return false;
}
}  // namespace

bool HardwareInfoCollector::EnsureCollected()
{
    if (fingerprint_)
        return false;
    fingerprint_ = std::make_unique<HardwareFingerprint>();

    // 1. Disk Serial (C:) — 仅作为轻量指纹项
    DWORD serialNum = 0;
    if (GetVolumeInformationW(L"C:\\", NULL, 0, &serialNum, NULL, NULL, NULL, 0))
    {
        fingerprint_->set_disk_serial(std::to_string(serialNum));
    }

    // 2. MAC Addresses - 生产环境增强：过滤虚拟网卡
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
    if (pAdapterInfo)
    {
        // 处理缓冲区大小不足的情况
        DWORD result = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);
        if (result == ERROR_BUFFER_OVERFLOW)
        {
            free(pAdapterInfo);
            pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
            if (pAdapterInfo)
            {
                result = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen);
            }
        }

        if (pAdapterInfo && result == NO_ERROR)
        {
            PIP_ADAPTER_INFO cur = pAdapterInfo;
            while (cur)
            {
                // 生产环境优化：过滤虚拟网卡和无效MAC
                if (cur->AddressLength >= 6 && cur->Type == MIB_IF_TYPE_ETHERNET)
                {
                    char macStr[18] = {0};
                    sprintf_s(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X", cur->Address[0], cur->Address[1],
                              cur->Address[2], cur->Address[3], cur->Address[4], cur->Address[5]);

                    // 过滤无效和虚拟MAC地址
                    std::string macString(macStr);
                    if (!IsVirtualOrInvalidMac(macString))
                    {
                        fingerprint_->add_mac_addresses(macStr);
                    }
                }
                cur = cur->Next;
            }
        }
        if (pAdapterInfo)
            free(pAdapterInfo);
    }

    // 3. Computer Name
    WCHAR computerName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(computerName, &size))
    {
        fingerprint_->set_computer_name(WideToUtf8(computerName));
    }

    // 4. OS Version - 生产环境修复：使用RtlGetVersion确保准确性
    typedef NTSTATUS(WINAPI * RtlGetVersion_t)(LPOSVERSIONINFOEXW);
    auto pRtlGetVersion = (RtlGetVersion_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");

    OSVERSIONINFOEXW osInfo = {0};
    osInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);

    bool versionObtained = false;
    if (pRtlGetVersion && pRtlGetVersion(&osInfo) == 0)
    {  // STATUS_SUCCESS = 0
        versionObtained = true;
    }
    else if (GetVersionExW(reinterpret_cast<LPOSVERSIONINFOW>(&osInfo)))
    {
        versionObtained = true;
    }

    if (versionObtained)
    {
        std::wstringstream wss;
        wss << L"Windows " << osInfo.dwMajorVersion << L"." << osInfo.dwMinorVersion << L" (Build "
            << osInfo.dwBuildNumber << L")";
        fingerprint_->set_os_version(WideToUtf8(wss.str()));
    }
    else
    {
        fingerprint_->set_os_version("Windows Unknown");
    }

    // 5. CPU Brand String
    int cpu_info[4] = {0};
    char cpu_brand[0x40] = {0};
    __cpuid(cpu_info, 0x80000000);
    unsigned int max_id = cpu_info[0];
    if (max_id >= 0x80000004)
    {
        __cpuid(cpu_info, 0x80000002);
        memcpy(cpu_brand + 0, cpu_info, sizeof(cpu_info));
        __cpuid(cpu_info, 0x80000003);
        memcpy(cpu_brand + 16, cpu_info, sizeof(cpu_info));
        __cpuid(cpu_info, 0x80000004);
        memcpy(cpu_brand + 32, cpu_info, sizeof(cpu_info));
        fingerprint_->set_cpu_info(cpu_brand);
    }

    return true;
}

std::unique_ptr<HardwareFingerprint> HardwareInfoCollector::ConsumeFingerprint()
{
    return std::move(fingerprint_);
}

}  // namespace anti_cheat
