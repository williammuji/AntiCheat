#include "HardwareInfoCollector.h"
#include "Logger.h"

#include <windows.h>
#include <winternl.h>  // For NTSTATUS and NT_SUCCESS
#include <Iphlpapi.h>
#include <intrin.h>

#include <sstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <vector>
#include <cwctype>

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

// === VM信息收集辅助函数 ===

// 检查注册表键值是否存在特定字符串
static bool CheckRegistryKey(HKEY hKeyRoot, const std::wstring& subKey, const std::wstring& valueName, const std::wstring& targetStr)
{
    HKEY hKey;
    if (RegOpenKeyExW(hKeyRoot, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
    {
        return false;
    }

    WCHAR data[256] = {0};
    DWORD dataSize = sizeof(data);
    DWORD type = 0;
    bool found = false;

    if (RegQueryValueExW(hKey, valueName.c_str(), NULL, &type, (LPBYTE)data, &dataSize) == ERROR_SUCCESS)
    {
        if (type == REG_SZ)
        {
            std::wstring dataStr = data;
            std::transform(dataStr.begin(), dataStr.end(), dataStr.begin(), ::towlower);
            std::wstring target = targetStr;
            std::transform(target.begin(), target.end(), target.begin(), ::towlower);

            if (dataStr.find(target) != std::wstring::npos)
            {
                found = true;
            }
        }
    }

    RegCloseKey(hKey);
    return found;
}

// 检查特定文件是否存在
static bool CheckFileExists(const std::wstring& filePath)
{
    DWORD attr = GetFileAttributesW(filePath.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY));
}

// 检查VMware I/O端口 (需SEH保护)
static bool CheckVMwareIOPort()
{
    bool rc = true;
    __try
    {
        __asm
        {
            push   edx
            push   ecx
            push   ebx

            mov    eax, 'VMXh'
            mov    ebx, 0 // any value but not the MAGIC VALUE
            mov    ecx, 10 // get VMWare version
            mov    edx, 'VX' // port number

            in     eax, dx // read port
                           // on return EAX returns the VERSION
                           cmp    ebx, 'VMXh' // is it a reply from VMWare?
                           setz[rc] // set return value

                           pop    ebx
                           pop    ecx
                           pop    edx
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        rc = false;
    }
    return rc;
}

// 收集所有VM相关信息
static std::string CollectVMInfo()
{
    std::string result;

    // 1. 注册表检测
    if (CheckRegistryKey(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum", L"0", L"vmware") ||
        CheckRegistryKey(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum", L"0", L"vbox"))
    {
        result += "Reg:DiskEnum|";
    }

    if (CheckRegistryKey(HKEY_LOCAL_MACHINE, L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", L"Identifier", L"vmware") ||
        CheckRegistryKey(HKEY_LOCAL_MACHINE, L"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", L"Identifier", L"vbox"))
    {
        result += "Reg:Scsi|";
    }

    if (CheckRegistryKey(HKEY_LOCAL_MACHINE, L"HARDWARE\\Description\\System", L"SystemBiosVersion", L"vbox"))
    {
        result += "Reg:BiosVer|";
    }

    // 2. 文件检测
    if (CheckFileExists(L"C:\\windows\\system32\\drivers\\VBoxGuest.sys")) result += "File:VBoxGuest|";
    if (CheckFileExists(L"C:\\windows\\system32\\drivers\\vmmouse.sys")) result += "File:vmmouse|";
    if (CheckFileExists(L"C:\\windows\\system32\\drivers\\vm3dgl.dll")) result += "File:vm3dgl|";

    // 3. I/O端口检测 (VMware)
    if (CheckVMwareIOPort())
    {
        result += "IO:VMware|";
    }

    // 4. CPUID Hypervisor位检查 (HardwareInfoCollector已做, 这里补充更具体的Vendor ID检查)
    int cpu_info[4] = {0};
    __cpuid(cpu_info, 0x40000000);
    char szHyperVendorID[13] = {0};
    memcpy(szHyperVendorID + 0, &cpu_info[1], sizeof(int)); // ebx
    memcpy(szHyperVendorID + 4, &cpu_info[2], sizeof(int)); // ecx
    memcpy(szHyperVendorID + 8, &cpu_info[3], sizeof(int)); // edx
    szHyperVendorID[12] = '\0';

    if (strlen(szHyperVendorID) > 0)
    {
         result += "CPUID:" + std::string(szHyperVendorID) + "|";
    }

    return result;
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
    else
    {
        DWORD error = GetLastError();
        LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM,
                      "HardwareInfoCollector: GetVolumeInformationW failed, error=%lu (possible sandbox)", error);
        fingerprint_->set_disk_serial("ERROR:GetVolumeInformationW:" + std::to_string(error));
    }

    // 2. MAC Addresses - 生产环境增强：过滤虚拟网卡
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
    int macCount = 0;
    int filteredCount = 0;

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
                    macCount++;
                    char macStr[18] = {0};
                    sprintf_s(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X", cur->Address[0], cur->Address[1],
                              cur->Address[2], cur->Address[3], cur->Address[4], cur->Address[5]);

                    // 过滤无效和虚拟MAC地址
                    std::string macString(macStr);
                    if (!IsVirtualOrInvalidMac(macString))
                    {
                        fingerprint_->add_mac_addresses(macStr);
                    }
                    else
                    {
                        filteredCount++;
                    }
                }
                cur = cur->Next;
            }
        }
        else
        {
            LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM,
                          "HardwareInfoCollector: GetAdaptersInfo failed, result=%lu (possible sandbox)", result);
            fingerprint_->add_mac_addresses("ERROR:GetAdaptersInfo:" + std::to_string(result));
        }

        if (pAdapterInfo)
            free(pAdapterInfo);
    }
    else
    {
        LOG_WARNING(AntiCheatLogger::LogCategory::SYSTEM,
                    "HardwareInfoCollector: Failed to allocate memory for adapter info");
        fingerprint_->add_mac_addresses("ERROR:AllocateAdapterInfoFailed");
    }

    if (macCount == 0 && fingerprint_->mac_addresses().empty())
    {
        fingerprint_->add_mac_addresses("ERROR:NoPhysicalMacFound");
    }

    // 如果所有MAC都被过滤，记录警告（可能是沙箱环境）
    if (macCount > 0 && fingerprint_->mac_addresses().empty())
    {
        LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM,
                      "HardwareInfoCollector: All %d MAC addresses were filtered (possible sandbox)", macCount);
        fingerprint_->add_mac_addresses("ERROR:AllMacFiltered:count=" + std::to_string(macCount) +
                                        ";filtered=" + std::to_string(filteredCount));
    }

    // 3. Computer Name
    WCHAR computerName[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(computerName, &size))
    {
        fingerprint_->set_computer_name(WideToUtf8(computerName));
    }
    else
    {
        DWORD error = GetLastError();
        LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM,
                      "HardwareInfoCollector: GetComputerNameW failed, error=%lu (possible sandbox)", error);
        fingerprint_->set_computer_name("ERROR:GetComputerNameW:" + std::to_string(error));
    }

    // 4. OS Version - 使用RtlGetVersion获取准确的系统版本信息
    {
        // 定义RtlGetVersion函数指针类型
        using RtlGetVersionFunc = NTSTATUS(WINAPI*)(PRTL_OSVERSIONINFOW);

        // 获取ntdll.dll模块句柄
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll)
        {
            // 获取RtlGetVersion函数地址
            RtlGetVersionFunc RtlGetVersion =
                    reinterpret_cast<RtlGetVersionFunc>(GetProcAddress(hNtdll, "RtlGetVersion"));

            if (RtlGetVersion)
            {
                RTL_OSVERSIONINFOW osInfo = {};
                osInfo.dwOSVersionInfoSize = sizeof(osInfo);

                if (NT_SUCCESS(RtlGetVersion(&osInfo)))
                {
                    std::wstringstream wss;
                    wss << L"Windows " << osInfo.dwMajorVersion << L"." << osInfo.dwMinorVersion << L" (Build "
                        << osInfo.dwBuildNumber << L")";
                    fingerprint_->set_os_version(WideToUtf8(wss.str()));
                }
                else
                {
                    fingerprint_->set_os_version("Windows Unknown (RtlGetVersion failed)");
                }
            }
            else
            {
                fingerprint_->set_os_version("Windows Unknown (RtlGetVersion not found)");
            }
        }
        else
        {
            fingerprint_->set_os_version("Windows Unknown (ntdll not found)");
        }
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
    else
    {
        LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM,
                      "HardwareInfoCollector: CPU info collection failed, max_id=0x%x (possible sandbox)", max_id);
        std::ostringstream oss;
        oss << "ERROR:CPUID:max_id=0x" << std::hex << max_id;
        fingerprint_->set_cpu_info(oss.str());
    }

    // 6. VM/Sandbox Info Collection
    // 增强检测：收集注册表、文件、I/O端口等维度的环境特征
    std::string vmInfo = CollectVMInfo();
    if (!vmInfo.empty())
    {
        fingerprint_->set_vm_info(vmInfo);

        // 如果收集到了明确的VM特征，记录一条警告日志
        if (vmInfo.length() > 5)
        {
             LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM,
                           "HardwareInfoCollector: VM environment artifacts found: %s", vmInfo.c_str());
        }
    }

    // 检查收集结果：如果所有硬件信息都为空，可能是沙箱环境
    bool hasAnyInfo = !fingerprint_->disk_serial().empty() || !fingerprint_->mac_addresses().empty() ||
                      !fingerprint_->computer_name().empty() || !fingerprint_->cpu_info().empty() ||
                      !fingerprint_->vm_info().empty();

    if (!hasAnyInfo)
    {
        LOG_WARNING(AntiCheatLogger::LogCategory::SYSTEM,
                    "HardwareInfoCollector: All hardware info collection failed (possible sandbox environment)");
    }

    return true;
}

std::unique_ptr<HardwareFingerprint> HardwareInfoCollector::ConsumeFingerprint()
{
    return std::move(fingerprint_);
}

}  // namespace anti_cheat
