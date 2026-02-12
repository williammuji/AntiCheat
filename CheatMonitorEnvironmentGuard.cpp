#include "CheatMonitor.h"
#include "CheatMonitorImpl.h"
#include "ISensor.h"
#include "IatHookSensor.h"
#include "VehHookSensor.h"
#include "InlineHookSensor.h"
#include "ProcessHollowingSensor.h"
#include "ProcessAndWindowMonitorSensor.h"
#include "DriverIntegritySensor.h"
#include "ThreadActivitySensor.h"
#include "ModuleActivitySensor.h"
#include "MemorySecuritySensor.h"
#include "AdvancedAntiDebugSensor.h"
#include "SystemCodeIntegritySensor.h"
#include "ModuleIntegritySensor.h"
#include "ProcessHandleSensor.h"
#include "VTableHookSensor.h"
#include "CheatConfigManager.h"
#include "Logger.h"
#include "utils/SystemUtils.h"
#include "utils/Utils.h"

#include <algorithm>
#include <array>
#include <iphlpapi.h>

typedef NTSTATUS(NTAPI *P_LdrRegisterDllNotification)(ULONG Flags, PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
                                                      PVOID Context, PVOID *Cookie);
typedef NTSTATUS(NTAPI *P_LdrUnregisterDllNotification)(PVOID Cookie);

void CheatMonitorImpl::InitializeSystem()
{
    if (m_lightweightSensors.empty())
    {
        m_lightweightSensors.push_back(std::make_unique<AdvancedAntiDebugSensor>());
        m_lightweightSensors.push_back(std::make_unique<SystemCodeIntegritySensor>());
        m_lightweightSensors.push_back(std::make_unique<IatHookSensor>());
        m_lightweightSensors.push_back(std::make_unique<VehHookSensor>());
        m_lightweightSensors.push_back(std::make_unique<VTableHookSensor>());

        m_heavyweightSensors.push_back(std::make_unique<ThreadActivitySensor>());
        m_heavyweightSensors.push_back(std::make_unique<ModuleActivitySensor>());
        m_heavyweightSensors.push_back(std::make_unique<MemorySecuritySensor>());
        m_heavyweightSensors.push_back(std::make_unique<DriverIntegritySensor>());
        m_heavyweightSensors.push_back(std::make_unique<InlineHookSensor>());
        m_heavyweightSensors.push_back(std::make_unique<ProcessHollowingSensor>());
        m_heavyweightSensors.push_back(std::make_unique<ProcessHandleSensor>());
        m_heavyweightSensors.push_back(std::make_unique<ModuleIntegritySensor>());
        m_heavyweightSensors.push_back(std::make_unique<ProcessAndWindowMonitorSensor>());

        for (const auto &sensor : m_lightweightSensors) m_sensorRegistry[sensor->GetName()] = sensor.get();
        for (const auto &sensor : m_heavyweightSensors) m_sensorRegistry[sensor->GetName()] = sensor.get();
    }

    RegisterDllNotification();
    if (!m_wmiMonitor)
    {
        m_wmiMonitor = std::make_unique<anti_cheat::WMIProcessMonitor>(
                [this](DWORD pid, const std::wstring &name) { this->OnProcessCreated(pid, name); });
        if (!m_wmiMonitor->Initialize())
        {
            LOG_WARNING(AntiCheatLogger::LogCategory::SYSTEM, "WMI/Toolhelp process monitor initialization failed.");
        }
    }
    HardenProcessAndThreads();
    CheckParentProcessAtStartup();
    DetectVirtualMachine();
    InitializeProcessBaseline();
    InitializeSelfIntegrityBaseline();
}

void CheatMonitorImpl::OnConfigUpdated()
{
    std::string osVersionName = CheatConfigManager::GetInstance().GetMinOsVersionName();
    anti_cheat::OsVersion requiredOsVersion = CheatConfigManager::GetInstance().GetMinOsVersion();
    (void)osVersionName;
    const bool osVersionSupported = IsCurrentOsSupported();
    LOG_INFO_F(AntiCheatLogger::LogCategory::SYSTEM, "OS版本门控结果: 当前OS=%d, 配置要求min_os=%d, 版本兼容=%s",
               (int)m_windowsVersion, (int)requiredOsVersion, osVersionSupported ? "是" : "否");
}

bool CheatMonitorImpl::IsCurrentOsSupported() const
{
    anti_cheat::OsVersion requiredOsVersion = CheatConfigManager::GetInstance().GetMinOsVersion();
    switch (requiredOsVersion)
    {
        case anti_cheat::OS_ANY:
            return true;
        case anti_cheat::OS_WIN_XP:
            return m_windowsVersion == SystemUtils::WindowsVersion::Win_XP ||
                   m_windowsVersion == SystemUtils::WindowsVersion::Win_Vista_Win7 ||
                   m_windowsVersion == SystemUtils::WindowsVersion::Win_8_Win81 ||
                   m_windowsVersion == SystemUtils::WindowsVersion::Win_10 ||
                   m_windowsVersion == SystemUtils::WindowsVersion::Win_11;
        case anti_cheat::OS_WIN7_SP1:
            return m_windowsVersion == SystemUtils::WindowsVersion::Win_Vista_Win7 ||
                   m_windowsVersion == SystemUtils::WindowsVersion::Win_8_Win81 ||
                   m_windowsVersion == SystemUtils::WindowsVersion::Win_10 ||
                   m_windowsVersion == SystemUtils::WindowsVersion::Win_11;
        case anti_cheat::OS_WIN10:
            return m_windowsVersion == SystemUtils::WindowsVersion::Win_10 ||
                   m_windowsVersion == SystemUtils::WindowsVersion::Win_11;
        default:
            return false;
    }
}

void CheatMonitorImpl::HardenProcessAndThreads()
{
    bool isElevated = false;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size))
        {
            isElevated = elevation.TokenIsElevated != 0;
        }
        CloseHandle(hToken);
    }
    if (!isElevated)
    {
        LOG_WARNING(AntiCheatLogger::LogCategory::SYSTEM, "进程未以管理员权限运行，某些安全策略可能无法设置");
    }

    typedef BOOL(WINAPI *PSetProcessMitigationPolicy)(PROCESS_MITIGATION_POLICY Policy, PVOID lpBuffer, SIZE_T dwLength);
    static PSetProcessMitigationPolicy pSetProcessMitigationPolicy =
            (PSetProcessMitigationPolicy)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "SetProcessMitigationPolicy");

    if (!SystemUtils::HasApiCapability(SystemUtils::ApiCapability::ProcessMitigationPolicy))
    {
        LOG_INFO(AntiCheatLogger::LogCategory::SYSTEM,
                 "当前OS能力矩阵未启用 ProcessMitigationPolicy，跳过进程缓解策略。");
    }
    else if (pSetProcessMitigationPolicy)
    {
        PROCESS_MITIGATION_DEP_POLICY depPolicy = {};
        depPolicy.Enable = 1;
        depPolicy.Permanent = false;
        (void)pSetProcessMitigationPolicy(ProcessDEPPolicy, &depPolicy, sizeof(depPolicy));

        PROCESS_MITIGATION_CHILD_PROCESS_POLICY childPolicy = {};
        childPolicy.NoChildProcessCreation = 1;
        (void)pSetProcessMitigationPolicy(ProcessChildProcessPolicy, &childPolicy, sizeof(childPolicy));
    }
    else
    {
        LOG_WARNING(AntiCheatLogger::LogCategory::SYSTEM,
                    "SetProcessMitigationPolicy API 不可用，可能是系统版本过低。");
    }

    if (SystemUtils::g_pNtSetInformationThread)
    {
        NTSTATUS status = SystemUtils::g_pNtSetInformationThread(GetCurrentThread(), (THREADINFOCLASS)17, nullptr, 0);
        if (!NT_SUCCESS(status))
            LOG_WARNING_F(AntiCheatLogger::LogCategory::SYSTEM, "线程隐藏设置失败，NTSTATUS: 0x%08X", status);
        else
            LOG_INFO(AntiCheatLogger::LogCategory::SYSTEM, "监控线程已设置为对调试器隐藏");
    }
    else
    {
        LOG_WARNING(AntiCheatLogger::LogCategory::SYSTEM, "NtSetInformationThread API 不可用，无法隐藏监控线程");
    }
}

void CheatMonitorImpl::CheckParentProcessAtStartup()
{
    DWORD parentPid = 0;
    std::string parentName;
    if (Utils::GetParentProcessInfo(parentPid, parentName))
    {
        std::transform(parentName.begin(), parentName.end(), parentName.begin(), ::tolower);
        if (parentName != "loader.exe")
        {
            AddEvidence(anti_cheat::ENVIRONMENT_INVALID_PARENT_PROCESS,
                        "Invalid parent process: " + parentName + " (PID: " + std::to_string(parentPid) + ")");
        }
    }
    else
    {
        LOG_INFO(AntiCheatLogger::LogCategory::SYSTEM, "Parent process not found - could be normal launcher behavior");
    }
}

void CheatMonitorImpl::DetectVirtualMachine()
{
    DetectVmByCpuid();
    DetectVmByRegistry();
    DetectVmByMacAddress();
}

void CheatMonitorImpl::DetectVmByCpuid()
{
    std::array<int, 4> cpuid_info;
    __cpuid(cpuid_info.data(), 1);
    if ((cpuid_info[2] >> 31) & 1)
    {
        AddEvidence(anti_cheat::ENVIRONMENT_VIRTUAL_MACHINE, "检测到虚拟机环境 (CPUID hypervisor bit)");
    }
    __cpuid(cpuid_info.data(), 0x40000000);
    std::string vendor_id;
    vendor_id.append(reinterpret_cast<char *>(&cpuid_info[1]), 4);
    vendor_id.append(reinterpret_cast<char *>(&cpuid_info[2]), 4);
    vendor_id.append(reinterpret_cast<char *>(&cpuid_info[3]), 4);
    if (vendor_id.find("VMware") != std::string::npos || vendor_id.find("KVMKVMKVM") != std::string::npos ||
        vendor_id.find("VBoxVBoxVBox") != std::string::npos || vendor_id.find("Microsoft Hv") != std::string::npos)
    {
        AddEvidence(anti_cheat::ENVIRONMENT_VIRTUAL_MACHINE, "检测到虚拟机环境 (CPUID vendor ID: " + vendor_id + ")");
    }
}

void CheatMonitorImpl::DetectVmByRegistry()
{
    const wchar_t *vmKeys[] = {L"HARDWARE\\DESCRIPTION\\System\\BIOS\\SystemManufacturer",
                               L"HARDWARE\\DESCRIPTION\\System\\BIOS\\SystemProductName"};
    const wchar_t *vmValues[] = {L"vmware", L"virtualbox", L"qemu", L"kvm", L"microsoft"};
    for (const auto &key : vmKeys)
    {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
        {
            wchar_t buffer[256];
            DWORD size = sizeof(buffer);
            if (RegQueryValueExW(hKey, L"SystemManufacturer", NULL, NULL, (LPBYTE)buffer, &size) == ERROR_SUCCESS)
            {
                std::wstring manufacturer(buffer);
                std::transform(manufacturer.begin(), manufacturer.end(), manufacturer.begin(), ::towlower);
                for (const auto &vm : vmValues)
                {
                    if (manufacturer.find(vm) != std::wstring::npos)
                    {
                        AddEvidence(anti_cheat::ENVIRONMENT_VIRTUAL_MACHINE,
                                    "检测到虚拟机环境 (Registry: " + Utils::WideToString(manufacturer) + ")");
                        RegCloseKey(hKey);
                        return;
                    }
                }
            }
            RegCloseKey(hKey);
        }
    }
}

void CheatMonitorImpl::DetectVmByMacAddress()
{
    const std::vector<std::string> vmMacPrefixes = {"00:05:69", "00:0C:29", "00:1C:14",
                                                     "00:50:56", "08:00:27", "00:15:5D"};
    ULONG bufferSize = sizeof(IP_ADAPTER_INFO);
    std::vector<BYTE> buffer(bufferSize);
    PIP_ADAPTER_INFO pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
    if (GetAdaptersInfo(pAdapterInfo, &bufferSize) == ERROR_BUFFER_OVERFLOW)
    {
        buffer.resize(bufferSize);
        pAdapterInfo = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
    }
    if (GetAdaptersInfo(pAdapterInfo, &bufferSize) == NO_ERROR)
    {
        while (pAdapterInfo)
        {
            char macStr[18];
            sprintf_s(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X", pAdapterInfo->Address[0],
                      pAdapterInfo->Address[1], pAdapterInfo->Address[2], pAdapterInfo->Address[3],
                      pAdapterInfo->Address[4], pAdapterInfo->Address[5]);
            for (const auto &prefix : vmMacPrefixes)
            {
                if (std::string(macStr).rfind(prefix, 0) == 0)
                {
                    AddEvidence(anti_cheat::ENVIRONMENT_VIRTUAL_MACHINE,
                                "检测到虚拟机环境 (MAC Address: " + std::string(macStr) + ")");
                    return;
                }
            }
            pAdapterInfo = pAdapterInfo->Next;
        }
    }
}

uintptr_t CheatMonitorImpl::FindVehListAddress()
{
    PVOID pDecoyHandler = nullptr;
    int retryCount = 0;
    int maxRetries = 3;
    while (!pDecoyHandler && retryCount < 3)
    {
        pDecoyHandler = AddVectoredExceptionHandler(1, SystemUtils::DecoyVehHandler);
        if (!pDecoyHandler)
        {
            retryCount++;
            if (retryCount < maxRetries) Sleep(300);
        }
    }
    if (!pDecoyHandler) return 0;

    uintptr_t listHeadAddress = 0;
    __try
    {
        const auto *pEntry = reinterpret_cast<const VECTORED_HANDLER_ENTRY *>(pDecoyHandler);
        const LIST_ENTRY *pCurrent = &pEntry->List;
        for (int i = 0; i < 100; ++i)
        {
            const LIST_ENTRY *pBlink = pCurrent->Blink;
            if (!SystemUtils::IsValidPointer(pBlink, sizeof(LIST_ENTRY)) ||
                !SystemUtils::IsValidPointer(pBlink->Flink, sizeof(LIST_ENTRY *)))
                break;
            if (pBlink->Flink == pCurrent)
            {
                listHeadAddress = reinterpret_cast<uintptr_t>(pBlink);
                break;
            }
            pCurrent = pBlink;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        listHeadAddress = 0;
    }
    RemoveVectoredExceptionHandler(pDecoyHandler);
    if (listHeadAddress == 0) return 0;

    uintptr_t structBaseAddress = 0;
    SystemUtils::WindowsVersion ver = SystemUtils::GetWindowsVersion();
    switch (ver)
    {
        case SystemUtils::WindowsVersion::Win_XP:
            structBaseAddress = listHeadAddress - offsetof(VECTORED_HANDLER_LIST_XP, List);
            break;
        case SystemUtils::WindowsVersion::Win_Vista_Win7:
            structBaseAddress = listHeadAddress - offsetof(VECTORED_HANDLER_LIST_VISTA, ExceptionList);
            break;
        default:
            structBaseAddress = listHeadAddress - offsetof(VECTORED_HANDLER_LIST_WIN8, ExceptionList);
            break;
    }
    LOG_INFO_F(AntiCheatLogger::LogCategory::SYSTEM, "Dynamically located VEH list structure at: 0x%p",
               (void *)structBaseAddress);
    return structBaseAddress;
}

VOID CALLBACK CheatMonitorImpl::DllLoadCallback(ULONG NotificationReason, const LDR_DLL_NOTIFICATION_DATA *NotificationData,
                                                PVOID Context)
{
    if (NotificationReason == LDR_DLL_NOTIFICATION_REASON_LOADED)
    {
        auto *impl = static_cast<CheatMonitorImpl *>(Context);
        if (impl) impl->OnDllLoaded(NotificationData->Loaded);
    }
}

void CheatMonitorImpl::RegisterDllNotification()
{
    if (!SystemUtils::HasApiCapability(SystemUtils::ApiCapability::LdrDllNotification))
    {
        LOG_INFO(AntiCheatLogger::LogCategory::SYSTEM, "当前OS能力矩阵未启用 LdrDllNotification，跳过DLL通知注册。");
        return;
    }
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return;
    auto pLdrRegisterDllNotification =
            (P_LdrRegisterDllNotification)GetProcAddress(hNtdll, "LdrRegisterDllNotification");
    if (pLdrRegisterDllNotification && !m_dllNotificationCookie)
    {
        pLdrRegisterDllNotification(0, DllLoadCallback, this, &m_dllNotificationCookie);
    }
}

void CheatMonitorImpl::UnregisterDllNotification()
{
    if (m_dllNotificationCookie)
    {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll)
        {
            auto pLdrUnregisterDllNotification =
                    (P_LdrUnregisterDllNotification)GetProcAddress(hNtdll, "LdrUnregisterDllNotification");
            if (pLdrUnregisterDllNotification)
            {
                pLdrUnregisterDllNotification(m_dllNotificationCookie);
            }
        }
        m_dllNotificationCookie = nullptr;
    }
}

void CheatMonitorImpl::OnDllLoaded(const LDR_DLL_LOAD_NOTIFICATION_DATA &data)
{
    if (!data.FullDllName || !data.FullDllName->Buffer) return;
    std::wstring modulePath(data.FullDllName->Buffer, data.FullDllName->Length / sizeof(WCHAR));
    if (Utils::IsWhitelistedModule(modulePath)) return;
    std::string pathStr = Utils::WideToString(modulePath);
    LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "Runtime DLL Loaded: %s", pathStr.c_str());
    AddEvidence(anti_cheat::RUNTIME_MODULE_INJECTION, "Runtime DLL load detected: " + pathStr);
}

void CheatMonitorImpl::OnProcessCreated(DWORD pid, const std::wstring &name)
{
    std::wstring lowerName = name;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::towlower);
    auto harmfulNames = CheatConfigManager::GetInstance().GetHarmfulProcessNames();
    if (harmfulNames)
    {
        for (const auto &harmful : *harmfulNames)
        {
            if (lowerName.find(harmful) != std::wstring::npos)
            {
                std::string u8Name = Utils::WideToString(name);
                LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "WMI Monitor: Harmful process detected: %s (PID: %lu)",
                              u8Name.c_str(), pid);
                AddEvidence(anti_cheat::RUNTIME_PROCESS_BLACKLIST, "Harmful process started: " + u8Name);
                return;
            }
        }
    }
}
