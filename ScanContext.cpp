#include "SensorRuntimeContext.h"
#include "CheatMonitorEngine.h"
#include "CheatConfigManager.h"
#include "utils/Utils.h"
#include "utils/SystemUtils.h"

#include <psapi.h>
#include <algorithm>

SensorRuntimeContext::SensorRuntimeContext(CheatMonitorEngine *engine, bool targetedScan)
    : m_engine(engine), m_isTargetedScan(targetedScan)
{
}

SensorRuntimeContext::~SensorRuntimeContext()
{
}

void SensorRuntimeContext::RefreshModuleCache()
{
    CachedModules.clear();
    CachedMemoryRegions.clear();
    IsMemoryCacheValid = false;

    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded))
    {
        size_t count = cbNeeded / sizeof(HMODULE);
        CachedModules.assign(hMods, hMods + count);
    }
}

void SensorRuntimeContext::RefreshMemoryCache()
{
    CachedMemoryRegions.clear();
    IsMemoryCacheValid = false;

    LPBYTE address = nullptr;
    MEMORY_BASIC_INFORMATION mbi;
    const uintptr_t maxAddress = sizeof(void *) == 4 ? 0x7FFFFFFF : 0x7FFFFFFFFFFF;

    while (VirtualQuery(address, &mbi, sizeof(mbi)))
    {
        CachedMemoryRegions.push_back(mbi);

        address = reinterpret_cast<LPBYTE>(mbi.BaseAddress) + mbi.RegionSize;

        if (address < reinterpret_cast<LPBYTE>(mbi.BaseAddress) ||
            reinterpret_cast<uintptr_t>(address) > maxAddress)
        {
            break;
        }
    }
    IsMemoryCacheValid = true;
}

bool SensorRuntimeContext::IsTargetedScan() const
{
    return m_isTargetedScan;
}

void SensorRuntimeContext::AddEvidence(anti_cheat::CheatCategory category, const std::string &description)
{
    m_engine->AddEvidence(category, description);
}

std::shared_ptr<const std::vector<std::wstring>> SensorRuntimeContext::GetHarmfulProcessNames() const
{
    return CheatConfigManager::GetInstance().GetHarmfulProcessNames();
}

std::shared_ptr<const std::vector<std::wstring>> SensorRuntimeContext::GetHarmfulKeywords() const
{
    return CheatConfigManager::GetInstance().GetHarmfulKeywords();
}

std::shared_ptr<const std::unordered_set<std::wstring>> SensorRuntimeContext::GetWhitelistedProcessPaths() const
{
    return CheatConfigManager::GetInstance().GetWhitelistedProcessPaths();
}

std::shared_ptr<const std::unordered_set<std::wstring>> SensorRuntimeContext::GetWhitelistedWindowKeywords() const
{
    return CheatConfigManager::GetInstance().GetWhitelistedWindowKeywords();
}

std::shared_ptr<const std::unordered_set<std::wstring>> SensorRuntimeContext::GetWhitelistedVEHModules() const
{
    return CheatConfigManager::GetInstance().GetWhitelistedVEHModules();
}

std::shared_ptr<const std::unordered_set<std::wstring>> SensorRuntimeContext::GetWhitelistedSystemModules() const
{
    return CheatConfigManager::GetInstance().GetWhitelistedSystemModules();
}

std::shared_ptr<const std::unordered_set<std::wstring>> SensorRuntimeContext::GetWhitelistedIntegrityIgnoreList() const
{
    return CheatConfigManager::GetInstance().GetWhitelistedIntegrityIgnoreList();
}

const std::unordered_map<std::string, std::vector<uint8_t>> &SensorRuntimeContext::GetIatBaselineHashes() const
{
    return m_engine->m_iatBaselineHashes;
}

const std::unordered_map<std::wstring, std::vector<uint8_t>> &SensorRuntimeContext::GetModuleBaselineHashes() const
{
    return m_engine->m_moduleBaselineHashes;
}

void SensorRuntimeContext::UpdateModuleBaselineHash(const std::wstring &modulePath, const std::vector<uint8_t> &hash)
{
    m_engine->UpdateModuleBaselineHash(modulePath, hash);
}

const uintptr_t SensorRuntimeContext::GetVehListAddress() const
{
    return m_engine->m_vehListAddress;
}

SystemUtils::WindowsVersion SensorRuntimeContext::GetWindowsVersion() const
{
    return m_engine->m_windowsVersion;
}

bool SensorRuntimeContext::IsCurrentOsSupported() const
{
    return m_engine->IsCurrentOsSupported();
}


bool SensorRuntimeContext::IsAddressInLegitimateModule(PVOID address, std::wstring &outModulePath)
{
    return m_engine->IsAddressInLegitimateModule(address, outModulePath);
}

bool SensorRuntimeContext::IsAddressInLegitimateModule(PVOID address)
{
    return m_engine->IsAddressInLegitimateModule(address);
}

std::shared_ptr<const std::unordered_set<std::wstring>> SensorRuntimeContext::GetKnownGoodHandleHolders() const
{
    return CheatConfigManager::GetInstance().GetWhitelistedProcessPaths();
}

void SensorRuntimeContext::UploadTelemetryMetricsReport(const anti_cheat::TelemetryMetrics &metrics)
{
    m_engine->UploadTelemetryMetricsReport(metrics);
}

void SensorRuntimeContext::SendServerLog(const std::string &log_level, const std::string &log_category, const std::string &log_message)
{
    m_engine->SendServerLog(log_level, log_category, log_message);
}

void SensorRuntimeContext::RecordSensorWorkloadCounters(const std::string &name, uint64_t snapshot_size, uint64_t attempts, uint64_t hits)
{
    m_engine->RecordSensorWorkloadCounters(name, snapshot_size, attempts, hits);
}

std::set<DWORD> SensorRuntimeContext::GetKnownThreadIds() const
{
    std::lock_guard<std::mutex> lock(m_engine->m_baselineMutex);
    return m_engine->m_knownThreadIds;
}

std::set<HMODULE> SensorRuntimeContext::GetKnownModules() const
{
    std::lock_guard<std::mutex> lock(m_engine->m_baselineMutex);
    return m_engine->m_knownModules;
}

bool SensorRuntimeContext::InsertKnownThreadId(DWORD threadId)
{
    std::lock_guard<std::mutex> lock(m_engine->m_baselineMutex);
    return m_engine->m_knownThreadIds.insert(threadId).second;
}

bool SensorRuntimeContext::IsModuleKnown(HMODULE hModule) const
{
    std::lock_guard<std::mutex> lock(m_engine->m_baselineMutex);
    return m_engine->m_knownModules.find(hModule) != m_engine->m_knownModules.end();
}

bool SensorRuntimeContext::InsertKnownModule(HMODULE hModule)
{
    std::lock_guard<std::mutex> lock(m_engine->m_baselineMutex);
    return m_engine->m_knownModules.insert(hModule).second;
}

void SensorRuntimeContext::VerifyModuleSignature(HMODULE hModule)
{
    m_engine->VerifyModuleSignature(hModule);
}

void SensorRuntimeContext::CheckSelfIntegrity()
{
    m_engine->CheckSelfIntegrity();
}

const HMODULE SensorRuntimeContext::GetSelfModuleHandle() const
{
    return m_engine->m_hSelfModule;
}

size_t SensorRuntimeContext::GetHandleCursorOffset() const
{
    return m_engine->m_handleCursorOffset;
}

void SensorRuntimeContext::SetHandleCursorOffset(size_t v)
{
    m_engine->m_handleCursorOffset = v;
}

size_t SensorRuntimeContext::GetModuleCursorOffset() const
{
    return m_engine->m_moduleCursorOffset;
}

void SensorRuntimeContext::SetModuleCursorOffset(size_t v)
{
    m_engine->m_moduleCursorOffset = v;
}

size_t SensorRuntimeContext::GetProcessCursorOffset() const
{
    return m_engine->m_processCursorOffset;
}

void SensorRuntimeContext::SetProcessCursorOffset(size_t v)
{
    m_engine->m_processCursorOffset = v;
}

std::unordered_map<DWORD, std::chrono::steady_clock::time_point> &SensorRuntimeContext::GetPidThrottleUntil()
{
    return m_engine->m_pidThrottleUntil;
}

std::unordered_map<std::wstring, std::pair<Utils::SignatureStatus, std::chrono::steady_clock::time_point>> &
SensorRuntimeContext::GetProcessSigCache()
{
    return m_engine->m_processSigCache;
}

std::unordered_map<std::wstring, std::chrono::steady_clock::time_point> &SensorRuntimeContext::GetProcessSigThrottleUntil()
{
    return m_engine->m_processSigThrottleUntil;
}
