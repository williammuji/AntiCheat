#include "include/ScanContext.h"
#include "include/CheatMonitorImpl.h"
#include "CheatConfigManager.h"
#include "utils/Utils.h"
#include "utils/SystemUtils.h"

#include <psapi.h>
#include <algorithm>

ScanContext::ScanContext(CheatMonitorImpl *pimpl, bool targetedScan)
    : m_pimpl(pimpl), m_isTargetedScan(targetedScan)
{
}

ScanContext::~ScanContext()
{
}

void ScanContext::RefreshModuleCache()
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

void ScanContext::RefreshMemoryCache()
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

bool ScanContext::IsTargetedScan() const
{
    return m_isTargetedScan;
}

void ScanContext::AddEvidence(anti_cheat::CheatCategory category, const std::string &description)
{
    m_pimpl->AddEvidence(category, description);
}

std::shared_ptr<const std::vector<std::wstring>> ScanContext::GetHarmfulProcessNames() const
{
    return CheatConfigManager::GetInstance().GetHarmfulProcessNames();
}

std::shared_ptr<const std::vector<std::wstring>> ScanContext::GetHarmfulKeywords() const
{
    return CheatConfigManager::GetInstance().GetHarmfulKeywords();
}

std::shared_ptr<const std::unordered_set<std::wstring>> ScanContext::GetWhitelistedProcessPaths() const
{
    return CheatConfigManager::GetInstance().GetWhitelistedProcessPaths();
}

std::shared_ptr<const std::unordered_set<std::wstring>> ScanContext::GetWhitelistedWindowKeywords() const
{
    return CheatConfigManager::GetInstance().GetWhitelistedWindowKeywords();
}

std::shared_ptr<const std::unordered_set<std::wstring>> ScanContext::GetWhitelistedVEHModules() const
{
    return CheatConfigManager::GetInstance().GetWhitelistedVEHModules();
}

const std::unordered_map<std::string, std::vector<uint8_t>> &ScanContext::GetIatBaselineHashes() const
{
    return m_pimpl->m_iatBaselineHashes;
}

const std::unordered_map<std::wstring, std::vector<uint8_t>> &ScanContext::GetModuleBaselineHashes() const
{
    return m_pimpl->m_moduleBaselineHashes;
}

void ScanContext::UpdateModuleBaselineHash(const std::wstring &modulePath, const std::vector<uint8_t> &hash)
{
    m_pimpl->UpdateModuleBaselineHash(modulePath, hash);
}

const uintptr_t ScanContext::GetVehListAddress() const
{
    return m_pimpl->m_vehListAddress;
}

SystemUtils::WindowsVersion ScanContext::GetWindowsVersion() const
{
    return m_pimpl->m_windowsVersion;
}

bool ScanContext::IsCurrentOsSupported() const
{
    return m_pimpl->IsCurrentOsSupported();
}

void ScanContext::CheckIatHooks(const BYTE *baseAddress, const IMAGE_IMPORT_DESCRIPTOR *pImportDesc)
{
    m_pimpl->CheckIatHooks(*this, baseAddress, pImportDesc);
}

bool ScanContext::IsAddressInLegitimateModule(PVOID address, std::wstring &outModulePath)
{
    return m_pimpl->IsAddressInLegitimateModule(address, outModulePath);
}

bool ScanContext::IsAddressInLegitimateModule(PVOID address)
{
    return m_pimpl->IsAddressInLegitimateModule(address);
}

std::shared_ptr<const std::unordered_set<std::wstring>> ScanContext::GetKnownGoodHandleHolders() const
{
    return CheatConfigManager::GetInstance().GetWhitelistedProcessPaths();
}

void ScanContext::UploadTelemetryMetricsReport(const anti_cheat::TelemetryMetrics &metrics)
{
    m_pimpl->UploadTelemetryMetricsReport(metrics);
}

void ScanContext::SendServerLog(const std::string &log_level, const std::string &log_category, const std::string &log_message)
{
    m_pimpl->SendServerLog(log_level, log_category, log_message);
}

void ScanContext::RecordSensorWorkloadCounters(const std::string &name, uint64_t snapshot_size, uint64_t attempts, uint64_t hits)
{
    m_pimpl->RecordSensorWorkloadCounters(name, snapshot_size, attempts, hits);
}

std::set<DWORD> ScanContext::GetKnownThreadIds() const
{
    std::lock_guard<std::mutex> lock(m_pimpl->m_baselineMutex);
    return m_pimpl->m_knownThreadIds;
}

std::set<HMODULE> ScanContext::GetKnownModules() const
{
    std::lock_guard<std::mutex> lock(m_pimpl->m_baselineMutex);
    return m_pimpl->m_knownModules;
}

bool ScanContext::InsertKnownThreadId(DWORD threadId)
{
    std::lock_guard<std::mutex> lock(m_pimpl->m_baselineMutex);
    return m_pimpl->m_knownThreadIds.insert(threadId).second;
}

bool ScanContext::IsModuleKnown(HMODULE hModule) const
{
    std::lock_guard<std::mutex> lock(m_pimpl->m_baselineMutex);
    return m_pimpl->m_knownModules.find(hModule) != m_pimpl->m_knownModules.end();
}

bool ScanContext::InsertKnownModule(HMODULE hModule)
{
    std::lock_guard<std::mutex> lock(m_pimpl->m_baselineMutex);
    return m_pimpl->m_knownModules.insert(hModule).second;
}

void ScanContext::VerifyModuleSignature(HMODULE hModule)
{
    m_pimpl->VerifyModuleSignature(hModule);
}

void ScanContext::CheckSelfIntegrity()
{
    m_pimpl->CheckSelfIntegrity();
}

const HMODULE ScanContext::GetSelfModuleHandle() const
{
    return m_pimpl->m_hSelfModule;
}

size_t ScanContext::GetHandleCursorOffset() const
{
    return m_pimpl->m_handleCursorOffset;
}

void ScanContext::SetHandleCursorOffset(size_t v)
{
    m_pimpl->m_handleCursorOffset = v;
}

size_t ScanContext::GetModuleCursorOffset() const
{
    return m_pimpl->m_moduleCursorOffset;
}

void ScanContext::SetModuleCursorOffset(size_t v)
{
    m_pimpl->m_moduleCursorOffset = v;
}

size_t ScanContext::GetProcessCursorOffset() const
{
    return m_pimpl->m_processCursorOffset;
}

void ScanContext::SetProcessCursorOffset(size_t v)
{
    m_pimpl->m_processCursorOffset = v;
}

std::unordered_map<DWORD, std::chrono::steady_clock::time_point> &ScanContext::GetPidThrottleUntil()
{
    return m_pimpl->m_pidThrottleUntil;
}

std::unordered_map<std::wstring, std::pair<Utils::SignatureStatus, std::chrono::steady_clock::time_point>> &
ScanContext::GetProcessSigCache()
{
    return m_pimpl->m_processSigCache;
}

std::unordered_map<std::wstring, std::chrono::steady_clock::time_point> &ScanContext::GetProcessSigThrottleUntil()
{
    return m_pimpl->m_processSigThrottleUntil;
}
