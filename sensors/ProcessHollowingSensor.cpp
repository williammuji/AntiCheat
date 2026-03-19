#include "ProcessHollowingSensor.h"
#include "SensorRuntimeContext.h"
#include "utils/SystemUtils.h"
#include "utils/Utils.h"
#include "Logger.h"
#include <vector>
#include <sstream>
#include <algorithm>

SensorExecutionResult ProcessHollowingSensor::Execute(SensorRuntimeContext &context)
{
    m_lastFailureReason = anti_cheat::UNKNOWN_FAILURE;

    // 1. Get main module handle (Base Address)
    HMODULE hModule = GetModuleHandleW(NULL);
    if (!hModule)
    {
         RecordFailure(anti_cheat::GET_MODULE_HANDLE_FAILED);
         return SensorExecutionResult::FAILURE;
    }

    // 2. Read PE headers in memory
    // Note: Read directly from own process memory, no ReadProcessMemory needed
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (!SystemUtils::IsReadableMemory(pDosHeader, sizeof(IMAGE_DOS_HEADER)))
    {
         RecordFailure(anti_cheat::MEMORY_ACCESS_EXCEPTION);
         return SensorExecutionResult::FAILURE;
    }

    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
         context.AddEvidence(anti_cheat::INTEGRITY_PROCESS_HOLLOWED, "Memory DOS Header signature invalid (Magic mismatch)");
         return SensorExecutionResult::SUCCESS;
    }

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    if (!SystemUtils::IsReadableMemory(pNtHeaders, sizeof(IMAGE_NT_HEADERS)))
    {
         RecordFailure(anti_cheat::MEMORY_ACCESS_EXCEPTION);
         return SensorExecutionResult::FAILURE;
    }

    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
         context.AddEvidence(anti_cheat::INTEGRITY_PROCESS_HOLLOWED, "Memory NT Header signature invalid");
         return SensorExecutionResult::SUCCESS;
    }

    // 3. Get module path and read disk file headers
    wchar_t modulePath[MAX_PATH];
    if (GetModuleFileNameW(hModule, modulePath, MAX_PATH) == 0)
    {
         RecordFailure(anti_cheat::GET_MODULE_PATH_FAILED);
         return SensorExecutionResult::FAILURE;
    }

    HANDLE hFile = CreateFileW(modulePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
         // File or its exclusive access is unavailable for some reason, ignore for now
         return SensorExecutionResult::FAILURE;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize < 4096) // File too small, cannot be a valid PE file
    {
         CloseHandle(hFile);
         return SensorExecutionResult::FAILURE;
    }

    // Read file header (4KB is enough for DOS+NT+SectionHeaders)
    std::vector<BYTE> fileHeaderBuffer(4096);
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, fileHeaderBuffer.data(), 4096, &bytesRead, NULL))
    {
         CloseHandle(hFile);
         RecordFailure(anti_cheat::SYSTEM_API_CALL_FAILED);
         return SensorExecutionResult::FAILURE;
    }
    CloseHandle(hFile);

    // 4. Parse disk PE header
    PIMAGE_DOS_HEADER pFileDosHeader = (PIMAGE_DOS_HEADER)fileHeaderBuffer.data();
    if (pFileDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        // Disk file header invalid? Maybe packed or encrypted
         return SensorExecutionResult::FAILURE;
    }

    PIMAGE_NT_HEADERS pFileNtHeaders = (PIMAGE_NT_HEADERS)(fileHeaderBuffer.data() + pFileDosHeader->e_lfanew);

    // Ensure NT header is within read range
    if ((BYTE*)pFileNtHeaders > fileHeaderBuffer.data() + bytesRead - sizeof(IMAGE_NT_HEADERS))
    {
         return SensorExecutionResult::FAILURE;
    }

    std::wstring normalizedPath = modulePath;
    std::transform(normalizedPath.begin(), normalizedPath.end(), normalizedPath.begin(), ::towlower);
    if (Utils::IsWhitelistedModule(normalizedPath))
    {
        return SensorExecutionResult::SUCCESS;
    }

    // 5. Critical field comparison: EntryPoint and SizeOfImage
    const bool entryMismatch =
            pNtHeaders->OptionalHeader.AddressOfEntryPoint != pFileNtHeaders->OptionalHeader.AddressOfEntryPoint;
    const bool sizeMismatch = pNtHeaders->OptionalHeader.SizeOfImage != pFileNtHeaders->OptionalHeader.SizeOfImage;

    // 6. Double confirmation: Entry page permissions/type anomaly, or multiple primary signals
    bool entryPageAnomaly = false;
    BYTE *entryAddress = reinterpret_cast<BYTE *>(hModule) + pNtHeaders->OptionalHeader.AddressOfEntryPoint;
    MEMORY_BASIC_INFORMATION entryMbi = {};
    if (VirtualQuery(entryAddress, &entryMbi, sizeof(entryMbi)) == sizeof(entryMbi))
    {
        const bool execWritable =
                (entryMbi.Protect & PAGE_EXECUTE_READWRITE) || (entryMbi.Protect & PAGE_EXECUTE_WRITECOPY);
        const bool notImageType = entryMbi.Type != MEM_IMAGE;
        entryPageAnomaly = execWritable || notImageType;
    }
    const bool multiPrimarySignals = entryMismatch && sizeMismatch;
    const bool confirmed = multiPrimarySignals || ((entryMismatch || sizeMismatch) && entryPageAnomaly);

    if (confirmed)
    {
        std::ostringstream oss;
        oss << "Process Hollowing Detected:";
        if (entryMismatch)
        {
            oss << " EntryPoint mismatch(mem=0x" << std::hex << pNtHeaders->OptionalHeader.AddressOfEntryPoint
                << ",disk=0x" << pFileNtHeaders->OptionalHeader.AddressOfEntryPoint << ")";
        }
        if (sizeMismatch)
        {
            oss << " SizeOfImage mismatch(mem=0x" << std::hex << pNtHeaders->OptionalHeader.SizeOfImage
                << ",disk=0x" << pFileNtHeaders->OptionalHeader.SizeOfImage << ")";
        }
        if (entryPageAnomaly)
        {
            oss << " EntryPageAnomaly(protect=0x" << std::hex << entryMbi.Protect << ",type=0x" << entryMbi.Type << ")";
        }
        context.AddEvidence(anti_cheat::INTEGRITY_PROCESS_HOLLOWED, oss.str());
    }

    return SensorExecutionResult::SUCCESS;
}
