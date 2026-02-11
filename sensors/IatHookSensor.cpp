#include "IatHookSensor.h"
#include "../include/ScanContext.h"
#include "../utils/SystemUtils.h"
#include "../Logger.h"
#include <vector>

SensorExecutionResult IatHookSensor::Execute(ScanContext &context)
{
    // 重置失败原因
    m_lastFailureReason = anti_cheat::UNKNOWN_FAILURE;

    // 策略1：配置版本门控 - 检查当前OS是否满足配置的最低要求
    if (!IsOsSupported(context))
    {
        LOG_DEBUG(AntiCheatLogger::LogCategory::SENSOR, "IAT Hook检测已禁用：当前OS版本低于配置最低要求");
        RecordFailure(anti_cheat::IAT_OS_VERSION_UNSUPPORTED);
        return SensorExecutionResult::FAILURE;
    }

    const HMODULE hSelf = GetModuleHandle(NULL);
    if (!hSelf)
    {
        LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "IatHookSensor: 无法获取自身模块句柄");
        RecordFailure(anti_cheat::IAT_GET_MODULE_HANDLE_FAILED);
        return SensorExecutionResult::FAILURE;
    }

    // 生产环境优化：验证模块有效性
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(hSelf, &mbi, sizeof(mbi)) != sizeof(mbi))
    {
        LOG_WARNING(AntiCheatLogger::LogCategory::SENSOR, "IatHookSensor: 模块内存查询失败");
        RecordFailure(anti_cheat::IAT_VIRTUAL_QUERY_FAILED);
        return SensorExecutionResult::FAILURE;
    }

    // 检查内存状态
    if (mbi.State != MEM_COMMIT)
    {
        LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "IatHookSensor: 模块内存状态异常 (State=0x%08X)",
                      mbi.State);
        RecordFailure(anti_cheat::IAT_MEMORY_STATE_ABNORMAL);
        return SensorExecutionResult::FAILURE;
    }

    // 检查内存保护属性 - 模块基地址可能是数据段，不一定是可执行段
    // 只要内存是可访问的（可读或可执行），就认为是有效的模块内存
    bool hasValidAccess = (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
                                          PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;

    if (!hasValidAccess)
    {
        LOG_WARNING_F(AntiCheatLogger::LogCategory::SENSOR, "IatHookSensor: 模块内存访问权限异常 (Protect=0x%08X)",
                      mbi.Protect);
        RecordFailure(anti_cheat::IAT_MEMORY_STATE_ABNORMAL);
        return SensorExecutionResult::FAILURE;
    }

    // 记录调试信息
    LOG_DEBUG_F(AntiCheatLogger::LogCategory::SENSOR,
                "IatHookSensor: 模块内存状态正常 (State=0x%08X, Protect=0x%08X)", mbi.State, mbi.Protect);

    // 执行IAT钩子检测
    bool checkResult = PerformIatIntegrityCheck(context, hSelf);
    if (!checkResult)
    {
        // 失败原因已经在PerformIatIntegrityCheck中设置
        return SensorExecutionResult::FAILURE;
    }

    return SensorExecutionResult::SUCCESS;
}

bool IatHookSensor::PerformIatIntegrityCheck(ScanContext &context, HMODULE hSelf)
{
    const BYTE *baseAddress = reinterpret_cast<const BYTE *>(hSelf);

    // 1. 验证PE文件结构
    if (!ValidatePeStructure(baseAddress, context))
    {
        return false;
    }

    // 2. 检查导入表完整性
    if (!CheckImportTableIntegrity(context, baseAddress))
    {
        return false;
    }

    return true;
}

bool IatHookSensor::ValidatePeStructure(const BYTE *baseAddress, ScanContext &context)
{
    // 验证DOS头
    if (!baseAddress || !SystemUtils::IsValidPointer(baseAddress, sizeof(IMAGE_DOS_HEADER)))
    {
        LOG_ERROR(AntiCheatLogger::LogCategory::SENSOR, "IAT检测失败：无效的基地址");
        RecordFailure(anti_cheat::IAT_BASE_ADDRESS_INVALID);
        return false;
    }

    const IMAGE_DOS_HEADER *pDosHeader = reinterpret_cast<const IMAGE_DOS_HEADER *>(baseAddress);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        LOG_ERROR(AntiCheatLogger::LogCategory::SENSOR, "IAT检测失败：无效的DOS签名");
        RecordFailure(anti_cheat::IAT_DOS_SIGNATURE_INVALID);
        return false;
    }

    // 验证NT头
    const BYTE *ntHeaderAddress = baseAddress + pDosHeader->e_lfanew;
    if (!SystemUtils::IsValidPointer(ntHeaderAddress, sizeof(IMAGE_NT_HEADERS)))
    {
        LOG_ERROR(AntiCheatLogger::LogCategory::SENSOR, "IAT检测失败：NT头地址无效");
        RecordFailure(anti_cheat::IAT_NT_HEADER_INVALID);
        return false;
    }

    const IMAGE_NT_HEADERS *pNtHeaders = reinterpret_cast<const IMAGE_NT_HEADERS *>(ntHeaderAddress);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        LOG_ERROR(AntiCheatLogger::LogCategory::SENSOR, "IAT检测失败：无效的NT签名");
        RecordFailure(anti_cheat::IAT_NT_SIGNATURE_INVALID);
        return false;
    }

    return true;
}

bool IatHookSensor::CheckImportTableIntegrity(ScanContext &context, const BYTE *baseAddress)
{
    const IMAGE_NT_HEADERS *pNtHeaders = reinterpret_cast<const IMAGE_NT_HEADERS *>(
            baseAddress + reinterpret_cast<const IMAGE_DOS_HEADER *>(baseAddress)->e_lfanew);

    // 获取导入表目录
    IMAGE_DATA_DIRECTORY importDirectory = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDirectory.VirtualAddress == 0 || importDirectory.Size == 0)
    {
        // 对于反作弊程序，没有导入表是异常情况，因为需要调用大量系统API
        LOG_ERROR(AntiCheatLogger::LogCategory::SENSOR, "IAT检测失败：反作弊程序缺少导入表，可能被篡改");
        RecordFailure(anti_cheat::IAT_IMPORT_TABLE_ACCESS_FAILED);
        return false;
    }

    // 验证导入表地址
    const BYTE *importDescAddress = baseAddress + importDirectory.VirtualAddress;
    if (!SystemUtils::IsValidPointer(importDescAddress, sizeof(IMAGE_IMPORT_DESCRIPTOR)))
    {
        LOG_ERROR(AntiCheatLogger::LogCategory::SENSOR, "IAT检测失败：导入表地址无效");
        RecordFailure(anti_cheat::IAT_IMPORT_TABLE_ACCESS_FAILED);
        return false;
    }

    // 执行IAT钩子检测
    const IMAGE_IMPORT_DESCRIPTOR *pImportDesc =
            reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR *>(importDescAddress);

    // Moved CheckIatHooks implementation here locally
    CheckIatHooks(context, baseAddress, pImportDesc);

    return true;
}

void IatHookSensor::CheckIatHooks(ScanContext &context, const BYTE *baseAddress,
                                  const IMAGE_IMPORT_DESCRIPTOR *pImportDesc)
{
    const auto &baselineHashes = context.GetIatBaselineHashes();
    while (pImportDesc->Name)
    {
        const char *dllName = (const char *)(baseAddress + pImportDesc->Name);
        // Safety check for pointer?
        if (!SystemUtils::IsValidPointer(dllName, 1)) {
            pImportDesc++;
            continue;
        }

        auto it = baselineHashes.find(dllName);
        if (it != baselineHashes.end())
        {
            // Calculate current hash
            std::vector<uint8_t> current_iat_hashes;
            auto *pThunk = reinterpret_cast<IMAGE_THUNK_DATA *>((BYTE *)baseAddress + pImportDesc->FirstThunk);

            // Safety check for PThunk
            if (!SystemUtils::IsValidPointer(pThunk, sizeof(IMAGE_THUNK_DATA))) {
                 pImportDesc++;
                 continue;
            }

            while (pThunk->u1.AddressOfData)
            {
                uintptr_t func_ptr = pThunk->u1.Function;
                current_iat_hashes.insert(current_iat_hashes.end(), (uint8_t *)&func_ptr,
                                          (uint8_t *)&func_ptr + sizeof(func_ptr));
                pThunk++;
                if (!SystemUtils::IsValidPointer(pThunk, sizeof(IMAGE_THUNK_DATA))) break;
            }
            std::vector<uint8_t> currentHash =
                    SystemUtils::CalculateFnv1aHash(current_iat_hashes.data(), current_iat_hashes.size());

            if (currentHash != it->second)
            {
                context.AddEvidence(anti_cheat::INTEGRITY_API_HOOK, "检测到IAT Hook: " + std::string(dllName));
            }
        }
        pImportDesc++;
        if (!SystemUtils::IsValidPointer(pImportDesc, sizeof(IMAGE_IMPORT_DESCRIPTOR))) break;
    }
}
