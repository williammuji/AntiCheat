#pragma once

#include <string>
#include "anti_cheat.pb.h"

#include "ScanContext.h"

// 传感器权重分级枚举
enum class SensorWeight
{
    LIGHT,    // 0-10ms: AdvancedAntiDebug, SystemCodeIntegrity, IatHook, VehHook
    HEAVY,    // 100-1000ms: ThreadActivitySensor, ModuleActivitySensor, MemorySecuritySensor
    CRITICAL  // 1000-10000ms: ProcessHandle, ProcessAndWindowMonitor, ModuleIntegrity (分段扫描)
};

// 传感器执行结果枚举
enum class SensorExecutionResult
{
    SUCCESS = 0,  // 成功执行
    TIMEOUT = 1,  // 执行超时
    FAILURE = 2   // 执行失败
};

// ISensor: 所有检测传感器的抽象基类接口 (策略模式)
class ISensor
{
   public:
    virtual ~ISensor() = default;
    virtual const char *GetName() const = 0;     // 用于日志和调试
    virtual SensorWeight GetWeight() const = 0;  // 获取传感器权重分级
    virtual SensorExecutionResult Execute(ScanContext &context) = 0;

   public:
    // 获取最后一次失败原因 - 基类实现
    anti_cheat::SensorFailureReason GetLastFailureReason() const
    {
        return m_lastFailureReason;
    }

   protected:
    // 统一的失败原因记录方法 - 基类实现
    void RecordFailure(anti_cheat::SensorFailureReason reason)
    {
        m_lastFailureReason = reason;
    }

    // 统一的失败原因成员变量 - 所有传感器共享
    anti_cheat::SensorFailureReason m_lastFailureReason = anti_cheat::UNKNOWN_FAILURE;

    // 统一的OS版本检查接口 - 内联实现
    bool IsOsSupported(ScanContext &context) const
    {
        return context.IsCurrentOsSupported();
    }
};
