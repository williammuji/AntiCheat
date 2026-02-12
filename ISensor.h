#pragma once

#include <string>
#include "anti_cheat.pb.h"

#include "SensorRuntimeContext.h"

// 浼犳劅鍣ㄦ潈閲嶅垎绾ф灇涓?
enum class SensorWeight
{
    LIGHT,    // 0-10ms: AdvancedAntiDebug, SystemCodeIntegrity, IatHook, VehHook
    HEAVY,    // 100-1000ms: ThreadActivitySensor, ModuleActivitySensor, MemorySecuritySensor
    CRITICAL  // 1000-10000ms: ProcessHandle, ProcessAndWindowMonitor, ModuleIntegrity (鍒嗘鎵弿)
};

// 浼犳劅鍣ㄦ墽琛岀粨鏋滄灇涓?
enum class SensorExecutionResult
{
    SUCCESS = 0,  // 鎴愬姛鎵ц
    TIMEOUT = 1,  // 鎵ц瓒呮椂
    FAILURE = 2   // 鎵ц澶辫触
};

// ISensor: 鎵€鏈夋娴嬩紶鎰熷櫒鐨勬娊璞″熀绫绘帴鍙?(绛栫暐妯″紡)
class ISensor
{
   public:
    virtual ~ISensor() = default;
    virtual const char *GetName() const = 0;     // 鐢ㄤ簬鏃ュ織鍜岃皟璇?
    virtual SensorWeight GetWeight() const = 0;  // 鑾峰彇浼犳劅鍣ㄦ潈閲嶅垎绾?
    virtual SensorExecutionResult Execute(SensorRuntimeContext &context) = 0;

   public:
    // 鑾峰彇鏈€鍚庝竴娆″け璐ュ師鍥?- 鍩虹被瀹炵幇
    anti_cheat::SensorFailureReason GetLastFailureReason() const
    {
        return m_lastFailureReason;
    }

   protected:
    // 缁熶竴鐨勫け璐ュ師鍥犺褰曟柟娉?- 鍩虹被瀹炵幇
    void RecordFailure(anti_cheat::SensorFailureReason reason)
    {
        m_lastFailureReason = reason;
    }

    // 缁熶竴鐨勫け璐ュ師鍥犳垚鍛樺彉閲?- 鎵€鏈変紶鎰熷櫒鍏变韩
    anti_cheat::SensorFailureReason m_lastFailureReason = anti_cheat::UNKNOWN_FAILURE;

    // 缁熶竴鐨凮S鐗堟湰妫€鏌ユ帴鍙?- 鍐呰仈瀹炵幇
    bool IsOsSupported(SensorRuntimeContext &context) const
    {
        return context.IsCurrentOsSupported();
    }
};
