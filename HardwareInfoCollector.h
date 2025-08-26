#pragma once

#include <memory>
#include <string>
#include <vector>

// Protobuf generated header
#include "anti_cheat.pb.h"

namespace anti_cheat {

// 负责采集一次性硬件信息（磁盘序列号、MAC、计算机名、OS版本、CPU品牌等）。
// 与传感器分离，便于在上报作弊证据时附带硬件信息。
class HardwareInfoCollector {
public:
    // 若尚未采集则执行采集；返回是否本次调用刚刚完成采集（用于记录一次性证据）。
    bool EnsureCollected();

    // 返回内置指针（只读）。可能为nullptr（尚未采集或已被消费）。
    const HardwareFingerprint* GetFingerprint() const { return fingerprint_.get(); }

    // 取走当前指纹（上报后清空）。
    std::unique_ptr<HardwareFingerprint> ConsumeFingerprint();

private:
    std::unique_ptr<HardwareFingerprint> fingerprint_;
};

} // namespace anti_cheat
