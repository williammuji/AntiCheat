#pragma once

#include "../include/ISensor.h"

class DriverIntegritySensor : public ISensor
{
public:
    const char *GetName() const override { return "DriverIntegritySensor"; }
    SensorWeight GetWeight() const override { return SensorWeight::HEAVY; } // 涉及文件I/O和签名验证
    SensorExecutionResult Execute(ScanContext &context) override;

private:
    bool VerifyDriverSignature(const std::wstring& filePath);
};
