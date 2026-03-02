#include <iostream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <memory>
#include <Windows.h>

#include "ISensor.h"
#include "SensorRuntimeContext.h"
#include "CheatMonitorEngine.h"
#include "utils/SystemUtils.h"

// 包含所有传感器头文件
#include "sensors/AdvancedAntiDebugSensor.h"
#include "sensors/DriverIntegritySensor.h"
#include "sensors/IatHookSensor.h"
#include "sensors/InlineHookSensor.h"
#include "sensors/MemorySecuritySensor.h"
#include "sensors/ModuleActivitySensor.h"
#include "sensors/ModuleIntegritySensor.h"
#include "sensors/ProcessAndWindowMonitorSensor.h"
#include "sensors/ProcessHandleSensor.h"
#include "sensors/ProcessHollowingSensor.h"
#include "sensors/SystemCodeIntegritySensor.h"
#include "sensors/ThreadActivitySensor.h"
#include "sensors/VTableHookSensor.h"
#include "sensors/VehHookSensor.h"

struct BenchmarkResult {
    std::string name;
    long long avg_segment_us;
    long long max_segment_us;
    long long total_cycle_us;
    int segments;
    SensorWeight weight;
};

int main() {
    SystemUtils::EnsureNtApisLoaded();
    std::cout << "=== Anti-Cheat Sensor Performance Benchmark ===" << std::endl;
    std::cout << "Windows Version: " << (int)SystemUtils::GetWindowsVersion() << std::endl;

    CheatMonitorEngine engine;
    engine.InitializeSystem(); // 核心初始化，包括获取 VEH 地址、OS 版本等

    SensorRuntimeContext context(&engine);
    context.RefreshModuleCache(); // 填充模块缓存，供 ModuleActivitySensor 使用

    // 模拟基本初始化环境
    engine.m_gameWindowHandle.store(reinterpret_cast<uintptr_t>(GetConsoleWindow()), std::memory_order_relaxed);

    std::vector<std::unique_ptr<ISensor>> sensors;
    sensors.push_back(std::make_unique<AdvancedAntiDebugSensor>());
    sensors.push_back(std::make_unique<DriverIntegritySensor>());
    sensors.push_back(std::make_unique<IatHookSensor>());
    sensors.push_back(std::make_unique<InlineHookSensor>());
    sensors.push_back(std::make_unique<MemorySecuritySensor>());
    sensors.push_back(std::make_unique<ModuleActivitySensor>());
    sensors.push_back(std::make_unique<ModuleIntegritySensor>());
    sensors.push_back(std::make_unique<ProcessAndWindowMonitorSensor>());
    sensors.push_back(std::make_unique<ProcessHandleSensor>());
    sensors.push_back(std::make_unique<ProcessHollowingSensor>());
    sensors.push_back(std::make_unique<SystemCodeIntegritySensor>());
    sensors.push_back(std::make_unique<ThreadActivitySensor>());
    sensors.push_back(std::make_unique<VTableHookSensor>());
    sensors.push_back(std::make_unique<VehHookSensor>());

    std::vector<BenchmarkResult> results;

    for (auto& sensor : sensors) {
        long long total_us = 0;
        long long max_segment_us = 0;
        int segments = 0;
        bool failed = false;

        // 仅在返回 TIMEOUT 时进行分段重试
        while (true) {
            auto start = std::chrono::high_resolution_clock::now();
            SensorExecutionResult res = sensor->Execute(context);
            auto end = std::chrono::high_resolution_clock::now();

            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
            total_us += duration;
            if (duration > max_segment_us) max_segment_us = duration;
            segments++;

            if (res == SensorExecutionResult::SUCCESS) {
                break;
            } else if (res == SensorExecutionResult::FAILURE) {
                failed = true;
                break;
            }

            // res == TIMEOUT，继续下一段
            if (segments >= 1000) break;
        }

        std::string name = sensor->GetName();
        if (failed) name += " [FAILED]";
        results.push_back({name, total_us / segments, max_segment_us, total_us, segments, sensor->GetWeight()});
    }

    std::cout << "\n" << std::setw(30) << std::left << "Sensor Name"
              << std::setw(12) << "Weight"
              << std::setw(15) << "Avg Seg (us)"
              << std::setw(15) << "Max Seg (us)"
              << std::setw(18) << "Total Cycle(us)"
              << std::setw(10) << "Segs" << std::endl;
    std::cout << std::string(100, '-') << std::endl;

    for (const auto& res : results) {
        std::string weight_str;
        switch (res.weight) {
            case SensorWeight::LIGHT: weight_str = "LIGHT"; break;
            case SensorWeight::HEAVY: weight_str = "HEAVY"; break;
            case SensorWeight::CRITICAL: weight_str = "CRITICAL"; break;
        }

        std::cout << std::setw(30) << std::left << res.name
                  << std::setw(12) << weight_str
                  << std::setw(15) << res.avg_segment_us
                  << std::setw(15) << res.max_segment_us
                  << std::setw(18) << res.total_cycle_us
                  << std::setw(10) << res.segments << std::endl;
    }

    return 0;
}
