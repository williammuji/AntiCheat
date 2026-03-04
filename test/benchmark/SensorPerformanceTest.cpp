#include <iostream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <memory>
#include <Windows.h>
#include <string>
#include <algorithm>

#include "ISensor.h"
#include "SensorRuntimeContext.h"
#include "CheatMonitorEngine.h"
#include "utils/SystemUtils.h"
#include "CheatConfigManager.h"

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
    long long total_cycle_us;
    int shards;
    SensorWeight weight;
};

int main() {
    SystemUtils::EnsureNtApisLoaded();
    std::cout << "=== Anti-Cheat Sensor Performance Benchmark (Full Mode) ===" << std::endl;

    // Force 100ms budget for benchmark to see sharding without excessive log overhead
    CheatConfigManager::GetInstance().UpdateHeavyScanBudgetMs(100);

    CheatMonitorEngine engine;
    engine.InitializeSystem(); // 核心初始化，包括获取 VEH 地址、OS 版本等

    SensorRuntimeContext context(&engine);
    context.RefreshModuleCache(); // 填充模块缓存，供 ModuleActivitySensor 使用

    // 模拟基本初始化环境
    engine.m_gameWindowHandle.store(reinterpret_cast<uintptr_t>(GetConsoleWindow()), std::memory_order_relaxed);

    std::vector<std::unique_ptr<ISensor>> test_sensors;
    test_sensors.push_back(std::make_unique<AdvancedAntiDebugSensor>());
    test_sensors.push_back(std::make_unique<DriverIntegritySensor>());
    test_sensors.push_back(std::make_unique<IatHookSensor>());
    test_sensors.push_back(std::make_unique<InlineHookSensor>());
    test_sensors.push_back(std::make_unique<MemorySecuritySensor>());
    test_sensors.push_back(std::make_unique<ModuleActivitySensor>());
    test_sensors.push_back(std::make_unique<ModuleIntegritySensor>());
    test_sensors.push_back(std::make_unique<ProcessAndWindowMonitorSensor>());
    test_sensors.push_back(std::make_unique<ProcessHandleSensor>());
    test_sensors.push_back(std::make_unique<ProcessHollowingSensor>());
    test_sensors.push_back(std::make_unique<SystemCodeIntegritySensor>());
    test_sensors.push_back(std::make_unique<ThreadActivitySensor>());
    test_sensors.push_back(std::make_unique<VTableHookSensor>());
    test_sensors.push_back(std::make_unique<VehHookSensor>());

    std::vector<BenchmarkResult> results;

    for (auto& sensor : test_sensors) {
        long long total_us = 0;
        int shards = 0;
        bool failed = false;

        // Execute until complete cycle finished
        while (true) {
            auto start = std::chrono::high_resolution_clock::now();
            SensorExecutionResult res = sensor->Execute(context);
            auto end = std::chrono::high_resolution_clock::now();

            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
            total_us += duration;
            shards++;

            if (res == SensorExecutionResult::SUCCESS || res == SensorExecutionResult::FAILURE) {
                if (res == SensorExecutionResult::FAILURE) failed = true;
                break;
            }

            // Add a safety break
            if (shards > 10000) break;
        }

        results.push_back({sensor.get()->GetName(), shards > 0 ? total_us / shards : 0, total_us, shards, sensor->GetWeight()});
    }

    std::cout << "\n" << std::setw(32) << std::left << "Sensor Name"
              << std::setw(10) << "Weight"
              << std::setw(15) << "Avg Seg (us)"
              << std::setw(15) << "Full Cycle(us)"
              << std::setw(10) << "Shards" << std::endl;
    std::cout << std::string(85, '-') << std::endl;

    for (const auto& res : results) {
        std::string weight_str;
        switch (res.weight) {
            case SensorWeight::LIGHT: weight_str = "LIGHT"; break;
            case SensorWeight::HEAVY: weight_str = "HEAVY"; break;
            case SensorWeight::CRITICAL: weight_str = "CRITICAL"; break;
        }

        std::cout << std::setw(32) << std::left << res.name
                  << std::setw(10) << weight_str
                  << std::setw(15) << res.avg_segment_us
                  << std::setw(15) << res.total_cycle_us
                  << std::setw(10) << res.shards << std::endl;
    }

    return 0;
}
