#include <iostream>
#include <vector>
#include <chrono>
#include <iomanip>
#include <memory>
#include <Windows.h>

#include "ISensor.h"
#include "SensorRuntimeContext.h"
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
    long long segment_us;
    long long total_cycle_us;
    int segments;
    SensorWeight weight;
};

int main() {
    std::cout << "=== Anti-Cheat Sensor Performance Benchmark ===" << std::endl;
    std::cout << "Windows Version: " << (int)SystemUtils::GetWindowsVersion() << std::endl;

    SensorRuntimeContext context;
    // 模拟基本初始化环境
    context.SetGameWindowHandle(NULL);

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
        int segments = 0;
        long long first_segment_us = 0;

        // 我们运行直到它不再由于超时而失败，并记录总耗时和分段数
        while (true) {
            auto start = std::chrono::high_resolution_clock::now();
            SensorExecutionResult res = sensor->Execute(context);
            auto end = std::chrono::high_resolution_clock::now();

            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
            total_us += duration;
            segments++;
            if (segments == 1) first_segment_us = duration;

            // 如果执行成功，则认为周期结束
            if (res == SensorExecutionResult::SUCCESS) {
                break;
            }

            // 安全退出，防止死循环
            if (segments > 1000) break;
        }

        results.push_back({sensor->GetName(), first_segment_us, total_us, segments, sensor->GetWeight()});
    }

    std::cout << "\n" << std::setw(30) << std::left << "Sensor Name"
              << std::setw(15) << "Weight"
              << std::setw(15) << "Segment (us)"
              << std::setw(18) << "Total Cycle (us)"
              << std::setw(10) << "Segments" << std::endl;
    std::cout << std::string(90, '-') << std::endl;

    for (const auto& res : results) {
        std::string weight_str;
        switch (res.weight) {
            case SensorWeight::LIGHT: weight_str = "LIGHT"; break;
            case SensorWeight::HEAVY: weight_str = "HEAVY"; break;
            case SensorWeight::CRITICAL: weight_str = "CRITICAL"; break;
        }

        std::cout << std::setw(30) << std::left << res.name
                  << std::setw(15) << weight_str
                  << std::setw(15) << res.segment_us
                  << std::setw(18) << res.total_cycle_us
                  << std::setw(10) << res.segments << std::endl;
    }

    return 0;
}
