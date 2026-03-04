#include <cstdint>
#include <cstddef>
#include <vector>
#include <iostream>

#include "sensors/MemorySecuritySensor.h"
#include "CheatMonitorEngine.h"
#include "SensorRuntimeContext.h"

// Basic Fuzzer for sensor parsing logic
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Initialize required objects
    CheatMonitorEngine engine;
    SensorRuntimeContext context(&engine);

    // We can simulate feeding this memory to MemorySecuritySensor's PE checker
    // CheckHiddenMemoryRegion is private but we can use the MemorySecuritySensorTestAccess bypass
    // However, without TestAccess here, we can just use the Execute path by making a fake module buffer

    // Set up a fake memory mapping
    context.IsMemoryCacheValid = true;
    context.CachedMemoryRegions.clear();

    MEMORY_BASIC_INFORMATION mbi = {};
    mbi.BaseAddress = (PVOID)data;
    mbi.RegionSize = size;
    mbi.State = MEM_COMMIT;
    mbi.Protect = PAGE_EXECUTE_READWRITE;
    mbi.Type = MEM_PRIVATE;

    context.CachedMemoryRegions.push_back(mbi);

    // Set an extremely high budget so it doesn't time out
    CheatConfigManager::GetInstance().UpdateHeavyScanBudgetMs(10000);

    MemorySecuritySensor sensor;
    // Execute will scan the fake region because it's marked as RX/RWX
    // This tests if the PE parsing in CheckHiddenMemoryRegion handles malformed data without crashing
    sensor.Execute(context);

    return 0;
}

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
int main(int argc, char **argv)
{
    std::cout << "Starting Sensor Fuzz (Smoke Test)..." << std::endl;
    std::vector<uint8_t> dummy_data = {0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00};
    LLVMFuzzerTestOneInput(dummy_data.data(), dummy_data.size());
    std::cout << "Sensor Fuzz stub executed successfully." << std::endl;
    return 0;
}
#endif
