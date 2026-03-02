#include <iostream>
#include <vector>
#include <string>
#include "anti_cheat.pb.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    // Test ClientConfig parsing
    {
        anti_cheat::ClientConfig config;
        config.ParseFromArray(data, size);
    }

    // Test TargetedSensorCommand parsing
    {
        anti_cheat::TargetedSensorCommand cmd;
        cmd.ParseFromArray(data, size);
    }

    // Test Report construction
    {
        anti_cheat::Report report;
        report.ParseFromArray(data, size);
    }

    return 0;
}

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
int main(int argc, char **argv) {
    std::cout << "Starting AntiCheat Protobuf Fuzz (Silent Mode)..." << std::endl;

    // Simulate corrupted data
    std::vector<uint8_t> bad_data = {0x08, 0x96, 0x01, 0x12, 0x0A, 0xFF, 0xEE, 0xDD};

    LLVMFuzzerTestOneInput(bad_data.data(), bad_data.size());
    std::cout << "Fuzz stub executed successfully without stderr noise." << std::endl;
    return 0;
}
#endif
