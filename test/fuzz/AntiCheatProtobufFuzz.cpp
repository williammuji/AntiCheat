#include <iostream>
#include <vector>
#include "anti_cheat.pb.h"

// 为了兼容常规测试环境，我们这里实现一个模拟的 FuzzTarget
// 如果是在完整的 LLVM Fuzz 环境下，会使用 LLVMFuzzerTestOneInput
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    // 随机测试 ClientConfig 解析
    {
        anti_cheat::ClientConfig config;
        config.ParseFromArray(data, size);
    }

    // 随机测试 TargetedSensorCommand 解析
    {
        anti_cheat::TargetedSensorCommand cmd;
        cmd.ParseFromArray(data, size);
    }

    // 进一步测试 Report 构造（模拟损坏数据上报）
    {
        anti_cheat::Report report;
        report.ParseFromArray(data, size);
    }

    return 0;
}

// 模拟主函数，用于在非 Fuzzer 环境下作为单元测试运行
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
int main(int argc, char **argv) {
    // 模拟一些损坏数据
    std::vector<uint8_t> bad_data = {0x08, 0x96, 0x01, 0x12, 0x0A, 0xFF};
    LLVMFuzzerTestOneInput(bad_data.data(), bad_data.size());
    std::cout << "Fuzz stub executed successfully." << std::endl;
    return 0;
}
#endif
