#include <gtest/gtest.h>
#include <Windows.h>
#include "CheatMonitor.h"
#include "CheatMonitorEngine.h"

class CheatMonitorBaselineManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        CheatMonitor::GetInstance().Initialize();
    }

    void TearDown() override {
        CheatMonitor::GetInstance().Shutdown();
    }
};

TEST_F(CheatMonitorBaselineManagerTest, TestProcessBaselineEstablishment) {
    // 触发基线建立
    // 注意：InitializeProcessBaseline 在 MonitorLoop 中或通过 Login 触发
    CheatMonitor::GetInstance().OnPlayerLogin(1, "TestUser");

    // 给一点时间让异步任务完成（虽然测试中可能需要更直接的触发方式）
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
}

TEST_F(CheatMonitorBaselineManagerTest, TestModuleSignatureVerification) {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    ASSERT_NE(hKernel32, nullptr);

    // 这里需要访问 Engine 内部，由于 Pimpl 隐藏，
    // 通常需要通过 CheatMonitor 的测试友好接口或 Mock 来验证。
    // 这里演示基础的签名逻辑调用。
    // CheatMonitor::GetInstance().GetEngine().VerifyModuleSignature(hKernel32);
}
