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
    // Trigger baseline establishment
    // Note: InitializeProcessBaseline triggered in MonitorLoop or via Login
    CheatMonitor::GetInstance().OnPlayerLogin(1, "TestUser");

    // Give some time for async tasks to complete (tests might need a more direct trigger)
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
}

TEST_F(CheatMonitorBaselineManagerTest, TestModuleSignatureVerification) {
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    ASSERT_NE(hKernel32, nullptr);

    // 这里需要访问 Engine 内部，由于 Pimpl 隐藏，
    // 通常需要通过 CheatMonitor 的测试友好接口或 Mock 来验证。
    // Demo basic signature logic call
    // CheatMonitor::GetInstance().GetEngine().VerifyModuleSignature(hKernel32);
}
