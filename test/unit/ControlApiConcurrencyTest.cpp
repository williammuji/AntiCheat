#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <chrono>
#include "CheatMonitor.h"

void LoginLogoutStressThread(int id, std::atomic<bool>& running) {
    while (running) {
        std::string name = "TestUser_" + std::to_string(id);
        CheatMonitor::GetInstance().OnPlayerLogin(id, name);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        CheatMonitor::GetInstance().OnPlayerLogout();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void ConfigUpdateStressThread(std::atomic<bool>& running) {
    while (running) {
        CheatMonitor::GetInstance().OnServerConfigUpdated();
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

void LegitimateCallerStressThread(std::atomic<bool>& running) {
    while (running) {
        bool res = CheatMonitor::GetInstance().IsCallerLegitimate();
        (void)res;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

int main() {
    std::cout << "=== Anti-Cheat Control API Concurrency Stress Test ===" << std::endl;

    if (!CheatMonitor::GetInstance().Initialize()) {
        std::cerr << "Failed to initialize CheatMonitor" << std::endl;
        return 1;
    }

    std::atomic<bool> running{true};
    std::vector<std::thread> threads;

    // 启动多个登录/退出压力线程
    for (int i = 0; i < 4; ++i) {
        threads.emplace_back(LoginLogoutStressThread, i + 1000, std::ref(running));
    }

    // 启动配置更新压力线程
    threads.emplace_back(ConfigUpdateStressThread, std::ref(running));

    // 启动合法调用校验压力线程
    for (int i = 0; i < 2; ++i) {
        threads.emplace_back(LegitimateCallerStressThread, std::ref(running));
    }

    std::cout << "Stress test running for 30 seconds..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(30));

    std::cout << "Stopping stress test..." << std::endl;
    running = false;
    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    std::cout << "Shutting down CheatMonitor..." << std::endl;
    CheatMonitor::GetInstance().Shutdown();

    std::cout << "=== Stress Test Finished (No Crashes) ===" << std::endl;
    return 0;
}
