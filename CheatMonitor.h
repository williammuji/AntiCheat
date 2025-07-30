#pragma once

#include <string>
#include <cstdint>

#include <mutex>

#include "anti_cheat.pb.h"

class CheatMonitor final {
public:
    static CheatMonitor& GetInstance();

    bool Initialize();
    void OnPlayerLogin(uint32_t user_id, const std::string& user_name);
    void OnPlayerLogout();
    void Shutdown();
    bool IsCallerLegitimate(); // [新增] 供游戏逻辑调用的返回地址校验接口

private:
    CheatMonitor();
    ~CheatMonitor();
    CheatMonitor(const CheatMonitor&) = delete;
    CheatMonitor& operator=(const CheatMonitor&) = delete;

    std::mutex m_initMutex; // 用于保护 Initialize 和 Shutdown 的互斥锁

    struct Pimpl;
    Pimpl* m_pimpl;
};

#define sCheatMonitor CheatMonitor::GetInstance()
