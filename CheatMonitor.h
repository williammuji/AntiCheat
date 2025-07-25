#pragma once

#include <string>
#include <cstdint>

#include "anti_cheat.pb.h"

class CheatMonitor final {
public:
    static CheatMonitor& GetInstance();

    void Initialize();
    void OnPlayerLogin(uint32_t user_id, const std::string& user_name, const std::string& client_version);
    void OnPlayerLogout();
    void Shutdown();
    bool IsCallerLegitimate(); // [新增] 供游戏逻辑调用的返回地址校验接口

private:
    CheatMonitor();
    ~CheatMonitor();
    CheatMonitor(const CheatMonitor&) = delete;
    CheatMonitor& operator=(const CheatMonitor&) = delete;

    struct Pimpl;
    Pimpl* m_pimpl;
};

#define sCheatMonitor CheatMonitor::GetInstance()
