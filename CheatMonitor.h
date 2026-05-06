#pragma once

#include <cstdint>
#include <string>

#include <mutex>

#include "anti_cheat.pb.h"
#include <memory>

class CheatMonitor final
{
   public:
    static CheatMonitor &GetInstance();

    bool Initialize();
    void OnPlayerLogin(uint32_t user_id, const std::string &user_name);
    void OnPlayerLogout();
    void Shutdown();
    bool IsCallerLegitimate();       // 供游戏逻辑调用的返回地址校验接口
    void SetGameWindow(void *hwnd);  // 允许游戏引擎设置主窗口句柄
    void OnServerConfigUpdated();    // 由ConfigManager在收到服务器配置后调用
    void SubmitTargetedSensorRequest(const std::string &request_id, const std::string &sensor_name);
    void SubmitTargetedSensorRequest(const anti_cheat::TargetedSensorCommand &command);

    // 新增：手动触发快照上报（用于测试）
    void UploadSnapshot();

    struct Pimpl;

   private:
    CheatMonitor();
    ~CheatMonitor();
    CheatMonitor(const CheatMonitor &) = delete;
    CheatMonitor &operator=(const CheatMonitor &) = delete;

    std::unique_ptr<Pimpl> m_pimpl;
};

#define sCheatMonitor CheatMonitor::GetInstance()
