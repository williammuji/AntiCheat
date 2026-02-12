#include <gtest/gtest.h>

#include "CheatMonitorEngine.h"

namespace
{
void UpdateMinOs(anti_cheat::OsVersion minOs)
{
    anti_cheat::ClientConfig cfg;
    cfg.set_min_os_version(minOs);
    std::string payload;
    ASSERT_TRUE(cfg.SerializeToString(&payload));
    CheatConfigManager::GetInstance().UpdateConfigFromServer(payload);
}
} // namespace

TEST(EngineOsGateTest, RejectsVersionBelowConfiguredMinimum)
{
    UpdateMinOs(anti_cheat::OS_WIN10);

    CheatMonitorEngine engine;
    engine.m_windowsVersion = SystemUtils::WindowsVersion::Win_Vista_Win7;
    EXPECT_FALSE(engine.IsCurrentOsSupported());

    engine.m_windowsVersion = SystemUtils::WindowsVersion::Win_10;
    EXPECT_TRUE(engine.IsCurrentOsSupported());
}
