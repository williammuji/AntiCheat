#include <gtest/gtest.h>
#include <algorithm>

#include "CheatConfigManager.h"

TEST(CheatConfigManagerTest, DefaultValuesAreInitialized)
{
    CheatConfigManager &cfg = CheatConfigManager::GetInstance();

    EXPECT_GT(cfg.GetBaseScanInterval(), 0);
    EXPECT_GT(cfg.GetHeavyScanIntervalMinutes(), 0);
    EXPECT_GT(cfg.GetReportUploadIntervalMinutes(), 0);
    EXPECT_GE(cfg.GetMaxEvidencesPerSession(), 1);
}

TEST(CheatConfigManagerTest, UpdateConfigFromServerOverridesFields)
{
    anti_cheat::ClientConfig config;
    config.set_base_scan_interval_seconds(7);
    config.set_heavy_scan_interval_minutes(3);
    config.set_report_upload_interval_minutes(5);
    config.set_min_os_version(anti_cheat::OS_WIN10);
    config.add_harmful_process_names("custom_cheat");
    config.add_harmful_keywords("custom_keyword");

    std::string payload;
    ASSERT_TRUE(config.SerializeToString(&payload));

    CheatConfigManager &cfg = CheatConfigManager::GetInstance();
    cfg.UpdateConfigFromServer(payload);

    EXPECT_EQ(cfg.GetBaseScanInterval(), 7);
    EXPECT_EQ(cfg.GetHeavyScanIntervalMinutes(), 3);
    EXPECT_EQ(cfg.GetReportUploadIntervalMinutes(), 5);
    EXPECT_EQ(cfg.GetMinOsVersion(), anti_cheat::OS_WIN10);

    const auto names = cfg.GetHarmfulProcessNames();
    ASSERT_TRUE(names);
    auto it = std::find(names->begin(), names->end(), L"custom_cheat");
    EXPECT_NE(it, names->end());
}

TEST(CheatConfigManagerTest, RuntimeSafetyBoundsAreClamped)
{
    anti_cheat::ClientConfig config;
    config.set_heartbeat_interval_seconds(99999);
    config.set_scan_watchdog_stall_seconds(0);
    config.set_control_watchdog_stall_seconds(-20);
    config.set_thread_rebuild_limit_count(1000);
    config.set_thread_rebuild_limit_window_seconds(1);

    std::string payload;
    ASSERT_TRUE(config.SerializeToString(&payload));

    CheatConfigManager &cfg = CheatConfigManager::GetInstance();
    cfg.UpdateConfigFromServer(payload);

    EXPECT_EQ(cfg.GetHeartbeatIntervalSeconds(), 120);
    EXPECT_EQ(cfg.GetScanWatchdogStallSeconds(), 3);
    EXPECT_EQ(cfg.GetControlWatchdogStallSeconds(), 3);
    EXPECT_EQ(cfg.GetThreadRebuildLimitCount(), 30);
    EXPECT_EQ(cfg.GetThreadRebuildLimitWindowSeconds(), 5);
}
