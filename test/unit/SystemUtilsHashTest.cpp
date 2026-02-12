#include <gtest/gtest.h>

#include "utils/SystemUtils.h"

namespace
{
std::vector<uint8_t> Bytes(std::initializer_list<uint8_t> values)
{
    return std::vector<uint8_t>(values);
}
} // namespace

TEST(SystemUtilsHashTest, CalculateFnv1aHashKnownVectors)
{
    const auto emptyHash = SystemUtils::CalculateFnv1aHash(reinterpret_cast<const BYTE *>(""), 0);
    EXPECT_EQ(emptyHash, Bytes({0x25, 0x23, 0x22, 0x84, 0xE4, 0x9C, 0xF2, 0xCB}));

    const char *hello = "hello";
    const auto helloHash = SystemUtils::CalculateFnv1aHash(reinterpret_cast<const BYTE *>(hello), 5);
    EXPECT_EQ(helloHash, Bytes({0x0B, 0xBD, 0xAA, 0x80, 0x46, 0xD8, 0x30, 0xA4}));
}

TEST(SystemUtilsHashTest, CapabilityMatrixCanBeOverriddenForTesting)
{
    SystemUtils::SetWindowsVersionOverrideForTesting(SystemUtils::WindowsVersion::Win_XP);
    EXPECT_TRUE(SystemUtils::HasWindowsVersionOverrideForTesting());
    EXPECT_FALSE(SystemUtils::HasApiCapability(SystemUtils::ApiCapability::ProcessMitigationPolicy));
    EXPECT_FALSE(SystemUtils::HasApiCapability(SystemUtils::ApiCapability::LdrDllNotification));
    EXPECT_EQ(SystemUtils::GetProcessQueryAccessMask(), PROCESS_QUERY_INFORMATION);

    SystemUtils::SetWindowsVersionOverrideForTesting(SystemUtils::WindowsVersion::Win_10);
    EXPECT_TRUE(SystemUtils::HasApiCapability(SystemUtils::ApiCapability::ProcessMitigationPolicy));
    EXPECT_TRUE(SystemUtils::HasApiCapability(SystemUtils::ApiCapability::LdrDllNotification));
    EXPECT_EQ(SystemUtils::GetProcessQueryAccessMask(), PROCESS_QUERY_LIMITED_INFORMATION);

    SystemUtils::ClearWindowsVersionOverrideForTesting();
    EXPECT_FALSE(SystemUtils::HasWindowsVersionOverrideForTesting());
}
