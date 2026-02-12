#include <gtest/gtest.h>

#include "utils/Utils.h"

TEST(UtilsStringTest, Utf8WideRoundTrip)
{
    const std::string utf8 = "AntiCheat-中文";
    const std::wstring wide = Utils::StringToWide(utf8);
    ASSERT_FALSE(wide.empty());
    EXPECT_EQ(Utils::WideToString(wide), utf8);
}

TEST(UtilsStringTest, GetFileNameHandlesWindowsAndUnixSeparators)
{
    EXPECT_EQ(Utils::GetFileName(L"C:\\Games\\AntiCheat\\client.dll"), L"client.dll");
    EXPECT_EQ(Utils::GetFileName(L"/tmp/anti_cheat.log"), L"anti_cheat.log");
    EXPECT_EQ(Utils::GetFileName(L"plain_name.exe"), L"plain_name.exe");
}
