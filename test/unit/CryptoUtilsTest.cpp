#include <gtest/gtest.h>
#include "utils/CryptoUtils.h"
#include <vector>
#include <string>

TEST(CryptoUtilsTest, HMAC_SHA256_Basic)
{
    std::string key = "secret_key";
    std::string message = "hello world";
    std::vector<uint8_t> data(message.begin(), message.end());

    std::string hmac = CryptoUtils::CalculateHMAC_SHA256(data, key);
    EXPECT_FALSE(hmac.empty());
    EXPECT_EQ(hmac.length(), 64); // 32 bytes hex encoded = 64 chars

    // Verify consistency
    std::string hmac2 = CryptoUtils::CalculateHMAC_SHA256(data, key);
    EXPECT_EQ(hmac, hmac2);

    // Verify different key produces different HMAC
    std::string hmac3 = CryptoUtils::CalculateHMAC_SHA256(data, "other_key");
    EXPECT_NE(hmac, hmac3);
}

TEST(CryptoUtilsTest, HMAC_SHA256_EmptyData)
{
    std::string key = "test_key";
    std::vector<uint8_t> empty_data;
    std::string hmac = CryptoUtils::CalculateHMAC_SHA256(empty_data, key);
    EXPECT_FALSE(hmac.empty());
}

TEST(CryptoUtilsTest, GenerateRandomKey)
{
    std::string key1 = CryptoUtils::GenerateRandomKey(16);
    std::string key2 = CryptoUtils::GenerateRandomKey(16);

    EXPECT_EQ(key1.length(), 32); // 16 bytes hex = 32 chars
    EXPECT_EQ(key2.length(), 32);
    EXPECT_NE(key1, key2);
}

TEST(CryptoUtilsTest, GetCurrentTimestampMs)
{
    uint64_t ts1 = CryptoUtils::GetCurrentTimestampMs();
    EXPECT_GT(ts1, 0ull);
}
