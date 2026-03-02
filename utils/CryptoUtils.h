#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include <wincrypt.h>

class CryptoUtils {
public:
    /**
     * @brief 使用 HMAC-SHA256 计算数据的签名 (Windows XP 兼容)
     *
     * @param data 要签名的数据字节流
     * @param key HMAC 密钥
     * @return std::string 十六进制格式的签名字符串，失败则返回空字符串
     */
    static std::string CalculateHMAC_SHA256(const std::vector<uint8_t>& data, const std::string& key);

    /**
     * @brief 生成一个随机的 HMAC 密钥 (用于测试或初始化)
     *
     * @param length 密钥字节长度
     * @return std::string 随机密钥的十六进制字符串
     */
    static std::string GenerateRandomKey(size_t length = 32);

    /**
     * @brief 获取当前系统的高精度毫秒时间戳
     */
    static uint64_t GetCurrentTimestampMs();
};
