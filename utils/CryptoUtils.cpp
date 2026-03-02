#include "CryptoUtils.h"
#include "Logger.h"
#include "Utils.h"
#include <sstream>
#include <iomanip>

// Windows XP SP3 支持 PROV_RSA_AES 和 CALG_SHA_256
// 但需要确保使用的是 MS_ENH_RSA_AES_PROV
#ifndef MS_ENH_RSA_AES_PROV
#define MS_ENH_RSA_AES_PROV L"Microsoft Enhanced RSA and AES Cryptographic Provider"
#endif

std::string CryptoUtils::CalculateHMAC_SHA256(const std::vector<uint8_t>& data, const std::string& key) {
    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;
    HCRYPTKEY hKey = NULL;
    std::string result = "";

    // 1. 获取加密服务提供者 (CSP)
    if (!CryptAcquireContextW(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        LOG_ERROR_F(AntiCheatLogger::LogCategory::MODULE, "CryptoUtils: CryptAcquireContext 失败 (0x%08X)", GetLastError());
        return "";
    }

    struct RawKeyBlob {
        BLOBHEADER hdr;
        DWORD cbKeySize;
        BYTE rgbKeyData[1]; // 长度可变
    };

    // 2. 导入密钥
    size_t keyLen = key.length();
    size_t blobLen = sizeof(BLOBHEADER) + sizeof(DWORD) + keyLen;
    std::vector<uint8_t> keyBlob(blobLen);
    RawKeyBlob* pBlob = reinterpret_cast<RawKeyBlob*>(keyBlob.data());
    pBlob->hdr.bType = PLAINTEXTKEYBLOB;
    pBlob->hdr.bVersion = CUR_BLOB_VERSION;
    pBlob->hdr.reserved = 0;
    pBlob->hdr.aiKeyAlg = CALG_RC2; // 实测表明导入HMAC密钥时此算法标识符在某些系统下会被忽略，但设为对称算法较稳妥
    pBlob->cbKeySize = (DWORD)keyLen;
    memcpy(pBlob->rgbKeyData, key.c_str(), keyLen);

    if (!CryptImportKey(hProv, keyBlob.data(), (DWORD)blobLen, 0, CRYPT_IPSEC_HMAC_KEY, &hKey)) {
        LOG_ERROR_F(AntiCheatLogger::LogCategory::MODULE, "CryptoUtils: CryptImportKey 失败 (0x%08X)", GetLastError());
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // 3. 创建 HMAC 哈希对象
    if (!CryptCreateHash(hProv, CALG_HMAC, hKey, 0, &hHash)) {
        LOG_ERROR_F(AntiCheatLogger::LogCategory::MODULE, "CryptoUtils: CryptCreateHash 失败 (0x%08X)", GetLastError());
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // 4. 设置 HMAC 信息 (指定使用 SHA-256)
    HMAC_INFO hmacInfo = { 0 };
    hmacInfo.HashAlgid = CALG_SHA_256;
    if (!CryptSetHashParam(hHash, HP_HMAC_INFO, reinterpret_cast<BYTE*>(&hmacInfo), 0)) {
        LOG_ERROR_F(AntiCheatLogger::LogCategory::MODULE, "CryptoUtils: CryptSetHashParam 失败 (0x%08X)", GetLastError());
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // 5. 压入数据
    if (!CryptHashData(hHash, data.data(), (DWORD)data.size(), 0)) {
        LOG_ERROR_F(AntiCheatLogger::LogCategory::MODULE, "CryptoUtils: CryptHashData 失败 (0x%08X)", GetLastError());
        CryptDestroyHash(hHash);
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    // 6. 获取哈希值
    DWORD dwHashLen = 0;
    DWORD dwSize = sizeof(DWORD);
    if (CryptGetHashParam(hHash, HP_HASHSIZE, reinterpret_cast<BYTE*>(&dwHashLen), &dwSize, 0)) {
        std::vector<uint8_t> hashResult(dwHashLen);
        if (CryptGetHashParam(hHash, HP_HASHVAL, hashResult.data(), &dwHashLen, 0)) {
            std::stringstream ss;
            for (auto b : hashResult) {
                ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
            }
            result = ss.str();
        }
    }

    // 7. 清理
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);

    return result;
}

std::string CryptoUtils::GenerateRandomKey(size_t length) {
    HCRYPTPROV hProv = NULL;
    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return "";
    }

    std::vector<uint8_t> keyData(length);
    if (CryptGenRandom(hProv, (DWORD)length, keyData.data())) {
        std::stringstream ss;
        for (auto b : keyData) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        CryptReleaseContext(hProv, 0);
        return ss.str();
    }

    CryptReleaseContext(hProv, 0);
    return "";
}

uint64_t CryptoUtils::GetCurrentTimestampMs() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    // 从 1601-01-01 到 1970-01-01 的 100ns 间隔数
    const uint64_t EPOCH_DIFF = 116444736000000000ULL;
    return (uli.QuadPart - EPOCH_DIFF) / 10000;
}
