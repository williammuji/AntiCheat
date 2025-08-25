#include "Logger.h"
#include <iostream>
#include <cstdarg>
#include <cstdio>
#include <ctime>
#include <mutex>

namespace AntiCheatLogger
{

// 线程安全的日志输出
static std::mutex g_logMutex;

// 临时实现：输出到标准输出，后续可替换为正式日志库
static const char* GetLevelString(LogLevel level)
{
    switch (level)
    {
        case LogLevel::DEBUG:
            return "DEBUG";
        case LogLevel::INFO:
            return "INFO";
        case LogLevel::WARNING:
            return "WARNING";
        case LogLevel::ERROR:
            return "ERROR";
        case LogLevel::CRITICAL:
            return "CRITICAL";
        default:
            return "UNKNOWN";
    }
}

static const char* GetCategoryString(LogCategory category)
{
    switch (category)
    {
        case LogCategory::GENERAL:
            return "GENERAL";
        case LogCategory::SENSOR:
            return "SENSOR";
        case LogCategory::PERFORMANCE:
            return "PERFORMANCE";
        case LogCategory::SECURITY:
            return "SECURITY";
        case LogCategory::SYSTEM:
            return "SYSTEM";
        default:
            return "UNKNOWN";
    }
}

static std::string GetTimestamp()
{
    auto now = std::time(nullptr);
    auto localTime = *std::localtime(&now);
    char buffer[64];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &localTime);
    return std::string(buffer);
}

void Log(LogLevel level, LogCategory category, const std::string& message)
{
    std::lock_guard<std::mutex> lock(g_logMutex);

    // 临时实现：格式化输出到标准输出
    // 格式：[时间戳] [级别] [类别] 消息
    std::cout << "[" << GetTimestamp() << "] "
              << "[" << GetLevelString(level) << "] "
              << "[" << GetCategoryString(category) << "] " << message << std::endl;

    // TODO: 后续替换为正式日志库接口
    // 例如：spdlog::get("anticheat")->log(spdlog::level::info, message);
}

void Log(LogLevel level, LogCategory category, const char* format, ...)
{
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    Log(level, category, std::string(buffer));
}

void LogPerformance(const std::string& operation, double durationMs)
{
    std::ostringstream oss;
    oss << "Performance: " << operation << " took " << durationMs << "ms";
    Log(LogLevel::INFO, LogCategory::PERFORMANCE, oss.str());
}

void LogSensorExecution(const std::string& sensorName, double durationMs, bool timeout)
{
    std::ostringstream oss;
    oss << "Sensor: " << sensorName << " took " << durationMs << "ms";
    if (timeout)
    {
        oss << " (TIMEOUT)";
    }
    Log(timeout ? LogLevel::WARNING : LogLevel::DEBUG, LogCategory::SENSOR, oss.str());
}

void LogSecurityEvent(const std::string& eventType, const std::string& details)
{
    std::ostringstream oss;
    oss << "Security Event: " << eventType << " - " << details;
    Log(LogLevel::WARNING, LogCategory::SECURITY, oss.str());
}

void LogSystemInfo(const std::string& osVersion, const std::string& architecture)
{
    std::ostringstream oss;
    oss << "System Info: OS=" << osVersion << ", Arch=" << architecture;
    Log(LogLevel::INFO, LogCategory::SYSTEM, oss.str());
}

}  // namespace AntiCheatLogger
