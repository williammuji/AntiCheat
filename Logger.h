#pragma once

#include <string>
#include <sstream>

// 反作弊模块日志库接口
// 设计为临时接口，便于后续切换到正式的日志库
namespace AntiCheatLogger
{

// 日志级别
enum class LogLevel
{
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO = 1,
    LOG_LEVEL_WARNING = 2,
    LOG_LEVEL_ERROR = 3,    // 重命名以避免与 Windows.h 中的 ERROR 宏冲突
    LOG_LEVEL_CRITICAL = 4
};

// 日志类别
enum class LogCategory
{
    GENERAL = 0,      // 通用日志
    SENSOR = 1,       // 传感器相关
    PERFORMANCE = 2,  // 性能相关
    SECURITY = 3,     // 安全相关
    SYSTEM = 4        // 系统相关
};

// 主要日志接口
void Log(LogLevel level, LogCategory category, const std::string& message);
void Log(LogLevel level, LogCategory category, const char* format, ...);

// 便捷的宏定义
#define LOG_DEBUG(category, msg) AntiCheatLogger::Log(AntiCheatLogger::LogLevel::LOG_LEVEL_DEBUG, category, msg)
#define LOG_INFO(category, msg) AntiCheatLogger::Log(AntiCheatLogger::LogLevel::LOG_LEVEL_INFO, category, msg)
#define LOG_WARNING(category, msg) AntiCheatLogger::Log(AntiCheatLogger::LogLevel::LOG_LEVEL_WARNING, category, msg)
#define LOG_ERROR(category, msg) AntiCheatLogger::Log(AntiCheatLogger::LogLevel::LOG_LEVEL_ERROR, category, msg)
#define LOG_CRITICAL(category, msg) AntiCheatLogger::Log(AntiCheatLogger::LogLevel::LOG_LEVEL_CRITICAL, category, msg)

// 格式化日志宏
#define LOG_DEBUG_F(category, fmt, ...) \
    AntiCheatLogger::Log(AntiCheatLogger::LogLevel::LOG_LEVEL_DEBUG, category, fmt, __VA_ARGS__)
#define LOG_INFO_F(category, fmt, ...) AntiCheatLogger::Log(AntiCheatLogger::LogLevel::LOG_LEVEL_INFO, category, fmt, __VA_ARGS__)
#define LOG_WARNING_F(category, fmt, ...) \
    AntiCheatLogger::Log(AntiCheatLogger::LogLevel::LOG_LEVEL_WARNING, category, fmt, __VA_ARGS__)
#define LOG_ERROR_F(category, fmt, ...) \
    AntiCheatLogger::Log(AntiCheatLogger::LogLevel::LOG_LEVEL_ERROR, category, fmt, __VA_ARGS__)
#define LOG_CRITICAL_F(category, fmt, ...) \
    AntiCheatLogger::Log(AntiCheatLogger::LogLevel::LOG_LEVEL_CRITICAL, category, fmt, __VA_ARGS__)

// 性能相关的特殊接口
void LogPerformance(const std::string& operation, double durationMs);
void LogSensorExecution(const std::string& sensorName, double durationMs, bool timeout = false);

// 安全事件接口
void LogSecurityEvent(const std::string& eventType, const std::string& details);

// 系统兼容性日志
void LogSystemInfo(const std::string& osVersion, const std::string& architecture);

}  // namespace AntiCheatLogger
