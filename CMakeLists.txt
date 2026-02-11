# 设置CMake的最低要求版本并定义项目名称
cmake_minimum_required(VERSION 3.15)
project(CheatMonitor LANGUAGES CXX)

# 设置项目使用的C++标准为C++14
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 查找本项目必需的Protobuf包。
# 这一步会找到Protobuf编译器(protoc)和相关的库文件。
find_package(Protobuf REQUIRED)

# 从 .proto 定义文件自动生成C++的源文件和头文件。
# 生成的文件将被放置在构建目录中。
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS anti_cheat.proto)

# 定义库目标。我们创建一个静态库(STATIC)，这样它可以被轻松地链接到您的主游戏程序中。
add_library(CheatMonitorLib STATIC
    CheatMonitor.h
    CheatMonitor.cpp
    CheatConfigManager.h
    CheatConfigManager.cpp
    HardwareInfoCollector.h
    HardwareInfoCollector.cpp
    WMIProcessMonitor.h
    WMIProcessMonitor.cpp
    ScanContext.cpp
    hde/hde32.h
    hde/hde32.cpp
    utils/SystemUtils.cpp
    utils/Utils.cpp
    sensors/IatHookSensor.cpp
    sensors/VehHookSensor.cpp
    sensors/InlineHookSensor.cpp
    sensors/VTableHookSensor.cpp
    sensors/ProcessHollowingSensor.cpp
    sensors/ProcessAndWindowMonitorSensor.cpp
    sensors/DriverIntegritySensor.cpp
    sensors/ThreadActivitySensor.cpp
    sensors/ModuleActivitySensor.cpp
    sensors/MemorySecuritySensor.cpp
    sensors/AdvancedAntiDebugSensor.cpp
    sensors/SystemCodeIntegritySensor.cpp
    sensors/ModuleIntegritySensor.cpp
    sensors/ProcessHandleSensor.cpp
    ${PROTO_SRCS}
    ${PROTO_HDRS}
)

# 指定编译库所需的包含目录。
# CMAKE_CURRENT_BINARY_DIR 指向的是存放了生成的protobuf头文件的目录。
target_include_directories(CheatMonitorLib PUBLIC
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/utils
    ${CMAKE_CURRENT_SOURCE_DIR}/sensors
    ${Protobuf_INCLUDE_DIRS}
)

# 统一编译宏与最低操作系统目标：仅支持 Windows 7 SP1 及以上
if (MSVC)
    target_compile_options(CheatMonitorLib PRIVATE /utf-8)
endif()

if (WIN32)
    target_compile_definitions(CheatMonitorLib PUBLIC
        WINVER=0x0601
        _WIN32_WINNT=0x0601
        UNICODE
        _UNICODE
        NOMINMAX
        WIN32_LEAN_AND_MEAN
    )
endif()

# 将我们的库链接到Protobuf库。
target_link_libraries(CheatMonitorLib PUBLIC ${Protobuf_LIBRARIES})

# 添加Windows平台特定的库。这取代了在代码中使用 #pragma comment(lib, ...)，
# 使得构建脚本更加清晰和可移植。
if(WIN32)
    # crypt32.lib 用于 CryptProtectData, advapi32.lib 包含旧版 CryptoAPI (用于哈希)
    target_link_libraries(CheatMonitorLib PUBLIC ole32 psapi user32 advapi32 iphlpapi wintrust crypt32 wbemuuid)
endif()

