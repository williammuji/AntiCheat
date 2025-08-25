# 设置CMake的最低要求版本并定义项目名称
cmake_minimum_required(VERSION 3.16)
project(AntiCheat VERSION 1.0.0 LANGUAGES CXX)

# 设置项目使用的C++标准为C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 查找本项目必需的Protobuf包。
# 这一步会找到Protobuf编译器(protoc)和相关的库文件。
find_package(Protobuf REQUIRED)

# 从 .proto 定义文件自动生成C++的源文件和头文件。
# 生成的文件将被放置在构建目录中。
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS anti_cheat.proto)

# 定义库目标。我们创建一个静态库(STATIC)，这样它可以被轻松地链接到您的主游戏程序中。
add_library(AntiCheat STATIC
    CheatMonitor.h
    CheatMonitor.cpp
    CheatConfigManager.h
    CheatConfigManager.cpp
    HardwareInfoCollector.h
    HardwareInfoCollector.cpp
    Logger.h
    Logger.cpp
    ${PROTO_SRCS}
    ${PROTO_HDRS}
)

# 指定编译库所需的包含目录。
# CMAKE_CURRENT_BINARY_DIR 指向的是存放了生成的protobuf头文件的目录。
target_include_directories(AntiCheat PUBLIC
    ${CMAKE_CURRENT_BINARY_DIR}
    ${Protobuf_INCLUDE_DIRS}
)

# 统一编译宏与最低操作系统目标：仅支持 Windows 7 SP1 及以上
if (WIN32)
    target_compile_definitions(AntiCheat PUBLIC
        WINVER=0x0601
        _WIN32_WINNT=0x0601
        UNICODE
        _UNICODE
        NOMINMAX
        WIN32_LEAN_AND_MEAN
    )
endif()

# 将我们的库链接到Protobuf库。
target_link_libraries(AntiCheat PUBLIC ${Protobuf_LIBRARIES})

# 添加Windows平台特定的库。这取代了在代码中使用 #pragma comment(lib, ...)，
# 使得构建脚本更加清晰和可移植。
if(WIN32)
    # crypt32.lib 用于 CryptProtectData, advapi32.lib 包含旧版 CryptoAPI (用于哈希)
    target_link_libraries(AntiCheat PUBLIC ole32 psapi user32 advapi32 iphlpapi wintrust crypt32)
endif()

