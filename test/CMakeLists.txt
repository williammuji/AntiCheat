# 设置CMake的最低要求版本并定义项目名称
cmake_minimum_required(VERSION 3.15)
project(CheatMonitorTest LANGUAGES CXX)

# 设置项目使用的C++标准为C++14
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 查找本项目必需的Protobuf包
find_package(Protobuf REQUIRED)

# 添加可执行文件目标
add_executable(CheatMonitorTest main.cpp)

# 指定查找头文件的目录
target_include_directories(CheatMonitorTest PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${Protobuf_INCLUDE_DIRS}
)

# 将测试程序链接到我们之前创建的静态库 CheatMonitorLib
target_link_libraries(CheatMonitorTest PRIVATE
    CheatMonitorLib
    protobuf::libprotobuf
)
