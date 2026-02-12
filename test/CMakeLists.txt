cmake_minimum_required(VERSION 3.15)
project(CheatMonitorTest LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Protobuf REQUIRED)

add_executable(CheatMonitorTest main.cpp)
target_include_directories(CheatMonitorTest PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_BINARY_DIR}
    ${Protobuf_INCLUDE_DIRS}
)
target_link_libraries(CheatMonitorTest PRIVATE
    CheatMonitorLib
    protobuf::libprotobuf
)

if(BUILD_TESTING)
    add_test(NAME smoke.quick COMMAND CheatMonitorTest --quick)
    set_tests_properties(smoke.quick PROPERTIES TIMEOUT 120)
endif()

option(ANTICHEAT_ENABLE_UNIT_TESTS "Build AntiCheat unit tests" ON)
if(ANTICHEAT_ENABLE_UNIT_TESTS)
    find_package(GTest QUIET)
    if(GTest_FOUND)
        add_executable(CheatMonitorUnitTests
            unit/SystemUtilsHashTest.cpp
            unit/UtilsStringTest.cpp
            unit/CheatConfigManagerTest.cpp
            unit/HdeDisasmTest.cpp
            unit/EngineOsGateTest.cpp
            unit/SensorMemorySecurityTest.cpp
            unit/SensorProcessHandleTest.cpp
            unit/SensorVehHookTest.cpp
            unit/SensorAdvancedAntiDebugTest.cpp
            unit/SensorModuleIntegrityTest.cpp
            unit/SensorThreadActivityTest.cpp
            unit/SensorModuleActivityTest.cpp
        )
        target_include_directories(CheatMonitorUnitTests PRIVATE
            ${CMAKE_SOURCE_DIR}
            ${CMAKE_BINARY_DIR}
            ${Protobuf_INCLUDE_DIRS}
        )
        target_link_libraries(CheatMonitorUnitTests PRIVATE
            CheatMonitorLib
            protobuf::libprotobuf
            GTest::gtest_main
        )

        if(BUILD_TESTING)
            add_test(NAME unit.all COMMAND CheatMonitorUnitTests)
            set_tests_properties(unit.all PROPERTIES TIMEOUT 120)
        endif()
    else()
        message(WARNING "GTest not found. Unit tests are skipped. Enable vcpkg feature: tests.")
    endif()
endif()
