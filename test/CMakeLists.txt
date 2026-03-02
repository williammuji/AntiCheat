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
            unit/WMIProcessMonitorMockTest.cpp
            unit/CheatMonitorBaselineManagerTest.cpp
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
            GTest::gtest
            GTest::gmock
        )

        # Added manual main to SystemUtilsHashTest.cpp to ensure registration
        target_compile_definitions(CheatMonitorUnitTests PRIVATE USE_MANUAL_MAIN)

        # ASan DLL will be handled by add_asan_dll_copy function below

        if(BUILD_TESTING)
            add_test(NAME unit.all COMMAND CheatMonitorUnitTests)
            set_tests_properties(unit.all PROPERTIES TIMEOUT 120)
        endif()
    else()
        message(WARNING "GTest not found. Unit tests are skipped. Enable vcpkg feature: tests.")
    endif()
endif()

# Phase A: 增加性能基准测试与并发压测
add_executable(SensorPerformanceTest benchmark/SensorPerformanceTest.cpp)
target_link_libraries(SensorPerformanceTest PRIVATE CheatMonitorLib protobuf::libprotobuf)
target_include_directories(SensorPerformanceTest PRIVATE ${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR} ${Protobuf_INCLUDE_DIRS})

add_executable(ControlApiConcurrencyTest unit/ControlApiConcurrencyTest.cpp)
target_link_libraries(ControlApiConcurrencyTest PRIVATE CheatMonitorLib protobuf::libprotobuf)
target_include_directories(ControlApiConcurrencyTest PRIVATE ${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR} ${Protobuf_INCLUDE_DIRS})

if(BUILD_TESTING)
    add_test(NAME performance.sensors COMMAND SensorPerformanceTest)
    add_test(NAME stress.concurrency.api COMMAND ControlApiConcurrencyTest)
endif()

# Protobuf Fuzz Test
add_executable(AntiCheatProtobufFuzz fuzz/AntiCheatProtobufFuzz.cpp)
target_link_libraries(AntiCheatProtobufFuzz PRIVATE CheatMonitorLib protobuf::libprotobuf)
target_include_directories(AntiCheatProtobufFuzz PRIVATE ${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR} ${Protobuf_INCLUDE_DIRS})

if(BUILD_TESTING)
    add_test(NAME fuzz.protobuf.parsing COMMAND AntiCheatProtobufFuzz)
endif()

# Helper to copy ASan DLL to target output
function(add_asan_dll_copy target_name)
    if(MSVC AND ANTICHEAT_ENABLE_ASAN)
        # Attempt to find ASan DLL dynamically based on compiler path
        get_filename_component(MSVC_BIN_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)

        set(ASAN_DLL_NAME "clang_rt.asan_dynamic-i386.dll")
        if(CMAKE_SIZEOF_VOID_P EQUAL 8)
            set(ASAN_DLL_NAME "clang_rt.asan_dynamic-x86_64.dll")
        endif()

        # Search for the DLL in the compiler's bin directory or its parents/siblings
        # Standard locations include:
        # Hostx64/x86 (for x86 targets on x64 host)
        # Hostx64/x64 (for x64 targets on x64 host)
        find_file(ASAN_DLL_PATH
            NAMES ${ASAN_DLL_NAME}
            PATHS
                "${MSVC_BIN_DIR}"
                "${MSVC_BIN_DIR}/.."
                "${MSVC_BIN_DIR}/../../.."
                "C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/*/bin/Hostx64/x86"
                "C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/*/bin/Hostx64/x64"
                "C:/Program Files/Microsoft Visual Studio/2022/Preview/VC/Tools/MSVC/*/bin/Hostx64/x86"
                "C:/Program Files/Microsoft Visual Studio/2022/Preview/VC/Tools/MSVC/*/bin/Hostx64/x64"
            PATH_SUFFIXES
                ""
                "x86"
                "x64"
                "Hostx64/x86"
                "Hostx64/x64"
                "Hostx86/x86"
                "Hostx86/x64"
            NO_DEFAULT_PATH
        )

        if(ASAN_DLL_PATH)
            message(STATUS "Found ASan DLL for ${target_name}: ${ASAN_DLL_PATH}")
            add_custom_command(TARGET ${target_name} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${ASAN_DLL_PATH}"
                $<TARGET_FILE_DIR:${target_name}>
                COMMENT "Copying ASan runtime DLL (${ASAN_DLL_NAME}) to output directory for ${target_name}"
            )
            # Clear for next target
            unset(ASAN_DLL_PATH CACHE)
        else()
            message(WARNING "ASan DLL ${ASAN_DLL_NAME} not found automatically near ${MSVC_BIN_DIR}. Linking might fail at runtime.")
        endif()
    endif()
endfunction()

add_asan_dll_copy(CheatMonitorTest)
add_asan_dll_copy(CheatMonitorUnitTests)
add_asan_dll_copy(SensorPerformanceTest)
add_asan_dll_copy(ControlApiConcurrencyTest)
add_asan_dll_copy(AntiCheatProtobufFuzz)

# ASan Verification Tool (Standardized)
add_executable(AsanVerification unit/AsanVerification.cpp)
add_asan_dll_copy(AsanVerification)
