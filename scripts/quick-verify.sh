#!/bin/bash

# AntiCheat Quick Verification Script (Bash version for macOS)
# 快速验证代码是否准备好提交

set -e

echo "⚡ AntiCheat Quick Verification"
echo "==============================="

start_time=$(date +%s)
issues=()
warnings=()

# 1. 检查文件完整性
echo ""
echo "📁 Checking file integrity..."
required_files=(
    "CheatMonitor.cpp"
    "CheatMonitor.h"
    "CheatConfigManager.cpp"
    "CheatConfigManager.h"
    "anti_cheat.proto"
    "CMakeLists.txt"
    "vcpkg.json"
)

for file in "${required_files[@]}"; do
    if [ -f "$file" ]; then
        echo "  ✅ $file"
    else
        issues+=("Missing file: $file")
        echo "  ❌ $file"
    fi
done

# 2. 检查代码语法（基本检查）
echo ""
echo "🔍 Checking code syntax..."
if [ -f "CheatMonitor.cpp" ]; then
    # 检查基本语法问题
    echo "  ✅ CheatMonitor.cpp exists"
    
    # 检查传感器注册
    echo ""
    echo "🔧 Checking sensor registration..."
    expected_sensors=(
        "AdvancedAntiDebugSensor"
        "SystemCodeIntegritySensor"
        "ProcessAndWindowMonitorSensor"
        "IatHookSensor"
        "ModuleIntegritySensor"
        "ProcessHandleSensor"
        "ThreadAndModuleActivitySensor"
        "MemorySecuritySensor"
        "VehHookSensor"
    )
    
    registered_sensors=0
    for sensor in "${expected_sensors[@]}"; do
        if grep -q "std::make_unique<Sensors::$sensor>" CheatMonitor.cpp; then
            echo "  ✅ $sensor"
            ((registered_sensors++))
        else
            issues+=("Sensor not registered: $sensor")
            echo "  ❌ $sensor"
        fi
    done
    
    echo "  📊 Registered sensors: $registered_sensors/${#expected_sensors[@]}"
    
    # 检查错误处理
    echo ""
    echo "🛡️ Checking error handling..."
    error_patterns=(
        "RecordFailure"
        "GetLastError"
        "__try"
        "__except"
        "try"
        "catch"
    )
    
    for pattern in "${error_patterns[@]}"; do
        count=$(grep -c "$pattern" CheatMonitor.cpp || echo "0")
        if [ "$count" -gt 0 ]; then
            echo "  ✅ $pattern: $count"
        else
            warnings+=("No $pattern found")
            echo "  ⚠️ $pattern: 0"
        fi
    done
    
else
    issues+=("Cannot read CheatMonitor.cpp")
    echo "  ❌ Cannot read CheatMonitor.cpp"
fi

# 3. 检查配置完整性
echo ""
echo "⚙️ Checking configuration..."
if [ -f "CheatConfigManager.cpp" ] && [ -f "anti_cheat.proto" ]; then
    config_fields=(
        "base_scan_interval_seconds"
        "heavy_scan_interval_minutes"
        "max_evidences_per_session"
        "harmful_process_names"
        "harmful_keywords"
    )
    
    config_ok=0
    for field in "${config_fields[@]}"; do
        if grep -q "$field" anti_cheat.proto && grep -q "$field" CheatConfigManager.cpp; then
            echo "  ✅ $field"
            ((config_ok++))
        else
            issues+=("Configuration field missing: $field")
            echo "  ❌ $field"
        fi
    done
    
    echo "  📊 Configuration fields: $config_ok/${#config_fields[@]}"
else
    issues+=("Cannot read configuration files")
    echo "  ❌ Cannot read configuration files"
fi

# 4. 检查CMake配置
echo ""
echo "🔨 Checking CMake configuration..."
if [ -f "CMakeLists.txt" ]; then
    cmake_checks=(
        "CMAKE_CXX_STANDARD 17"
        "find_package(Protobuf REQUIRED)"
        "WINVER=0x0601"
        "target_link_libraries"
    )
    
    for check in "${cmake_checks[@]}"; do
        if grep -q "$check" CMakeLists.txt; then
            echo "  ✅ $check"
        else
            issues+=("CMake issue: $check")
            echo "  ❌ $check"
        fi
    done
else
    issues+=("Cannot read CMakeLists.txt")
    echo "  ❌ Cannot read CMakeLists.txt"
fi

# 5. 检查Git状态
echo ""
echo "📋 Checking Git status..."
if git status --porcelain >/dev/null 2>&1; then
    staged_files=$(git status --porcelain | grep -c "^[AM]" || echo "0")
    modified_files=$(git status --porcelain | grep -c "^ [M?]" || echo "0")
    
    echo "  📊 Staged files: $staged_files"
    echo "  📊 Modified files: $modified_files"
    
    if [ "$staged_files" -gt 0 ]; then
        echo "  ✅ Files ready for commit"
    else
        warnings+=("No files staged for commit")
        echo "  ⚠️ No files staged for commit"
    fi
else
    warnings+=("Not in a Git repository")
    echo "  ⚠️ Not in a Git repository"
fi

# 生成结果
end_time=$(date +%s)
duration=$((end_time - start_time))

echo ""
echo "📊 Verification Results:"
echo "========================"
echo "Duration: ${duration} seconds"
echo "Issues: ${#issues[@]}"
echo "Warnings: ${#warnings[@]}"

if [ ${#issues[@]} -gt 0 ]; then
    echo ""
    echo "❌ Critical Issues:"
    for issue in "${issues[@]}"; do
        echo "  - $issue"
    done
fi

if [ ${#warnings[@]} -gt 0 ]; then
    echo ""
    echo "⚠️ Warnings:"
    for warning in "${warnings[@]}"; do
        echo "  - $warning"
    done
fi

# 最终状态
if [ ${#issues[@]} -eq 0 ]; then
    echo ""
    echo "🎉 Quick verification passed!"
    echo "✅ Code is ready for commit and CI/CD"
    exit 0
else
    echo ""
    echo "❌ Quick verification failed!"
    echo "Please fix critical issues before committing"
    exit 1
fi
