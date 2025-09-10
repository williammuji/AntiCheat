#!/bin/bash

# AntiCheat Code Quality Check Script (Bash version for macOS)
# 在macOS开发环境中进行静态代码质量检查

set -e

verbose=false
output_file="code-quality-report.md"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -v|--verbose)
            verbose=true
            shift
            ;;
        -o|--output)
            output_file="$2"
            shift 2
            ;;
        *)
            echo "Unknown option $1"
            exit 1
            ;;
    esac
done

echo "🔍 AntiCheat Code Quality Check"
echo "================================="

# 检查文件是否存在
required_files=(
    "CheatMonitor.cpp"
    "CheatMonitor.h"
    "CheatConfigManager.cpp"
    "CheatConfigManager.h"
    "anti_cheat.proto"
    "CMakeLists.txt"
)

missing_files=()
for file in "${required_files[@]}"; do
    if [ ! -f "$file" ]; then
        missing_files+=("$file")
    fi
done

if [ ${#missing_files[@]} -gt 0 ]; then
    echo "❌ Missing required files:"
    for file in "${missing_files[@]}"; do
        echo "  - $file"
    done
    exit 1
fi

echo "✅ All required files present"

# 代码质量检查
issues=()
warnings=()

# 1. 检查头文件包含
echo ""
echo "📋 Checking header includes..."
if [ -f "CheatMonitor.cpp" ]; then
    # 检查关键头文件
    critical_headers=(
        "CheatMonitor.h"
        "CheatConfigManager.h"
        "HardwareInfoCollector.h"
        "Logger.h"
    )
    
    for header in "${critical_headers[@]}"; do
        if grep -q "$header" CheatMonitor.cpp; then
            echo "  ✅ $header"
        else
            issues+=("Missing header: $header")
            echo "  ❌ $header"
        fi
    done
    
    # 检查Windows特定头文件（在macOS上可能找不到，但代码中应该有引用）
    windows_headers=(
        "windows.h"
        "anti_cheat.pb.h"
    )
    
    for header in "${windows_headers[@]}"; do
        if grep -q "$header" CheatMonitor.cpp; then
            echo "  ✅ $header (referenced in code)"
        else
            warnings+=("Windows header not referenced: $header")
            echo "  ⚠️ $header (not referenced)"
        fi
    done
fi

# 2. 检查传感器注册
echo ""
echo "🔧 Checking sensor registration..."
if [ -f "CheatMonitor.cpp" ]; then
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
    
    for sensor in "${expected_sensors[@]}"; do
        if grep -q "std::make_unique<Sensors::$sensor>" CheatMonitor.cpp; then
            echo "  ✅ $sensor"
        else
            issues+=("Sensor not registered: $sensor")
            echo "  ❌ $sensor"
        fi
    done
fi

# 3. 检查错误处理
echo ""
echo "🛡️ Checking error handling..."
if [ -f "CheatMonitor.cpp" ]; then
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
            echo "  ✅ $pattern : $count occurrences"
        else
            warnings+=("No $pattern found")
            echo "  ⚠️ $pattern : 0 occurrences"
        fi
    done
fi

# 4. 检查内存管理
echo ""
echo "💾 Checking memory management..."
if [ -f "CheatMonitor.cpp" ]; then
    memory_patterns=(
        "std::unique_ptr"
        "std::shared_ptr"
        "std::make_unique"
        "std::make_shared"
        "delete"
        "new"
    )
    
    for pattern in "${memory_patterns[@]}"; do
        count=$(grep -c "$pattern" CheatMonitor.cpp || echo "0")
        if [ "$count" -gt 0 ]; then
            echo "  ✅ $pattern : $count occurrences"
        else
            echo "  ℹ️ $pattern : $count occurrences"
        fi
    done
fi

# 5. 检查线程安全
echo ""
echo "🔒 Checking thread safety..."
if [ -f "CheatMonitor.cpp" ]; then
    thread_patterns=(
        "std::atomic"
        "std::mutex"
        "std::lock_guard"
        "std::unique_lock"
    )
    
    for pattern in "${thread_patterns[@]}"; do
        count=$(grep -c "$pattern" CheatMonitor.cpp || echo "0")
        if [ "$count" -gt 0 ]; then
            echo "  ✅ $pattern : $count occurrences"
        else
            echo "  ℹ️ $pattern : $count occurrences"
        fi
    done
fi

# 6. 检查配置完整性
echo ""
echo "⚙️ Checking configuration..."
if [ -f "CheatConfigManager.cpp" ] && [ -f "anti_cheat.proto" ]; then
    config_fields=(
        "base_scan_interval_seconds"
        "heavy_scan_interval_minutes"
        "max_evidences_per_session"
        "harmful_process_names"
        "harmful_keywords"
        "whitelisted_veh_modules"
    )
    
    for field in "${config_fields[@]}"; do
        if grep -q "$field" anti_cheat.proto && grep -q "$field" CheatConfigManager.cpp; then
            echo "  ✅ $field"
        else
            issues+=("Configuration field missing: $field")
            echo "  ❌ $field"
        fi
    done
fi

# 7. 检查CMake配置
echo ""
echo "🔨 Checking CMake configuration..."
if [ -f "CMakeLists.txt" ]; then
    cmake_requirements=(
        "CMAKE_CXX_STANDARD 17"
        "find_package(Protobuf REQUIRED)"
        "protobuf_generate_cpp"
        "WINVER=0x0601"
        "_WIN32_WINNT=0x0601"
    )
    
    for req in "${cmake_requirements[@]}"; do
        if grep -q "$req" CMakeLists.txt; then
            echo "  ✅ $req"
        else
            issues+=("CMake requirement missing: $req")
            echo "  ❌ $req"
        fi
    done
fi

# 8. 检查代码复杂度
echo ""
echo "📊 Checking code complexity..."
if [ -f "CheatMonitor.cpp" ]; then
    # 检查文件大小
    file_size=$(wc -l < CheatMonitor.cpp)
    echo "  📏 CheatMonitor.cpp: $file_size lines"
    
    if [ "$file_size" -gt 5000 ]; then
        warnings+=("CheatMonitor.cpp is very large ($file_size lines)")
        echo "  ⚠️ File is very large"
    else
        echo "  ✅ File size reasonable"
    fi
    
    # 检查函数复杂度（简单检查）
    function_count=$(grep -c "SensorExecutionResult.*Execute" CheatMonitor.cpp || echo "0")
    echo "  🔧 Sensor Execute functions: $function_count"
    
    # 检查循环复杂度
    loop_count=$(grep -c "for\|while" CheatMonitor.cpp || echo "0")
    echo "  🔄 Loops: $loop_count"
fi

# 9. 检查命名规范
echo ""
echo "📝 Checking naming conventions..."
if [ -f "CheatMonitor.cpp" ]; then
    # 检查类名
    class_count=$(grep -c "class.*Sensor" CheatMonitor.cpp || echo "0")
    echo "  🏷️ Sensor classes: $class_count"
    
    # 检查常量命名
    const_count=$(grep -c "const.*k[A-Z]" CheatMonitor.cpp || echo "0")
    echo "  📌 Constants: $const_count"
    
    # 检查成员变量命名
    member_count=$(grep -c "m_[a-zA-Z]" CheatMonitor.cpp || echo "0")
    echo "  🔧 Member variables: $member_count"
fi

# 生成报告
echo ""
echo "📊 Generating quality report..."

report="# AntiCheat Code Quality Report

**Generated:** $(date '+%Y-%m-%d %H:%M:%S')
**Environment:** macOS Development
**Target:** Windows Production

## Summary

- **Total Issues:** ${#issues[@]}
- **Total Warnings:** ${#warnings[@]}
- **Status:** $(if [ ${#issues[@]} -eq 0 ]; then echo "✅ PASS"; else echo "❌ FAIL"; fi)

## Issues Found

"

if [ ${#issues[@]} -gt 0 ]; then
    report+="
### Critical Issues

"
    for issue in "${issues[@]}"; do
        report+="- ❌ $issue
"
    done
else
    report+="
✅ No critical issues found!
"
fi

if [ ${#warnings[@]} -gt 0 ]; then
    report+="
### Warnings

"
    for warning in "${warnings[@]}"; do
        report+="- ⚠️ $warning
"
    done
fi

report+="

## Recommendations

1. **Before Git Commit:**
   - Fix all critical issues
   - Review warnings
   - Run GitHub Actions CI/CD

2. **For Production:**
   - Ensure all sensors are properly registered
   - Verify error handling coverage
   - Test on Windows environment

3. **CI/CD Integration:**
   - Use GitHub Actions for automated testing
   - Enable branch protection rules
   - Require status checks before merge

---
*Report generated by AntiCheat Code Quality Check*
"

echo "$report" > "$output_file"

# 输出结果
echo ""
echo "📋 Quality Check Results:"
echo "========================"
echo "Issues: ${#issues[@]}"
echo "Warnings: ${#warnings[@]}"
echo "Report: $output_file"

if [ ${#issues[@]} -gt 0 ]; then
    echo ""
    echo "❌ Quality check failed. Please fix issues before committing."
    exit 1
else
    echo ""
    echo "✅ Quality check passed! Code is ready for commit."
    exit 0
fi
