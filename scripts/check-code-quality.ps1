# AntiCheat Code Quality Check Script
# 在macOS开发环境中进行静态代码质量检查

param(
    [switch]$Verbose = $false,
    [string]$OutputFile = "code-quality-report.md"
)

$ErrorActionPreference = "Stop"

Write-Host "🔍 AntiCheat Code Quality Check" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

# 检查文件是否存在
$requiredFiles = @(
    "CheatMonitor.cpp",
    "CheatMonitor.h", 
    "CheatConfigManager.cpp",
    "CheatConfigManager.h",
    "anti_cheat.proto",
    "CMakeLists.txt"
)

$missingFiles = @()
foreach ($file in $requiredFiles) {
    if (-not (Test-Path $file)) {
        $missingFiles += $file
    }
}

if ($missingFiles.Count -gt 0) {
    Write-Host "❌ Missing required files:" -ForegroundColor Red
    $missingFiles | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}

Write-Host "✅ All required files present" -ForegroundColor Green

# 代码质量检查
$issues = @()
$warnings = @()

# 1. 检查头文件包含
Write-Host "`n📋 Checking header includes..." -ForegroundColor Yellow
$monitorContent = Get-Content "CheatMonitor.cpp" -Raw

$requiredHeaders = @(
    "anti_cheat.pb.h",
    "CheatMonitor.h",
    "CheatConfigManager.h", 
    "HardwareInfoCollector.h",
    "Logger.h",
    "windows.h",
    "psapi.h",
    "tlhelp32.h"
)

foreach ($header in $requiredHeaders) {
    if ($monitorContent -match [regex]::Escape($header)) {
        Write-Host "  ✅ $header" -ForegroundColor Green
    } else {
        $issues += "Missing header: $header"
        Write-Host "  ❌ $header" -ForegroundColor Red
    }
}

# 2. 检查传感器注册
Write-Host "`n🔧 Checking sensor registration..." -ForegroundColor Yellow
$expectedSensors = @(
    "AdvancedAntiDebugSensor",
    "SystemCodeIntegritySensor", 
    "ProcessAndWindowMonitorSensor",
    "IatHookSensor",
    "ModuleIntegritySensor",
    "ProcessHandleSensor",
    "ThreadAndModuleActivitySensor",
    "MemorySecuritySensor",
    "VehHookSensor"
)

foreach ($sensor in $expectedSensors) {
    if ($monitorContent -match "std::make_unique<Sensors::$sensor>") {
        Write-Host "  ✅ $sensor" -ForegroundColor Green
    } else {
        $issues += "Sensor not registered: $sensor"
        Write-Host "  ❌ $sensor" -ForegroundColor Red
    }
}

# 3. 检查错误处理
Write-Host "`n🛡️ Checking error handling..." -ForegroundColor Yellow
$errorPatterns = @(
    "RecordFailure",
    "GetLastError",
    "__try",
    "__except",
    "try\s*\{",
    "catch\s*\("
)

foreach ($pattern in $errorPatterns) {
    $matches = ([regex]::Matches($monitorContent, $pattern)).Count
    if ($matches -gt 0) {
        Write-Host "  ✅ $pattern : $matches occurrences" -ForegroundColor Green
    } else {
        $warnings += "No $pattern found"
        Write-Host "  ⚠️ $pattern : 0 occurrences" -ForegroundColor Yellow
    }
}

# 4. 检查内存管理
Write-Host "`n💾 Checking memory management..." -ForegroundColor Yellow
$memoryPatterns = @(
    "std::unique_ptr",
    "std::shared_ptr", 
    "std::make_unique",
    "std::make_shared",
    "delete\s*\[",
    "new\s*\["
)

foreach ($pattern in $memoryPatterns) {
    $matches = ([regex]::Matches($monitorContent, $pattern)).Count
    if ($matches -gt 0) {
        Write-Host "  ✅ $pattern : $matches occurrences" -ForegroundColor Green
    } else {
        Write-Host "  ℹ️ $pattern : $matches occurrences" -ForegroundColor Blue
    }
}

# 5. 检查线程安全
Write-Host "`n🔒 Checking thread safety..." -ForegroundColor Yellow
$threadPatterns = @(
    "std::atomic",
    "std::mutex",
    "std::lock_guard",
    "std::unique_lock"
)

foreach ($pattern in $threadPatterns) {
    $matches = ([regex]::Matches($monitorContent, $pattern)).Count
    if ($matches -gt 0) {
        Write-Host "  ✅ $pattern : $matches occurrences" -ForegroundColor Green
    } else {
        Write-Host "  ℹ️ $pattern : $matches occurrences" -ForegroundColor Blue
    }
}

# 6. 检查配置完整性
Write-Host "`n⚙️ Checking configuration..." -ForegroundColor Yellow
$configContent = Get-Content "CheatConfigManager.cpp" -Raw
$protoContent = Get-Content "anti_cheat.proto" -Raw

$configFields = @(
    "base_scan_interval_seconds",
    "heavy_scan_interval_minutes", 
    "max_evidences_per_session",
    "harmful_process_names",
    "harmful_keywords",
    "whitelisted_veh_modules"
)

foreach ($field in $configFields) {
    if ($protoContent -match $field -and $configContent -match $field) {
        Write-Host "  ✅ $field" -ForegroundColor Green
    } else {
        $issues += "Configuration field missing: $field"
        Write-Host "  ❌ $field" -ForegroundColor Red
    }
}

# 7. 检查CMake配置
Write-Host "`n🔨 Checking CMake configuration..." -ForegroundColor Yellow
$cmakeContent = Get-Content "CMakeLists.txt" -Raw

$cmakeRequirements = @(
    "CMAKE_CXX_STANDARD 17",
    "find_package\(Protobuf REQUIRED\)",
    "protobuf_generate_cpp",
    "WINVER=0x0601",
    "_WIN32_WINNT=0x0601"
)

foreach ($req in $cmakeRequirements) {
    if ($cmakeContent -match [regex]::Escape($req)) {
        Write-Host "  ✅ $req" -ForegroundColor Green
    } else {
        $issues += "CMake requirement missing: $req"
        Write-Host "  ❌ $req" -ForegroundColor Red
    }
}

# 生成报告
Write-Host "`n📊 Generating quality report..." -ForegroundColor Cyan

$report = @"
# AntiCheat Code Quality Report

**Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
**Environment:** macOS Development
**Target:** Windows Production

## Summary

- **Total Issues:** $($issues.Count)
- **Total Warnings:** $($warnings.Count)
- **Status:** $(if ($issues.Count -eq 0) { "✅ PASS" } else { "❌ FAIL" })

## Issues Found

"@

if ($issues.Count -gt 0) {
    $report += "`n### Critical Issues`n`n"
    foreach ($issue in $issues) {
        $report += "- ❌ $issue`n"
    }
} else {
    $report += "`n✅ No critical issues found!`n"
}

if ($warnings.Count -gt 0) {
    $report += "`n### Warnings`n`n"
    foreach ($warning in $warnings) {
        $report += "- ⚠️ $warning`n"
    }
}

$report += @"

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
"@

Set-Content -Path $OutputFile -Value $report

# 输出结果
Write-Host "`n📋 Quality Check Results:" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan
Write-Host "Issues: $($issues.Count)" -ForegroundColor $(if ($issues.Count -eq 0) { "Green" } else { "Red" })
Write-Host "Warnings: $($warnings.Count)" -ForegroundColor $(if ($warnings.Count -eq 0) { "Green" } else { "Yellow" })
Write-Host "Report: $OutputFile" -ForegroundColor Blue

if ($issues.Count -gt 0) {
    Write-Host "`n❌ Quality check failed. Please fix issues before committing." -ForegroundColor Red
    exit 1
} else {
    Write-Host "`n✅ Quality check passed! Code is ready for commit." -ForegroundColor Green
    exit 0
}
