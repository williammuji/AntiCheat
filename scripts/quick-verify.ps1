# AntiCheat Quick Verification Script
# 快速验证代码是否准备好提交

param(
    [switch]$Verbose = $false
)

$ErrorActionPreference = "Stop"

Write-Host "⚡ AntiCheat Quick Verification" -ForegroundColor Cyan
Write-Host "===============================" -ForegroundColor Cyan

$startTime = Get-Date
$issues = @()
$warnings = @()

# 1. 检查文件完整性
Write-Host "`n📁 Checking file integrity..." -ForegroundColor Yellow
$requiredFiles = @(
    "CheatMonitor.cpp",
    "CheatMonitor.h",
    "CheatConfigManager.cpp",
    "CheatConfigManager.h", 
    "anti_cheat.proto",
    "CMakeLists.txt",
    "vcpkg.json"
)

foreach ($file in $requiredFiles) {
    if (Test-Path $file) {
        Write-Host "  ✅ $file" -ForegroundColor Green
    } else {
        $issues += "Missing file: $file"
        Write-Host "  ❌ $file" -ForegroundColor Red
    }
}

# 2. 检查代码语法（基本检查）
Write-Host "`n🔍 Checking code syntax..." -ForegroundColor Yellow
$monitorContent = Get-Content "CheatMonitor.cpp" -Raw -ErrorAction SilentlyContinue

if ($monitorContent) {
    # 检查基本语法问题
    $syntaxChecks = @{
        "Missing semicolons" = "class\s+\w+\s*\{[^}]*[^;]\s*\}"
        "Unclosed brackets" = "\{[^}]*$"
        "Unclosed parentheses" = "\([^)]*$"
        "Unclosed strings" = '"[^"]*$'
    }
    
    foreach ($check in $syntaxChecks.GetEnumerator()) {
        if ($monitorContent -match $check.Value) {
            $warnings += $check.Key
            Write-Host "  ⚠️ $($check.Key)" -ForegroundColor Yellow
        } else {
            Write-Host "  ✅ $($check.Key)" -ForegroundColor Green
        }
    }
} else {
    $issues += "Cannot read CheatMonitor.cpp"
    Write-Host "  ❌ Cannot read CheatMonitor.cpp" -ForegroundColor Red
}

# 3. 检查传感器注册
Write-Host "`n🔧 Checking sensor registration..." -ForegroundColor Yellow
if ($monitorContent) {
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
    
    $registeredSensors = 0
    foreach ($sensor in $expectedSensors) {
        if ($monitorContent -match "std::make_unique<Sensors::$sensor>") {
            $registeredSensors++
            Write-Host "  ✅ $sensor" -ForegroundColor Green
        } else {
            $issues += "Sensor not registered: $sensor"
            Write-Host "  ❌ $sensor" -ForegroundColor Red
        }
    }
    
    Write-Host "  📊 Registered sensors: $registeredSensors/$($expectedSensors.Count)" -ForegroundColor Blue
}

# 4. 检查错误处理
Write-Host "`n🛡️ Checking error handling..." -ForegroundColor Yellow
if ($monitorContent) {
    $errorHandling = @{
        "RecordFailure calls" = "RecordFailure"
        "GetLastError calls" = "GetLastError"
        "SEH blocks" = "__try"
        "C++ exceptions" = "try\s*\{"
    }
    
    foreach ($check in $errorHandling.GetEnumerator()) {
        $matches = ([regex]::Matches($monitorContent, $check.Value)).Count
        if ($matches -gt 0) {
            Write-Host "  ✅ $($check.Key): $matches" -ForegroundColor Green
        } else {
            $warnings += "No $($check.Key) found"
            Write-Host "  ⚠️ $($check.Key): 0" -ForegroundColor Yellow
        }
    }
}

# 5. 检查配置完整性
Write-Host "`n⚙️ Checking configuration..." -ForegroundColor Yellow
$configContent = Get-Content "CheatConfigManager.cpp" -Raw -ErrorAction SilentlyContinue
$protoContent = Get-Content "anti_cheat.proto" -Raw -ErrorAction SilentlyContinue

if ($configContent -and $protoContent) {
    $configFields = @(
        "base_scan_interval_seconds",
        "heavy_scan_interval_minutes",
        "max_evidences_per_session",
        "harmful_process_names",
        "harmful_keywords"
    )
    
    $configOk = 0
    foreach ($field in $configFields) {
        if ($protoContent -match $field -and $configContent -match $field) {
            $configOk++
            Write-Host "  ✅ $field" -ForegroundColor Green
        } else {
            $issues += "Configuration field missing: $field"
            Write-Host "  ❌ $field" -ForegroundColor Red
        }
    }
    
    Write-Host "  📊 Configuration fields: $configOk/$($configFields.Count)" -ForegroundColor Blue
} else {
    $issues += "Cannot read configuration files"
    Write-Host "  ❌ Cannot read configuration files" -ForegroundColor Red
}

# 6. 检查CMake配置
Write-Host "`n🔨 Checking CMake configuration..." -ForegroundColor Yellow
$cmakeContent = Get-Content "CMakeLists.txt" -Raw -ErrorAction SilentlyContinue

if ($cmakeContent) {
    $cmakeChecks = @{
        "C++17 standard" = "CMAKE_CXX_STANDARD 17"
        "Protobuf dependency" = "find_package\(Protobuf REQUIRED\)"
        "Windows version" = "WINVER=0x0601"
        "Library linking" = "target_link_libraries"
    }
    
    foreach ($check in $cmakeChecks.GetEnumerator()) {
        if ($cmakeContent -match [regex]::Escape($check.Value)) {
            Write-Host "  ✅ $($check.Key)" -ForegroundColor Green
        } else {
            $issues += "CMake issue: $($check.Key)"
            Write-Host "  ❌ $($check.Key)" -ForegroundColor Red
        }
    }
} else {
    $issues += "Cannot read CMakeLists.txt"
    Write-Host "  ❌ Cannot read CMakeLists.txt" -ForegroundColor Red
}

# 7. 检查Git状态
Write-Host "`n📋 Checking Git status..." -ForegroundColor Yellow
$gitStatus = git status --porcelain 2>$null
if ($LASTEXITCODE -eq 0) {
    $stagedFiles = ($gitStatus | Where-Object { $_.StartsWith("A ") -or $_.StartsWith("M ") }).Count
    $modifiedFiles = ($gitStatus | Where-Object { $_.StartsWith(" M") -or $_.StartsWith("??") }).Count
    
    Write-Host "  📊 Staged files: $stagedFiles" -ForegroundColor Blue
    Write-Host "  📊 Modified files: $modifiedFiles" -ForegroundColor Blue
    
    if ($stagedFiles -gt 0) {
        Write-Host "  ✅ Files ready for commit" -ForegroundColor Green
    } else {
        $warnings += "No files staged for commit"
        Write-Host "  ⚠️ No files staged for commit" -ForegroundColor Yellow
    }
} else {
    $warnings += "Not in a Git repository"
    Write-Host "  ⚠️ Not in a Git repository" -ForegroundColor Yellow
}

# 生成结果
$endTime = Get-Date
$duration = ($endTime - $startTime).TotalSeconds

Write-Host "`n📊 Verification Results:" -ForegroundColor Cyan
Write-Host "========================" -ForegroundColor Cyan
Write-Host "Duration: $([Math]::Round($duration, 2)) seconds" -ForegroundColor Blue
Write-Host "Issues: $($issues.Count)" -ForegroundColor $(if ($issues.Count -eq 0) { "Green" } else { "Red" })
Write-Host "Warnings: $($warnings.Count)" -ForegroundColor $(if ($warnings.Count -eq 0) { "Green" } else { "Yellow" })

if ($issues.Count -gt 0) {
    Write-Host "`n❌ Critical Issues:" -ForegroundColor Red
    $issues | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
}

if ($warnings.Count -gt 0) {
    Write-Host "`n⚠️ Warnings:" -ForegroundColor Yellow
    $warnings | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
}

# 最终状态
if ($issues.Count -eq 0) {
    Write-Host "`n🎉 Quick verification passed!" -ForegroundColor Green
    Write-Host "✅ Code is ready for commit and CI/CD" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n❌ Quick verification failed!" -ForegroundColor Red
    Write-Host "Please fix critical issues before committing" -ForegroundColor Red
    exit 1
}
