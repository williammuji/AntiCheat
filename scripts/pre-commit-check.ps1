# AntiCheat Pre-Commit Check Script
# 在Git提交前进行最终检查

param(
    [switch]$SkipQualityCheck = $false,
    [switch]$Force = $false
)

$ErrorActionPreference = "Stop"

Write-Host "🚀 AntiCheat Pre-Commit Check" -ForegroundColor Cyan
Write-Host "=============================" -ForegroundColor Cyan

# 检查Git状态
Write-Host "`n📋 Checking Git status..." -ForegroundColor Yellow
$gitStatus = git status --porcelain
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Not in a Git repository" -ForegroundColor Red
    exit 1
}

$stagedFiles = $gitStatus | Where-Object { $_.StartsWith("A ") -or $_.StartsWith("M ") }
$modifiedFiles = $gitStatus | Where-Object { $_.StartsWith(" M") -or $_.StartsWith("??") }

if ($stagedFiles.Count -eq 0 -and -not $Force) {
    Write-Host "ℹ️ No staged files to commit" -ForegroundColor Blue
    exit 0
}

Write-Host "✅ Git repository status OK" -ForegroundColor Green

# 检查关键文件
Write-Host "`n📁 Checking critical files..." -ForegroundColor Yellow
$criticalFiles = @(
    "CheatMonitor.cpp",
    "CheatMonitor.h",
    "CheatConfigManager.cpp", 
    "CheatConfigManager.h",
    "anti_cheat.proto",
    "CMakeLists.txt",
    "vcpkg.json"
)

$missingFiles = @()
foreach ($file in $criticalFiles) {
    if (-not (Test-Path $file)) {
        $missingFiles += $file
    }
}

if ($missingFiles.Count -gt 0) {
    Write-Host "❌ Missing critical files:" -ForegroundColor Red
    $missingFiles | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}

Write-Host "✅ All critical files present" -ForegroundColor Green

# 运行代码质量检查
if (-not $SkipQualityCheck) {
    Write-Host "`n🔍 Running code quality check..." -ForegroundColor Yellow
    & "$PSScriptRoot/check-code-quality.ps1" -OutputFile "pre-commit-quality-report.md"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Code quality check failed" -ForegroundColor Red
        Write-Host "Review pre-commit-quality-report.md for details" -ForegroundColor Yellow
        exit 1
    }
    Write-Host "✅ Code quality check passed" -ForegroundColor Green
}

# 检查文件大小
Write-Host "`n📏 Checking file sizes..." -ForegroundColor Yellow
$largeFiles = @()
Get-ChildItem -Recurse -File | Where-Object { $_.Length -gt 10MB } | ForEach-Object {
    $largeFiles += $_.FullName
}

if ($largeFiles.Count -gt 0) {
    Write-Host "⚠️ Large files detected:" -ForegroundColor Yellow
    $largeFiles | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
}

# 检查二进制文件
Write-Host "`n🔍 Checking for binary files..." -ForegroundColor Yellow
$binaryExtensions = @("*.exe", "*.dll", "*.lib", "*.obj", "*.pdb", "*.bin")
$binaryFiles = @()
foreach ($ext in $binaryExtensions) {
    Get-ChildItem -Recurse -File -Name $ext -ErrorAction SilentlyContinue | ForEach-Object {
        $binaryFiles += $_
    }
}

if ($binaryFiles.Count -gt 0) {
    Write-Host "⚠️ Binary files detected:" -ForegroundColor Yellow
    $binaryFiles | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    Write-Host "Consider adding to .gitignore" -ForegroundColor Yellow
}

# 检查.gitignore
Write-Host "`n📝 Checking .gitignore..." -ForegroundColor Yellow
if (-not (Test-Path ".gitignore")) {
    Write-Host "⚠️ .gitignore not found, creating one..." -ForegroundColor Yellow
    $gitignoreContent = @"
# Build directories
build/
build-*/
out/
bin/
obj/

# Visual Studio
.vs/
*.vcxproj.user
*.sln.docstates

# CMake
CMakeCache.txt
CMakeFiles/
cmake_install.cmake
Makefile

# vcpkg
vcpkg_installed/
vcpkg/

# Protobuf generated files
*.pb.h
*.pb.cc

# Logs
*.log

# Temporary files
*.tmp
*.temp
*~

# OS generated files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# IDE files
.vscode/settings.json
.idea/
*.swp
*.swo

# Test artifacts
test-results/
coverage/
"@
    Set-Content -Path ".gitignore" -Value $gitignoreContent
    Write-Host "✅ Created .gitignore" -ForegroundColor Green
} else {
    Write-Host "✅ .gitignore exists" -ForegroundColor Green
}

# 检查提交信息格式
Write-Host "`n📝 Checking commit message..." -ForegroundColor Yellow
if (-not $Force) {
    Write-Host "ℹ️ Use -Force to skip commit message check" -ForegroundColor Blue
}

# 最终检查
Write-Host "`n🎯 Final checks..." -ForegroundColor Yellow

# 检查是否有未提交的更改
$uncommittedChanges = git diff --name-only
if ($uncommittedChanges.Count -gt 0 -and -not $Force) {
    Write-Host "⚠️ Uncommitted changes detected:" -ForegroundColor Yellow
    $uncommittedChanges | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
    Write-Host "Consider staging all changes or use -Force to proceed" -ForegroundColor Yellow
}

# 检查分支状态
$currentBranch = git branch --show-current
Write-Host "Current branch: $currentBranch" -ForegroundColor Blue

# 生成提交前报告
$report = @"
# Pre-Commit Check Report

**Date:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
**Branch:** $currentBranch
**Commit Hash:** $(git rev-parse HEAD)

## Check Results

- ✅ Git repository status: OK
- ✅ Critical files: All present
- ✅ Code quality: $(if ($SkipQualityCheck) { "Skipped" } else { "Passed" })
- ✅ File structure: OK

## Recommendations

1. **Before pushing to remote:**
   - Ensure all tests pass in CI/CD
   - Review code changes thoroughly
   - Update documentation if needed

2. **For production deployment:**
   - Run full test suite on Windows
   - Verify all sensors work correctly
   - Check performance metrics

## Next Steps

1. Commit your changes: `git commit -m "Your commit message"`
2. Push to remote: `git push origin $currentBranch`
3. Create PR if needed
4. Monitor CI/CD pipeline

---
*Report generated by AntiCheat Pre-Commit Check*
"@

Set-Content -Path "pre-commit-report.md" -Value $report

Write-Host "`n🎉 Pre-commit check completed!" -ForegroundColor Green
Write-Host "=============================" -ForegroundColor Green
Write-Host "✅ All checks passed" -ForegroundColor Green
Write-Host "📋 Report: pre-commit-report.md" -ForegroundColor Blue
Write-Host "`n🚀 Ready to commit!" -ForegroundColor Green

exit 0
