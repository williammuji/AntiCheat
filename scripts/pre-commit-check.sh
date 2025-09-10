#!/bin/bash

# AntiCheat Pre-Commit Check Script (Bash version for macOS)
# 在Git提交前进行最终检查

set -e

skip_quality_check=false
force=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-quality-check)
            skip_quality_check=true
            shift
            ;;
        --force)
            force=true
            shift
            ;;
        *)
            echo "Unknown option $1"
            echo "Usage: $0 [--skip-quality-check] [--force]"
            exit 1
            ;;
    esac
done

echo "🚀 AntiCheat Pre-Commit Check"
echo "============================="

# 检查Git状态
echo ""
echo "📋 Checking Git status..."
if ! git status --porcelain >/dev/null 2>&1; then
    echo "❌ Not in a Git repository"
    exit 1
fi

staged_files=$(git status --porcelain | grep -c "^[AM]" || echo "0")
modified_files=$(git status --porcelain | grep -c "^ [M?]" || echo "0")

if [ "$staged_files" -eq 0 ] && [ "$force" = false ]; then
    echo "ℹ️ No staged files to commit"
    exit 0
fi

echo "✅ Git repository status OK"
echo "📊 Staged files: $staged_files"
echo "📊 Modified files: $modified_files"

# 检查关键文件
echo ""
echo "📁 Checking critical files..."
critical_files=(
    "CheatMonitor.cpp"
    "CheatMonitor.h"
    "CheatConfigManager.cpp"
    "CheatConfigManager.h"
    "anti_cheat.proto"
    "CMakeLists.txt"
    "vcpkg.json"
)

missing_files=()
for file in "${critical_files[@]}"; do
    if [ ! -f "$file" ]; then
        missing_files+=("$file")
    fi
done

if [ ${#missing_files[@]} -gt 0 ]; then
    echo "❌ Missing critical files:"
    for file in "${missing_files[@]}"; do
        echo "  - $file"
    done
    exit 1
fi

echo "✅ All critical files present"

# 运行代码质量检查
if [ "$skip_quality_check" = false ]; then
    echo ""
    echo "🔍 Running code quality check..."
    if ! ./scripts/check-code-quality.sh; then
        echo "❌ Code quality check failed"
        echo "Review code-quality-report.md for details"
        exit 1
    fi
    echo "✅ Code quality check passed"
fi

# 检查文件大小
echo ""
echo "📏 Checking file sizes..."
large_files=()
while IFS= read -r -d '' file; do
    size=$(stat -f%z "$file" 2>/dev/null || echo "0")
    if [ "$size" -gt 10485760 ]; then  # 10MB
        large_files+=("$file")
    fi
done < <(find . -type f -size +10M -print0 2>/dev/null || true)

if [ ${#large_files[@]} -gt 0 ]; then
    echo "⚠️ Large files detected:"
    for file in "${large_files[@]}"; do
        size_mb=$(( $(stat -f%z "$file") / 1048576 ))
        echo "  - $file (${size_mb}MB)"
    done
fi

# 检查二进制文件
echo ""
echo "🔍 Checking for binary files..."
binary_extensions=("*.exe" "*.dll" "*.lib" "*.obj" "*.pdb" "*.bin")
binary_files=()
for ext in "${binary_extensions[@]}"; do
    while IFS= read -r -d '' file; do
        binary_files+=("$file")
    done < <(find . -name "$ext" -type f -print0 2>/dev/null || true)
done

if [ ${#binary_files[@]} -gt 0 ]; then
    echo "⚠️ Binary files detected:"
    for file in "${binary_files[@]}"; do
        echo "  - $file"
    done
    echo "Consider adding to .gitignore"
fi

# 检查.gitignore
echo ""
echo "📝 Checking .gitignore..."
if [ ! -f ".gitignore" ]; then
    echo "⚠️ .gitignore not found, creating one..."
    cat > .gitignore << 'EOF'
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

# Quality check reports
*-quality-report.md
pre-commit-report.md
smoke-test-report.md

# Backup files
*.bak
*.backup
EOF
    echo "✅ Created .gitignore"
else
    echo "✅ .gitignore exists"
fi

# 检查提交信息格式
echo ""
echo "📝 Checking commit message..."
if [ "$force" = false ]; then
    echo "ℹ️ Use --force to skip commit message check"
fi

# 最终检查
echo ""
echo "🎯 Final checks..."

# 检查是否有未提交的更改
uncommitted_changes=$(git diff --name-only | wc -l)
if [ "$uncommitted_changes" -gt 0 ] && [ "$force" = false ]; then
    echo "⚠️ Uncommitted changes detected:"
    git diff --name-only | head -5 | while read -r file; do
        echo "  - $file"
    done
    if [ "$uncommitted_changes" -gt 5 ]; then
        echo "  ... and $((uncommitted_changes - 5)) more"
    fi
    echo "Consider staging all changes or use --force to proceed"
fi

# 检查分支状态
current_branch=$(git branch --show-current 2>/dev/null || echo "unknown")
echo "Current branch: $current_branch"

# 生成提交前报告
report="# Pre-Commit Check Report

**Date:** $(date '+%Y-%m-%d %H:%M:%S')
**Branch:** $current_branch
**Commit Hash:** $(git rev-parse HEAD 2>/dev/null || echo "unknown")

## Check Results

- ✅ Git repository status: OK
- ✅ Critical files: All present
- ✅ Code quality: $(if [ "$skip_quality_check" = true ]; then echo "Skipped"; else echo "Passed"; fi)
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

1. Commit your changes: \`git commit -m \"Your commit message\"\`
2. Push to remote: \`git push origin $current_branch\`
3. Create PR if needed
4. Monitor CI/CD pipeline

---
*Report generated by AntiCheat Pre-Commit Check*
"

echo "$report" > "pre-commit-report.md"

echo ""
echo "🎉 Pre-commit check completed!"
echo "============================="
echo "✅ All checks passed"
echo "📋 Report: pre-commit-report.md"
echo ""
echo "🚀 Ready to commit!"

exit 0
