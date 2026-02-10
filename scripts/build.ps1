param(
  [switch]$UseVcpkg = $false,
  [string]$VcpkgRoot = "$PSScriptRoot/../vcpkg",
  [string]$BuildType = "Release",
  [string]$Arch = "x64",
  [string]$Generator = "Visual Studio 17 2022",
  [string]$ProtobufRoot = "",
  [switch]$Help = $false
)

# Show help if requested
if ($Help) {
  Write-Host "AntiCheat Build Script" -ForegroundColor Cyan
  Write-Host "Usage: .\build.ps1 [options]" -ForegroundColor White
  Write-Host ""
  Write-Host "Options:" -ForegroundColor Yellow
  Write-Host "  -UseVcpkg          Use vcpkg for dependency management (recommended)"
  Write-Host "  -VcpkgRoot <path>  Path to vcpkg installation (default: ../vcpkg)"
  Write-Host "  -BuildType <type>  Build configuration: Debug, Release (default: Release)"
  Write-Host "  -Arch <arch>       Target architecture: x86, x64 (default: x64)"
  Write-Host "  -Generator <gen>   CMake generator (default: Visual Studio 17 2022)"
  Write-Host "  -ProtobufRoot <path> Path to protobuf installation (optional, CMake will auto-detect if not specified)"
  Write-Host "  -Help              Show this help message"
  Write-Host ""
  Write-Host "Examples:" -ForegroundColor Yellow
  Write-Host "  .\build.ps1 -UseVcpkg                    # Build with vcpkg (recommended)"
  Write-Host "  .\build.ps1 -BuildType Debug -UseVcpkg   # Debug build with vcpkg"
  Write-Host "  .\build.ps1 -Arch x86 -UseVcpkg          # x86 build with vcpkg"
  Write-Host "  .\build.ps1 -Arch x86                    # Win32 build (x86)"
  Write-Host "  .\build.ps1 -Arch x64                    # Win64 build (x64, default)"
  Write-Host "  .\build.ps1 -ProtobufRoot C:\path\to\protobuf  # Use custom protobuf path"
  exit 0
}

$ErrorActionPreference = "Stop"

# Print build configuration
Write-Host "=== AntiCheat Build Configuration ===" -ForegroundColor Cyan
Write-Host "Build Type: $BuildType" -ForegroundColor White
Write-Host "Architecture: $Arch" -ForegroundColor White
Write-Host "Generator: $Generator" -ForegroundColor White
Write-Host "Use vcpkg: $UseVcpkg" -ForegroundColor White
if ($ProtobufRoot) {
  Write-Host "Protobuf Root: $ProtobufRoot" -ForegroundColor White
}
else {
  Write-Host "Protobuf Root: Auto-detect" -ForegroundColor White
}
Write-Host ""

# Resolve paths
$RepoRoot = Resolve-Path "$PSScriptRoot/.."
$BuildDir = Join-Path $RepoRoot "build-$Arch"

Write-Host "Repository Root: $RepoRoot" -ForegroundColor Gray
Write-Host "Build Directory: $BuildDir" -ForegroundColor Gray
Write-Host ""

# Create build directory
Write-Host "Creating build directory..." -ForegroundColor Yellow
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

$cmakeArgs = @("-S", $RepoRoot, "-B", $BuildDir, "-G", $Generator, "-A", $Arch)

# 对于x86架构，使用Win32平台名称来避免Visual Studio 2022的配置问题
if ($Arch -eq "x86") {
  # 将x86替换为Win32，这是Visual Studio 2022的正确平台名称
  $cmakeArgs = $cmakeArgs | ForEach-Object { if ($_ -eq "x86") { "Win32" } else { $_ } }
}

if ($UseVcpkg) {
  Write-Host "=== Setting up vcpkg ===" -ForegroundColor Cyan

  if (!(Test-Path $VcpkgRoot)) {
    Write-Host "Cloning vcpkg from GitHub..." -ForegroundColor Yellow
    git clone https://github.com/microsoft/vcpkg $VcpkgRoot
  }
  else {
    Write-Host "vcpkg directory already exists: $VcpkgRoot" -ForegroundColor Green
  }

  Push-Location $VcpkgRoot
  try {
    if (!(Test-Path "$VcpkgRoot/vcpkg.exe")) {
      Write-Host "Bootstrapping vcpkg..." -ForegroundColor Yellow
      .\bootstrap-vcpkg.bat
    }

    if (Test-Path (Join-Path $RepoRoot "vcpkg.json")) {
      Write-Host "Found vcpkg.json manifest, skipping manual package installation." -ForegroundColor Cyan
      Write-Host "CMake will automatically handle dependencies." -ForegroundColor Cyan
    }
    else {
      Write-Host "Installing protobuf for $Arch-windows..." -ForegroundColor Yellow
      .\vcpkg.exe install protobuf:$Arch-windows
    }
  }
  finally {
    Pop-Location
  }

  $toolchain = Join-Path $VcpkgRoot "scripts/buildsystems/vcpkg.cmake"
  $cmakeArgs += @("-DCMAKE_TOOLCHAIN_FILE=$toolchain")
  Write-Host "vcpkg toolchain: $toolchain" -ForegroundColor Green
}
else {
  Write-Host "=== Manual build mode ===" -ForegroundColor Yellow
  Write-Host "Note: Make sure protobuf is installed and accessible" -ForegroundColor Yellow

  # 如果指定了Protobuf路径，则使用它
  if ($ProtobufRoot) {
    if (Test-Path $ProtobufRoot) {
      Write-Host "Using protobuf from: $ProtobufRoot" -ForegroundColor Green
      $cmakeArgs += @("-DProtobuf_ROOT=$ProtobufRoot")
    }
    else {
      Write-Host "Warning: Protobuf path not found: $ProtobufRoot" -ForegroundColor Yellow
      Write-Host "CMake will try to find protobuf automatically" -ForegroundColor Yellow
    }
  }
  else {
    Write-Host "CMake will auto-detect protobuf installation" -ForegroundColor Green
  }
}

Write-Host ""

# Configure CMake
Write-Host "=== Configuring CMake ===" -ForegroundColor Cyan
Write-Host "CMake arguments: $($cmakeArgs -join ' ')" -ForegroundColor Gray
cmake @cmakeArgs

if ($LASTEXITCODE -ne 0) {
  Write-Error "CMake configuration failed!"
  exit 1
}

Write-Host "CMake configuration completed successfully!" -ForegroundColor Green
Write-Host ""

# Build
Write-Host "=== Building AntiCheat ===" -ForegroundColor Cyan
$startTime = Get-Date

cmake --build $BuildDir --config $BuildType --parallel

if ($LASTEXITCODE -ne 0) {
  Write-Error "Build failed!"
  exit 1
}

$buildTime = (Get-Date) - $startTime
Write-Host ""
Write-Host "=== Build Completed Successfully! ===" -ForegroundColor Green
Write-Host "Build Directory: $BuildDir" -ForegroundColor White
Write-Host "Configuration: $BuildType" -ForegroundColor White
Write-Host "Architecture: $Arch" -ForegroundColor White
Write-Host "Build Time: $($buildTime.TotalSeconds.ToString('F2')) seconds" -ForegroundColor White
Write-Host ""

# List build artifacts
Write-Host "=== Build Artifacts ===" -ForegroundColor Cyan
$artifacts = Get-ChildItem -Path $BuildDir -Recurse -Include "*.exe", "*.dll", "*.lib" -ErrorAction SilentlyContinue
if ($artifacts.Count -gt 0) {
  foreach ($artifact in $artifacts) {
    $size = [Math]::Round($artifact.Length / 1KB, 2)
    Write-Host "  $($artifact.Name): $size KB" -ForegroundColor White
  }
}
else {
  Write-Host "  No executable artifacts found" -ForegroundColor Yellow
}
