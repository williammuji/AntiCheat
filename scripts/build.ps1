param(
  [switch]$UseVcpkg = $false,
  [string]$VcpkgRoot = "$PSScriptRoot/../vcpkg",
  [string]$BuildType = "Release",
  [string]$Arch = "x64",
  [string]$Generator = "Visual Studio 17 2022"
)

$ErrorActionPreference = "Stop"

# Resolve paths
$RepoRoot = Resolve-Path "$PSScriptRoot/.."
$BuildDir = Join-Path $RepoRoot "build-smoke"
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null

$cmakeArgs = @("-S", $RepoRoot, "-B", $BuildDir, "-G", $Generator, "-A", $Arch)

if ($UseVcpkg) {
  if (!(Test-Path $VcpkgRoot)) {
    Write-Host "Cloning vcpkg..." -ForegroundColor Cyan
    git clone https://github.com/microsoft/vcpkg $VcpkgRoot
  }
  Push-Location $VcpkgRoot
  try {
    if (!(Test-Path "$VcpkgRoot/vcpkg.exe")) {
      .\bootstrap-vcpkg.bat
    }
    .\vcpkg.exe install protobuf:$Arch-windows
  } finally {
    Pop-Location
  }
  $toolchain = Join-Path $VcpkgRoot "scripts/buildsystems/vcpkg.cmake"
  $cmakeArgs += @("-DCMAKE_TOOLCHAIN_FILE=$toolchain")
}

# Configure
cmake @cmakeArgs

# Build
cmake --build $BuildDir --config $BuildType --parallel

Write-Host "Smoke build finished: $BuildDir ($BuildType)" -ForegroundColor Green
