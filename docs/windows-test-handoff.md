# Windows Test Handoff

This document is the final handoff checklist for running the AntiCheat test suite on Windows.

## 1) Prerequisites

- Windows 10/11 x64.
- Visual Studio 2022 with:
  - MSVC toolchain
  - CMake tools
  - Windows SDK
- PowerShell 7+ (or Windows PowerShell 5.1).
- `vcpkg` available locally.

## 2) Configure and Build (x64)

Run from repo root:

```powershell
cmake -B build -S . `
  -A x64 `
  -DCMAKE_TOOLCHAIN_FILE="C:/path/to/vcpkg/scripts/buildsystems/vcpkg.cmake" `
  -DVCPKG_TARGET_TRIPLET="x64-windows" `
  -DVCPKG_HOST_TRIPLET="x64-windows" `
  -DVCPKG_MANIFEST_FEATURES=tests

cmake --build build --config Debug --parallel 4
```

## 3) Run Unit + Smoke Tests

```powershell
ctest --test-dir build -C Debug --output-on-failure
```

Expected test entries:
- `unit.all`
- `smoke.quick`

## 4) Optional Matrix Validation

Run Release build:

```powershell
cmake --build build --config Release --parallel 4
ctest --test-dir build -C Release --output-on-failure
```

Run x86 build in separate folder:

```powershell
cmake -B build-x86 -S . `
  -A Win32 `
  -DCMAKE_TOOLCHAIN_FILE="C:/path/to/vcpkg/scripts/buildsystems/vcpkg.cmake" `
  -DVCPKG_TARGET_TRIPLET="x86-windows" `
  -DVCPKG_HOST_TRIPLET="x86-windows" `
  -DVCPKG_MANIFEST_FEATURES=tests

cmake --build build-x86 --config Debug --parallel 4
ctest --test-dir build-x86 -C Debug --output-on-failure
```

## 5) What Was Added for Regression Coverage

Core sensor regression tests now include:
- `SensorProcessHandleTest`
- `SensorMemorySecurityTest`
- `SensorVehHookTest`
- `SensorModuleIntegrityTest`
- `SensorAdvancedAntiDebugTest`
- `SensorThreadActivityTest`
- `SensorModuleActivityTest`

Plus foundational tests:
- `SystemUtilsHashTest`
- `UtilsStringTest`
- `CheatConfigManagerTest`
- `HdeDisasmTest`
- `EngineOsGateTest`

## 6) Common Windows-Side Issues

- **Cannot find `gtest`**
  - Ensure `-DVCPKG_MANIFEST_FEATURES=tests` is set during CMake configure.
- **Cannot find protobuf headers**
  - Verify vcpkg toolchain path and triplet match build architecture.
- **Only IDE shows include errors**
  - Re-run CMake configure in the same build profile used by IDE.
  - This repo uses Windows headers heavily; non-Windows indexing errors are expected.

## 7) Fast Sanity Command Set

```powershell
cmake --build build --config Debug --parallel 4
ctest --test-dir build -C Debug --output-on-failure -R unit.all
ctest --test-dir build -C Debug --output-on-failure -R smoke.quick
```
