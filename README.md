# AntiCheat System

Anti-cheat system for MMORPG games with multi-layered detection and sensor-based architecture.

## Sensors

| Weight | Execution Time | Sensors | Purpose |
|--------|----------------|---------|---------|
| **LIGHT** | 0-10ms | AdvancedAntiDebugSensor, SystemCodeIntegritySensor, IatHookSensor, VehHookSensor | Quick system integrity checks and API hook detection |
| **HEAVY** | 100-1000ms | ThreadActivitySensor, ModuleActivitySensor, MemorySecuritySensor, DriverIntegritySensor, InlineHookSensor, ProcessHollowingSensor | Deep system analysis with time-budgeted scanning |
| **CRITICAL** | 1000-10000ms | ProcessHandleSensor, ModuleIntegritySensor, ProcessAndWindowMonitorSensor | Intensive segmented scanning with cursor-based approach |


### AdvancedAntiDebugSensor
- **PEB Debug Flags**: Detects debugger presence via Process Environment Block
- **Debug Registers**: Monitors hardware debug registers (DR0-DR7)
- **Kernel Debugger**: Detects kernel-level debugging tools
- **Remote Debugging**: Identifies remote debugging connections

### SystemCodeIntegritySensor
- **System File Integrity**: Verifies critical system files haven't been modified
- **Driver Signing**: Checks for unsigned or malicious drivers
- **System Call Hooks**: Detects kernel-level API hooking
- **Boot Configuration**: Validates secure boot and system configuration

### IatHookSensor
- **Import Address Table Analysis**: Scans for API function redirections
- **DLL Injection Detection**: Identifies malicious DLL loading
- **API Hooking**: Detects function interception techniques
- **Module Tampering**: Verifies legitimate module loading

### VehHookSensor
- **Vector Exception Handling**: Monitors exception handling mechanisms
- **Exception Filtering**: Detects exception-based hooking techniques
- **Debug Exception Handling**: Monitors debug-related exceptions
- **Advanced Hooking**: Identifies sophisticated hooking methods

### ThreadActivitySensor
- **Thread Start Address Validation**: Reports threads whose start address resides outside legitimate modules
- **Hidden Thread Detection**: Identifies threads hidden from standard enumeration
- **Thread Injection**: Detects threads created by remote processes

### ModuleActivitySensor
- **New Module Verification**: Verifies signatures of newly observed modules and records results
- **Module Hiding Detection**: Detects modules unlinked from PEB
- **Manual Mapping**: Identifies manually mapped modules

### MemorySecuritySensor
- **Private Exec (Non-Module)**: Flags non-module exec regions with configurable size bounds
- **Hidden Exec Heuristic**: Lightweight MZ/access probe for PE-like regions
- **Page Permission Analysis**: Monitors suspicious memory protection changes

### DriverIntegritySensor
- **Driver Enumeration**: Lists loaded kernel drivers
- **Signature Verification**: Verifies digital signatures of drivers
- **Hidden Driver Detection**: Identifies drivers hidden from system lists

### InlineHookSensor
- **Function Prologue Analysis**: Checks for JMP/CALL instructions at function starts
- **Code Patching Detection**: Identifies modifications to executable code
- **Hotpatch Detection**: Detects hotpatching techniques

### ProcessHollowingSensor
- **PE Header comparison**: Compares memory PE header with disk file
- **Entry Point Hijacking**: Detects modified entry points
- **Image Base Mismatch**: Identifies relocated executable images

### ProcessHandleSensor
- **Handle Enumeration**: Scans process handles for suspicious access
- **Handle Duplication**: Detects handle duplication techniques
- **Cross-Process Access**: Monitors inter-process communication
- **Privilege Escalation**: Identifies privilege escalation attempts

### ModuleIntegritySensor
- **Code-Section Baseline**: Computes and compares baseline hash of executable code sections to detect tampering
- **Self/Third-Party Tampering**: Reports integrity violations for both anti-cheat and other loaded modules

### ProcessAndWindowMonitorSensor
- **Process Enumeration**: Monitors running processes for suspicious activity
- **Window Title Analysis**: Scans for cheat-related window titles
- **Process Tree Analysis**: Tracks parent-child process relationships
- **Suspicious Launch Detection**: Identifies cheat tool startup patterns

## Build

### Prerequisites
- **Visual Studio 2022**
- **CMake 3.15 or later**
- **Git** (for vcpkg)
- **PowerShell 5.1+**

### Quick Start (Recommended)
```powershell
# Standard x64 Release Build
.\scripts\build.ps1 -UseVcpkg

# x86 Debug Build with Tests and ASan (Recommended for Dev)
.\scripts\build.ps1 -BuildType Debug -Arch x86 -UseVcpkg -BuildTests -EnableAsan
```

### Manual Build
```powershell
# Configure for x86 Debug with ASan
cmake -S . -B build-x86 -A Win32 -DANTICHEAT_ENABLE_ASAN=ON -DBUILD_TESTING=ON

# Build
cmake --build build-x86 --config Debug
```

## Testing & Benchmarking

### 1. Unit Tests
```powershell
.\build-x86\test\Debug\CheatMonitorUnitTests.exe
```

### 2. Fuzz Testing
```powershell
.\build-x86\test\Debug\AntiCheatProtobufFuzz.exe
```

### 3. Performance Benchmark
```powershell
.\build-x86\test\Debug\SensorPerformanceTest.exe
```

### GitHub CI
- **Smoke Test**: Basic build and header integrity check.
- **Enhanced Smoke Test**: Multi-platform build, sensor registration check, and full test suite execution.

## Example

```cpp
#include "CheatMonitor.h"

// Initialize
sCheatMonitor.Initialize();

// Player login
sCheatMonitor.OnPlayerLogin(userId, userName);

// Player logout
sCheatMonitor.OnPlayerLogout();

// Shutdown
sCheatMonitor.Shutdown();
```
