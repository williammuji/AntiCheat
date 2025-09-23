# AntiCheat System

Anti-cheat system for MMORPG games with multi-layered detection and sensor-based architecture.

## Sensors

| Weight | Execution Time | Sensors | Purpose |
|--------|----------------|---------|---------|
| **LIGHT** | < 1ms | AdvancedAntiDebugSensor, SystemCodeIntegritySensor | Quick system integrity checks |
| **MEDIUM** | 1-10ms | IatHookSensor, ProcessAndWindowMonitorSensor | API hook detection and process monitoring |
| **HEAVY** | 10-100ms | ModuleIntegritySensor, ProcessHandleSensor, ThreadAndModuleActivitySensor, MemorySecuritySensor | Deep system analysis |
| **CRITICAL** | > 100ms | VehHookSensor | Advanced exception handling analysis |


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

### ProcessAndWindowMonitorSensor
- **Process Enumeration**: Monitors running processes for suspicious activity
- **Window Title Analysis**: Scans for cheat-related window titles
- **Process Tree Analysis**: Tracks parent-child process relationships
- **Suspicious Launch Detection**: Identifies cheat tool startup patterns

### ModuleIntegritySensor
- **Code-Section Baseline**: Computes and compares a baseline hash of the first executable code section to detect tampering.
- **Self/Third‑Party Tampering**: Reports integrity violations for both the anti‑cheat itself and other loaded modules.

### ProcessHandleSensor
- **Handle Enumeration**: Scans process handles for suspicious access
- **Handle Duplication**: Detects handle duplication techniques
- **Cross-Process Access**: Monitors inter-process communication
- **Privilege Escalation**: Identifies privilege escalation attempts

### ThreadAndModuleActivitySensor
- **Thread Start Address Validation**: Reports threads whose Win32 start address resides outside any legitimate module (strong indicator of shellcode).
- **New Module Verification**: On newly observed modules, verifies their signatures and records results.
- **Time‑Budgeted Scanning**: Enumerates threads/modules with rotating cursors and budget checks; logs tolerant NTSTATUS cases.

### MemorySecuritySensor
- **Private Exec (Non‑Module)**: Flags non‑module exec regions (configurable size bounds).
- **Hidden Exec Heuristic**: Lightweight MZ/access probe for PE‑like regions.

### VehHookSensor
- **Vector Exception Handling**: Monitors exception handling mechanisms
- **Exception Filtering**: Detects exception-based hooking techniques
- **Debug Exception Handling**: Monitors debug-related exceptions
- **Advanced Hooking**: Identifies sophisticated hooking methods

## Build

### Prerequisites
- **Visual Studio 2017 or later** (with C++ development tools)
- **CMake 3.15 or later**
- **Git** (for vcpkg dependency management)
- **PowerShell 5.1 or later** (for build scripts)
- **Protocol Buffers** (automatically managed by vcpkg)

### Quick Start (Recommended)
```bash
# build with vcpkg (recommended)
.\scripts\build.ps1 -BuildType Release -Arch x64 -UseVcpkg

# build without vcpkg (requires manual protobuf installation)
.\scripts\build.ps1 -BuildType Release -Arch x64 -ProtobufRoot "C:\path\to\protobuf\install"
```

### Manual Build
```bash
mkdir build-x64 && cd build-x64

cmake .. -G "Visual Studio 17 2022" -A x64 -DProtobuf_ROOT="C:\path\to\protobuf\install"

cmake --build . --config Release
```

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
