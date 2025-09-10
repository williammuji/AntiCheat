# AntiCheat System

Anti-cheat system for MMORPG games with multi-layered detection and sensor-based architecture.

## Architecture

### Core Components
- **CheatMonitor**: Main monitoring engine
- **Sensor System**: Modular detection sensors with weight classification
- **Configuration Manager**: Dynamic configuration management
- **Hardware Fingerprinting**: System identification
- **Telemetry System**: Performance and security metrics

### Sensor Classification

| Weight | Execution Time | Sensors | Purpose |
|--------|----------------|---------|---------|
| **LIGHT** | < 1ms | AdvancedAntiDebugSensor, SystemCodeIntegritySensor | Quick system integrity checks |
| **MEDIUM** | 1-10ms | IatHookSensor, ProcessAndWindowMonitorSensor | API hook detection and process monitoring |
| **HEAVY** | 10-100ms | ModuleIntegritySensor, ProcessHandleSensor, ThreadAndModuleActivitySensor, MemorySecuritySensor | Deep system analysis |
| **CRITICAL** | > 100ms | VehHookSensor | Advanced exception handling analysis |

### Detection Methods
- Import Address Table (IAT) Analysis
- Virtual Exception Handler (VEH) Analysis
- Memory Region Scanning
- Process Handle Analysis
- Thread Activity Monitoring
- Module Integrity Verification
- Hardware Fingerprinting

### Performance Optimization
- Intelligent timeout management
- Caching system for signatures and processes
- Rate limiting for resource-intensive operations
- Weight-based sensor scheduling

## Build Instructions

### Prerequisites
- Visual Studio 2019 or later
- CMake 3.15 or later
- Protocol Buffers

### Build
```bash
# Using PowerShell script
.\scripts\build.ps1 -BuildType Release -Arch x64

# Manual build
mkdir build && cd build
cmake .. -G "Visual Studio 17 2022" -A x64
cmake --build . --config Release
```

## Integration

```cpp
#include "CheatMonitor.h"

// Initialize
sCheatMonitor.Initialize();

// Player login
sCheatMonitor.OnPlayerLogin(userId, userName);

// Check caller legitimacy
if (!sCheatMonitor.IsCallerLegitimate()) {
    // Handle suspicious call
}

// Player logout
sCheatMonitor.OnPlayerLogout();

// Shutdown
sCheatMonitor.Shutdown();
```