[中文](#-cheatmonitor-游戏客户端反作弊) | [English](#cheatmonitor-a-game-client-anti-cheat)

---

# CheatMonitor: 游戏客户端反作弊

`CheatMonitor` 是一个为大型多人在线角色扮演游戏（MMORPG）设计的、运行在用户模式下的反作弊系统。其核心目标是在对游戏性能影响最小的前提下，全面、精准地检测各类作弊行为，并为服务器提供数据情报。

本项目的第一阶段主要侧重于**数据收集与摸底**。

## 核心设计理念

*   **高性能与低侵入**: 所有检测传感器都经过精心设计，以确保对游戏帧率的影响降至最低。采用动态休眠机制，在保证扫描频率的同时，智能调节系统资源占用。
*   **模块化与可扩展**: 系统采用模块化的传感器设计，便于未来新增或更新检测功能，而无需重构核心代码。
*   **主动防御**: 除了被动检测，系统还包含主动防御机制（如返回地址校验），旨在从根本上增加外挂的制作难度。
*   **数据驱动**: 强大的硬件指纹收集能力和精准的证据上报机制，为服务器端的行为分析和封禁决策提供数据支持。

## 功能特性 (Features)

`CheatMonitor` 已经实现了一个功能全面、多层次的防御体系。

### 主动防御与进程加固 (Proactive Defense & Hardening)

-   **返回地址校验 (`IsCallerLegitimate`)**: 游戏核心功能（如技能释放、移动等）可以调用此接口，校验调用者是否来自合法的游戏模块，有效阻止来自注入DLL和Shellcode的非法调用。
-   **非法调用来源节流**: 对同一非法来源（特定DLL或Shellcode内存区域）的调用，采用5分钟冷却策略上报，在保证数据有效性的同时，避免“告警风暴”。
-   **进程线程加固**:
    -   **对调试器隐藏**: 在Release模式下，通过 `NtSetInformationThread` 隐藏所有游戏线程，极大地增加了调试器附加和分析的难度。
    -   **进程缓解策略**: 阻止游戏客户端创建任何子进程，关闭常见的攻击路径。

### 运行时内存与模块分析 (Runtime Analysis)

-   **内存扫描**:
    -   检测不属于任何模块的私有可执行内存（`MEM_PRIVATE`），这是Shellcode注入的典型特征。
    -   检测已加载模块中被非法赋予写权限的代码节（`PAGE_EXECUTE_READWRITE`），这是内存Patch的强烈信号。
-   **模块完整性校验**:
    -   通过比对内存镜像与磁盘文件，校验核心系统模块（`ntdll.dll`, `kernel32.dll`）和游戏自身模块的 `.text` 代码节是否被篡改。
-   **Hook检测**:
    -   **Inline Hook**: 检测关键API函数头部的 `JMP` / `PUSH-RET` 等指令。
    -   **IAT Hook**: 遍历导入地址表，检测函数指针是否被修改。
-   **运行时活动监控**:
    -   检测新创建的未知线程。
    -   检测新加载的模块，并自动对其进行**数字签名验证**，有效识别未签名的恶意DLL。

### 环境与系统完整性检测 (Environment & Integrity)

-   **反调试**:
    -   包含多种经典反调试技术，如 `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, PEB标志位检查, `CloseHandle`无效句柄异常，以及硬件断点寄存器（DRx）检查。
    -   可在用户模式下检测**内核调试器**的存在（通过 `NtQuerySystemInformation` 和 `_KUSER_SHARED_DATA`）。
-   **反虚拟机**: 通过CPUID、注册表痕迹和虚拟网卡MAC地址前缀，检测游戏是否在VMware, VirtualBox, Hyper-V等虚拟机中运行。
-   **系统状态检查**:
    -   检测Windows是否开启了**测试签名模式 (Test Signing Mode)**，这是内核级外挂运行的温床。
-   **进程与句柄扫描**:
    -   检测系统中的已知作弊/逆向工具进程（如Cheat Engine, x64dbg, IDA）。
    -   检测并上报持有本游戏进程高权限句柄的可疑进程。
-   **父进程验证**: 校验游戏是否由合法的父进程（如官方启动器、IDE）启动，防止傀儡进程攻击。

### 行为启发式分析 (Behavioral Heuristics)

-   **输入自动化检测**: 通过低级鼠标钩子 (`WH_MOUSE_LL`) 采集数据，分析鼠标点击间隔的规律性（标准差）和移动轨迹的平滑度（共线性），以检测宏和机器人脚本。

### 数据收集与上报 (Data & Reporting)

-   **硬件指纹收集**: 在玩家首次登录时，收集磁盘序列号、MAC地址、计算机名、操作系统版本、CPU架构和核心数等信息，为机器封禁提供依据。
-   **高效的证据上报**:
    -   所有上报证据在会话内进行去重，减少数据冗余。
    -   通过Protobuf进行数据序列化，高效且跨平台。
    -   采用定时（5分钟）上报策略，平衡了实时性与网络开销。

## 未来计划 (Planned Features)

-   **内核级驱动 (Kernel-Mode Driver)**: 开发配套的内核驱动，以实现更底层的防护，如进程保护、线程创建过滤、回调函数监控等，对抗内核级作弊。
-   **网络流量分析 (Network Traffic Analysis)**: 监控游戏数据包，检测异常的发包频率或被篡改的协议内容。
-   **代码虚拟化与混淆 (Code Obfuscation/Virtualization)**: 对反作弊模块自身进行加固，防止被逆向分析和破解。
-   **文件系统扫描 (File System Scanning)**: 在启动时扫描游戏目录和常见作弊软件路径，发现已知的作弊工具文件。

## 编译 (Compile)

本项目使用CMake进行构建，可以在Windows环境下通过Visual Studio轻松编译。

### 1. 依赖环境

*   **CMake** (版本 3.15 或更高)
*   **Visual Studio** (2019 或更高版本，需安装 "使用C++的桌面开发" 工作负载)
*   **Protobuf** (v3.x):
    1.  从 Protobuf GitHub Releases 下载 `protoc-*-win64.zip`。
    2.  解压后，将 `bin` 目录的路径添加到系统的 `PATH` 环境变量中。

### 2. 编译步骤

```sh
# 1. 创建一个独立的构建目录，以保持源码目录整洁
mkdir build
cd build

# 2. 运行CMake生成Visual Studio项目文件
#    (如果使用VS 2019，请将 "Visual Studio 17 2022" 改为 "Visual Studio 16 2019")
cmake .. -G "Visual Studio 17 2022"

# 3. 使用CMake直接编译，或用Visual Studio打开生成的 .sln 文件进行编译
cmake --build . --config Release
```

编译成功后，静态库 `CheatMonitorLib.lib` 将会生成在 `build/Release` 目录下。

## 授权协议 (License)

本项目采用 MIT License。

---

# CheatMonitor: A Game Client Anti-Cheat

`CheatMonitor` is a user-mode anti-cheat system designed for Massively Multiplayer Online Role-Playing Games (MMORPGs). Its core objective is to comprehensively and accurately detect various forms of cheating while minimizing impact on game performance, providing valuable intelligence to the server.

The initial phase of this project focuses on **data collection and intelligence gathering**.

## Core Design Philosophy

*   **High Performance & Low Intrusion**: All detection sensors are meticulously designed to ensure minimal impact on game frame rates. A dynamic sleep mechanism is employed to intelligently manage system resource usage while guaranteeing a consistent scan frequency.
*   **Modular & Extensible**: The system uses a modular sensor design, making it easy to add or update detection capabilities in the future without refactoring the core code.
*   **Proactive Defense**: Beyond passive detection, the system includes proactive defense mechanisms (such as return address validation) aimed at fundamentally increasing the difficulty for cheat developers.
*   **Data-Driven**: Robust hardware fingerprinting capabilities and a precise evidence reporting mechanism provide the data support needed for server-side behavioral analysis and banning decisions.

## Features

`CheatMonitor` has implemented a comprehensive, multi-layered defense system.

### Proactive Defense & Hardening

-   **Return Address Validation (`IsCallerLegitimate`)**: Core game functions (e.g., skill casting, movement) can call this interface to verify that the caller originates from a legitimate game module, effectively blocking illegal calls from injected DLLs and shellcode.
-   **Illegal Call Source Throttling**: Reports for calls from the same illegal source (a specific DLL or shellcode memory region) are throttled with a 5-minute cooldown to prevent "alert storms" while ensuring data validity.
-   **Process & Thread Hardening**:
    -   **Hide from Debugger**: In Release mode, all game threads are hidden via `NtSetInformationThread`, significantly increasing the difficulty of attaching and analyzing with a debugger.
    -   **Process Mitigation Policies**: Prevents the game client from creating any child processes, closing off a common attack vector.

### Runtime Analysis

-   **Memory Scanning**:
    -   Detects private, executable memory (`MEM_PRIVATE`) that does not belong to any module, a classic sign of shellcode injection.
    -   Detects code sections in loaded modules that have been illicitly granted write permissions (`PAGE_EXECUTE_READWRITE`), a strong indicator of memory patching.
-   **Module Integrity Checks**:
    -   Verifies the integrity of core system modules (`ntdll.dll`, `kernel32.dll`) and the game's own modules by comparing the in-memory image against the on-disk file.
-   **Hook Detection**:
    -   **Inline Hooks**: Detects `JMP` / `PUSH-RET` instructions at the start of critical API functions.
    -   **IAT Hooks**: Traverses the Import Address Table to detect modified function pointers.
-   **Runtime Activity Monitoring**:
    -   Detects newly created, unknown threads.
    -   Detects newly loaded modules and automatically performs **digital signature verification** on them, effectively identifying unsigned malicious DLLs.

### Environment & Integrity

-   **Anti-Debugging**:
    -   Includes a battery of classic anti-debugging techniques, such as `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, PEB flag checks, the `CloseHandle` invalid handle trick, and hardware breakpoint register (DRx) checks.
    -   Can detect the presence of a **kernel debugger** from user-mode (via `NtQuerySystemInformation` and `_KUSER_SHARED_DATA`).
-   **Anti-Virtual Machine**: Detects if the game is running in a VM (like VMware, VirtualBox, Hyper-V) through CPUID, registry artifacts, and virtual network adapter MAC address prefixes.
-   **System State Checks**:
    -   Detects if Windows is in **Test Signing Mode**, a common prerequisite for kernel-level cheats.
-   **Process & Handle Scanning**:
    -   Detects known cheating/reversing tools (e.g., Cheat Engine, x64dbg, IDA).
    -   Detects and reports suspicious processes holding high-privilege handles to our game process.
-   **Parent Process Validation**: Verifies that the game was launched by a legitimate parent process (e.g., the official launcher, an IDE) to prevent puppet process attacks.

### Behavioral Heuristics

-   **Input Automation Detection**: Collects data via a low-level mouse hook (`WH_MOUSE_LL`) to analyze the regularity of click intervals (standard deviation) and the smoothness of movement paths (collinearity) to detect macros and bots.

### Data Collection & Reporting

-   **Hardware Fingerprint Collection**: On the player's first login, it collects disk serial number, MAC addresses, computer name, OS version, CPU architecture, and core count to support machine-based bans.
-   **Efficient Evidence Reporting**:
    -   All reported evidence is de-duplicated within a session to reduce data redundancy.
    -   Uses Protobuf for efficient, cross-platform data serialization.
    -   Employs a timed (5-minute) reporting strategy to balance real-time awareness with network overhead.

## Planned Features

-   **Kernel-Mode Driver**: Develop a companion kernel driver for lower-level protection, such as process protection, thread creation filtering, and callback monitoring to counter kernel-level cheats.
-   **Network Traffic Analysis**: Monitor game packets to detect abnormal sending frequencies or tampered protocol content.
-   **Code Obfuscation/Virtualization**: Harden the anti-cheat module itself to prevent reverse engineering and tampering.
-   **File System Scanning**: Scan the game directory and common cheat software paths at startup to find known cheat tool files.

## Compile

This project uses CMake and can be easily compiled with Visual Studio on a Windows environment.

### 1. Prerequisites

*   **CMake** (version 3.15 or higher)
*   **Visual Studio** (2019 or newer, with the "Desktop development with C++" workload installed)
*   **Protobuf** (v3.x):
    1.  Download `protoc-*-win64.zip` from the Protobuf GitHub Releases.
    2.  Unzip the file and add the path to its `bin` directory to your system's `PATH` environment variable.

### 2. Compilation Steps

```sh
# 1. Create a separate build directory to keep the source tree clean
mkdir build
cd build

# 2. Run CMake to generate the Visual Studio project files
#    (Change "Visual Studio 17 2022" to "Visual Studio 16 2019" if you are using VS 2019)
cmake .. -G "Visual Studio 17 2022"

# 3. Build directly with CMake, or open the generated .sln file in Visual Studio
cmake --build . --config Release
```

Upon successful compilation, the static library `CheatMonitorLib.lib` will be located in the `build/Release` directory.

## How to Use

1.  Link `CheatMonitorLib.lib` into your main game project.
2.  Initialize `CheatMonitor` when the game starts:
    ```cpp
    #include "CheatMonitor.h"
    
    void GameInitialize() {
        sCheatMonitor.Initialize();
    }
    ```
3.  Notify `CheatMonitor` to begin a session after a player successfully logs in:
    ```cpp
    void OnPlayerLoginSuccess(uint32_t player_id, const std::string& player_name) {
        sCheatMonitor.OnPlayerLogin(player_id, player_name, "1.0.0");
    }
    ```
4.  Call `IsCallerLegitimate()` at the entry point of critical game functions for proactive defense:
    ```cpp
    bool CPlayer::UseSkill(int skillId) {
        if (!sCheatMonitor.IsCallerLegitimate()) {
            return false; // Block the illegal call
        }
        // ... Normal skill logic ...
        return true;
    }
    ```
5.  Safely shut down `CheatMonitor` before the game exits:
    ```cpp
    void GameShutdown() {
        sCheatMonitor.Shutdown();
    }
    ```

## License

This project is licensed under the MIT License.