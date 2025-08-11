[中文](#-anticheat-游戏客户端反作弊) | [English](#anticheat-a-game-client-anti-cheat)

---

# AntiCheat: 游戏客户端反作弊

`AntiCheat` 是一个为大型多人在线角色扮演游戏（MMORPG）设计的、运行在用户模式下的反作弊系统。

本项目的第一阶段主要侧重于**数据收集与摸底**。

### 1）功能 (Features)

#### 主动防御与进程加固 (Proactive Defense & Hardening)

-   **返回地址校验 (`IsCallerLegitimate`)**: 游戏核心功能（如技能释放、移动等）可以调用此接口，校验调用者是否来自合法的游戏模块，有效阻止来自注入DLL和Shellcode的非法调用。
-   **进程线程加固**:
    -   **对调试器隐藏**: 在Release模式下，通过 `NtSetInformationThread` 隐藏反作弊自身的监控线程，增加调试和逆向分析的难度。
    -   **进程缓解策略**: 阻止游戏客户端创建任何子进程，关闭常见的攻击路径。

#### 运行时内存与模块分析 (Runtime Analysis)

-   **内存扫描**:
    -   检测不属于任何模块的私有可执行内存（`MEM_PRIVATE`），这是Shellcode注入的典型特征。
-   **模块完整性校验**: 在会话开始时为所有已加载模块的 `.text` 代码节建立哈希基线，并在运行时进行比对，以检测内存中的代码篡改。
-   **Hook检测**:
    -   **IAT Hook**: 遍历导入地址表，检测函数指针是否被修改。
    -   **VEH Hook**: 遍历向量化异常处理 (VEH) 链以检测异常处理器挂钩。**该实现通过在启动时扫描PEB来动态定位VEH列表，避免了对Windows内部硬编码偏移量的依赖，以确保与未来Windows版本的向前兼容性和稳定性。**
-   **运行时活动监控**:
    -   检测新创建的未知线程。
    -   检测新加载的模块，并自动对其进行**数字签名验证**，有效识别未签名的恶意DLL。
-   **线程完整性扫描**: 检查线程的起始地址是否位于合法的模块内，以识别由Shellcode创建的线程。
-   **隐藏模块扫描**: 通过遍历进程内存并与PEB模块列表对比，发现被手动映射（Manual Mapping）等技术隐藏的模块。

#### 环境与系统完整性检测 (Environment & Integrity)

-   **反调试**:
    -   包含多种经典反调试技术，如 `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, PEB标志位检查, `CloseHandle`无效句柄异常，以及硬件断点寄存器（DRx）检查。
    -   可在用户模式下检测**内核调试器**的存在（通过 `NtQuerySystemInformation` 和 `_KUSER_SHARED_DATA`）。
-   **反虚拟机**: 通过CPUID、注册表痕迹和虚拟网卡MAC地址前缀，检测游戏是否在VMware, VirtualBox, Hyper-V等虚拟机中运行。
-   **系统状态检查**:
    -   检测Windows是否开启了**测试签名模式 (Test Signing Mode)**，这是内核级外挂运行的温床。
-   **进程与句柄扫描**:
    -   检测系统中的已知作弊/逆向工具进程（如Cheat Engine, x64dbg, IDA）。
    -   检测并上报持有本游戏进程高权限句柄的可疑进程。
-   **可疑行为关联分析**:
    -   **句柄代理攻击**: 关联分析“白名单进程持有本进程句柄”与“高风险作弊行为（如内存修改）”同时发生的事件，以发现通过合法进程进行代理操作的攻击。
    -   **傀儡进程攻击**: 关联分析“游戏由未知父进程启动”与后续发生的“高风险作弊行为”，以识别
-   **父进程验证**: 校验游戏是否由合法的父进程（如官方启动器、IDE）启动，防止傀儡进程攻击。

#### 行为启发式分析 (Behavioral Heuristics)

-   **输入自动化检测**: 通过低级鼠标钩子 (`WH_MOUSE_LL`) 采集数据，分析鼠标点击间隔的规律性（标准差）和移动轨迹的平滑度（共线性），以检测宏和机器人脚本。

#### 数据收集与上报 (Data & Reporting)

-   **硬件指纹收集**: 在玩家首次登录时，收集磁盘序列号、MAC地址、计算机名、操作系统版本、CPU架构和核心数等信息，为机器封禁提供依据。
-   **高效的证据上报**:
    -   所有上报证据在会话内进行去重，减少数据冗余。
    -   通过Protobuf进行数据序列化，高效且跨平台。
    -   采用定时（5分钟）上报策略，平衡了实时性与网络开销。

### 2）未来计划 (Planned Features)

-   **内核级驱动 (Kernel-Mode Driver)**: 开发配套的内核驱动，以实现更底层的防护，如进程保护、线程创建过滤、回调函数监控等，对抗内核级作弊。
-   **网络流量分析 (Network Traffic Analysis)**: 监控游戏数据包，检测异常的发包频率或被篡改的协议内容。
-   **代码虚拟化与混淆 (Code Obfuscation/Virtualization)**: 对反作弊模块自身进行加固，防止被逆向分析和破解。
-   **文件系统扫描 (File System Scanning)**: 在启动时扫描游戏目录和常见作弊软件路径，发现已知的作弊工具文件。

### 3）编译 (Build)

#### 1. 依赖环境

*   **CMake** (版本 3.15 或更高)
*   **Visual Studio** (2019 或更高版本，需安装 "使用C++的桌面开发" 工作负载)
*   **Protobuf** (v3.x):
    1.  从 Protobuf GitHub Releases 下载 `protoc-*-win64.zip`。
    2.  解压后，将 `bin` 目录的路径添加到系统的 `PATH` 环境变量中。

#### 2. 编译步骤

```sh
# 1. 创建一个独立的构建目录，以保持源码目录整洁
mkdir build
cd build

# 2. 运行CMake生成Visual Studio项目文件
#    (如果使用VS 2019，请将 "Visual Studio 17 2022" 改为 "Visual Studio 16 2019")
cmake .. -G "Visual Studio 17 2022" -DProtobuf_ROOT=""

# 3. 使用CMake直接编译，或用Visual Studio打开生成的 .sln 文件进行编译
cmake --build . --config Release
```

### 4）授权协议 (License)

本项目采用 MIT License。

---

# AntiCheat: A Game Client Anti-Cheat

`AntiCheat` is a user-mode anti-cheat system designed for Massively Multiplayer Online Role-Playing Games (MMORPGs). 

The initial phase of this project focuses on **data collection and intelligence gathering**.

### 1) Features

#### Proactive Defense & Hardening

-   **Return Address Validation (`IsCallerLegitimate`)**: Core game functions (e.g., skill casting, movement) can call this interface to verify that the caller originates from a legitimate game module, effectively blocking illegal calls from injected DLLs and shellcode.
-   **Process & Thread Hardening**:
    -   **Hide from Debugger**: In Release mode, the anti-cheat's own monitoring thread is hidden via `NtSetInformationThread`, increasing the difficulty of debugging and reverse engineering.
    -   **Process Mitigation Policies**: Prevents the game client from creating any child processes, closing off a common attack vector.

#### Runtime Analysis

-   **Memory Scanning**:
    -   Detects private, executable memory (`MEM_PRIVATE`) that does not belong to any module, a classic sign of shellcode injection.
-   **Module Integrity Checks**:
    -   Establishes a hash baseline for the `.text` code section of all loaded modules at the start of a session and compares against it at runtime to detect in-memory code tampering.
-   **Hook Detection**:
    -   **IAT Hooks**: Traverses the Import Address Table to detect modified function pointers.
    -   **VEH Hooks**: Traverses the Vectored Exception Handling (VEH) chain to detect exception handler hooks. **The implementation dynamically locates the VEH list by scanning the PEB at startup, avoiding reliance on hardcoded offsets of Windows internals to ensure forward compatibility and stability with future Windows versions.**
-   **Runtime Activity Monitoring**:
    -   Detects newly created, unknown threads.
    -   Detects newly loaded modules and automatically performs **digital signature verification** on them, effectively identifying unsigned malicious DLLs.
-   **Thread Integrity Scanning**: Checks if a thread's start address is within a legitimate module to identify threads created by shellcode.
-   **Hidden Module Scanning**: Discovers modules hidden by techniques like Manual Mapping by traversing process memory and comparing it against the PEB module list.

#### Environment & Integrity

-   **Anti-Debugging**:
    -   Includes a battery of classic anti-debugging techniques, such as `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, PEB flag checks, the `CloseHandle` invalid handle trick, and hardware breakpoint register (DRx) checks.
    -   Can detect the presence of a **kernel debugger** from user-mode (via `NtQuerySystemInformation` and `_KUSER_SHARED_DATA`).
-   **Anti-Virtual Machine**: Detects if the game is running in a VM (like VMware, VirtualBox, Hyper-V) through CPUID, registry artifacts, and virtual network adapter MAC address prefixes.
-   **System State Checks**:
    -   Detects if Windows is in **Test Signing Mode**, a common prerequisite for kernel-level cheats.
-   **Process & Handle Scanning**:
    -   Detects known cheating/reversing tools (e.g., Cheat Engine, x64dbg, IDA).
    -   Detects and reports suspicious processes holding high-privilege handles to our game process.
-   **Suspicious Behavior Correlation Analysis**:
    -   **Handle Proxy Attacks**: Correlates events where a whitelisted process holds a handle to our process with high-risk cheating behaviors (like memory modification) to detect attacks proxied through legitimate processes.
    -   **Puppet Process Attacks**: Correlates the game being launched by an unknown parent process with subsequent high-risk behaviors to identify puppet process attacks.
-   **Parent Process Validation**: Verifies that the game was launched by a legitimate parent process (e.g., the official launcher, an IDE) to prevent puppet process attacks.

#### Behavioral Heuristics

-   **Input Automation Detection**: Collects data via low-level hooks (`WH_MOUSE_LL`, `WH_KEYBOARD_LL`) to analyze mouse click intervals (standard deviation), movement paths (collinearity), and **repetitive key sequences** to detect macros and bots.

#### Data Collection & Reporting

-   **Hardware Fingerprint Collection**: On the player's first login, it collects disk serial number, MAC addresses, computer name, OS version, and **CPU brand string** to support machine-based bans.
-   **Efficient Evidence Reporting**:
    -   All reported evidence is de-duplicated within a session to reduce data redundancy.
    -   Uses Protobuf for efficient, cross-platform data serialization.
    -   Employs a timed (**15-minute**) reporting strategy to balance real-time awareness with network overhead.

### 2) Planned Features

-   **Kernel-Mode Driver**: Develop a companion kernel driver for lower-level protection, such as process protection, thread creation filtering, and callback monitoring to counter kernel-level cheats.
-   **Network Traffic Analysis**: Monitor game packets to detect abnormal sending frequencies or tampered protocol content.
-   **Code Obfuscation/Virtualization**: Harden the anti-cheat module itself to prevent reverse engineering and tampering.
-   **File System Scanning**: Scan the game directory and common cheat software paths at startup to find known cheat tool files.

### 3) Build

#### 1. Prerequisites

*   **CMake** (version 3.15 or higher)
*   **Visual Studio** (2019 or newer, with the "Desktop development with C++" workload installed)
*   **Protobuf** (v3.x):
    1.  Download `protoc-*-win64.zip` from the Protobuf GitHub Releases.
    2.  Unzip the file and add the path to its `bin` directory to your system's `PATH` environment variable.

#### 2. Compilation Steps

```sh
# 1. Create a separate build directory to keep the source tree clean
mkdir build
cd build

# 2. Run CMake to generate the Visual Studio project files
#    (Change "Visual Studio 17 2022" to "Visual Studio 16 2019" if you are using VS 2019)
cmake .. -G "Visual Studio 17 2022" -DProtobuf_ROOT=""

# 3. Build directly with CMake, or open the generated .sln file in Visual Studio
cmake --build . --config Release
```

### 4) License

This project is licensed under the MIT License.