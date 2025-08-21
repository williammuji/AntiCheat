[中文](#-anticheat-游戏客户端反作弊) | [English](#anticheat-a-game-client-anti-cheat)

---

# AntiCheat: 游戏客户端反作弊

`AntiCheat` 是一个为大型多人在线角色扮演游戏（MMORPG）设计的、运行在用户模式下的反作弊系统。

本项目经过了多轮重构与强化，实现了基于动态配置的、多传感器协同工作的纵深防御体系。

### 1）功能 (Features)

#### 主动防御与进程加固 (Proactive Defense & Hardening)

-   **返回地址校验 (`IsCallerLegitimate`)**: 为关键的、非高频的游戏逻辑提供调用者校验。例如，在玩家**使用珍稀道具、完成重要任务、进入付费区域**等一次性事件的入口处调用此接口，可有效阻止来自注入DLL和Shellcode的非法调用。**注意：此函数有一定性能开销，严禁在移动、普通攻击等每帧执行或高频触发的逻辑中使用。**
-   **进程线程加固**:
    -   **对调试器隐藏**: 在Release模式下，通过 `NtSetInformationThread` 隐藏反作弊自身的监控线程，增加调试和逆向分析的难度。
    -   **进程缓解策略**: 阻止游戏客户端创建任何子进程，关闭常见的攻击路径。

#### 运行时内存与模块分析 (Runtime Analysis)

-   **内存扫描**:
    -   检测不属于任何模块的私有可执行内存（`MEM_PRIVATE`），这是Shellcode注入的典型特征。
-   **模块完整性校验**: 在进程启动时为所有已加载模块的 `.text` 代码节建立哈希基线，并在运行时进行比对，以检测内存中的代码篡改。
-   **Hook检测**:
    -   **IAT Hook**: 遍历主模块的导入地址表，通过哈希比对检测函数指针是否被修改。
    -   **VEH Hook**: 遍历向量化异常处理 (VEH) 链。**通过对`ntdll.dll`中函数的特征码扫描来动态定位VEH列表地址，以兼容不同Windows版本。**
-   **运行时活动监控**:
    -   检测新创建的未知线程。
    -   检测新加载的模块，并自动对其进行**数字签名验证**，有效识别未签名的恶意DLL。
-   **线程完整性扫描**: 检查线程的起始地址是否位于合法的模块内，以识别由Shellcode创建的线程。
-   **隐藏模块扫描**: 通过`VirtualQuery`遍历进程内存，并对可执行区域调用`GetModuleHandleExW`进行反向查询，寻找那些在PEB链表中被摘除的“隐身”模块。

#### 环境与系统完整性检测 (Environment & Integrity)

-   **反调试**:
    -   包含多种经典反调试技术，如 `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, PEB标志位检查, `CloseHandle`无效句柄异常，以及硬件断点寄存器（DRx）检查。
    -   可在用户模式下检测**内核调试器**的存在（通过 `NtQuerySystemInformation` 和 `_KUSER_SHARED_DATA`）。
-   **反虚拟机**: 通过CPUID、注册表痕迹和虚拟网卡MAC地址前缀，检测游戏是否在VMware, VirtualBox, Hyper-V等虚拟机中运行。
-   **系统状态检查**:
    -   检测Windows是否开启了**测试签名模式 (Test Signing Mode)**，这是内核级外挂运行的温床。
-   **进程与窗口扫描**:
    -   通过黑名单检测系统中的已知作弊/逆向工具进程（如Cheat Engine, x64dbg, IDA）。
    -   通过黑名单检测包含作弊关键词（如“外挂”, “修改器”）的窗口标题。
    -   检测并上报持有本游戏进程高权限句柄的可疑进程。
    -   检测非预期的**游戏窗口覆盖 (Overlay)**，以发现潜在的透视类外挂。
-   **可疑行为关联分析**:
    -   **句柄代理攻击**: 关联分析“白名单进程持有本进程句柄”与“高风险作弊行为（如内存修改）”同时发生的事件，以发现通过合法进程进行代理操作的攻击。
    -   **傀儡进程攻击**: 关联分析“父进程缺失”与后续发生的“高风险作弊行为”，以识别通过进程镂空（Process Hollowing）等技术启动的作弊行为。
-   **父进程验证**: 校验游戏的父进程。**针对启动器(`patch.exe`)启动后立即退出的情况，采用精确的逻辑：若父进程存在，则必须为`patch.exe`；若父进程不存在，则视为潜在可疑，交由关联分析传感器处理。**

#### 行为启发式分析 (Behavioral Heuristics)

-   **输入自动化检测**: 通过低级键鼠钩子采集数据，分析鼠标点击间隔的规律性（标准差）、移动轨迹的平滑度（共线性）、以及**键盘操作的重复序列**（通过高性能的后缀数组算法实现），以检测宏和机器人脚本。

#### 数据收集与上报 (Data & Reporting)

-   **硬件指纹收集**: 在玩家首次登录时，收集磁盘序列号、MAC地址、计算机名、操作系统版本、**CPU品牌字符串**等信息，为机器封禁提供依据。
-   **高效的证据上报**:
    -   所有上报证据在会话内进行去重，减少数据冗余。
    -   通过Protobuf进行数据序列化，高效且跨平台。
    -   采用可由服务器配置的定时上报策略，平衡了实时性与网络开销。
    -   所有配置（包括黑白名单）均可由服务器在运行时动态更新。

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

This project has undergone multiple rounds of refactoring and hardening, resulting in a deep defense system based on dynamic configuration and cooperative multi-sensor architecture.

### 1) Features

#### Proactive Defense & Hardening

-   **Return Address Validation (`IsCallerLegitimate`)**: Provides caller validation for critical, non-high-frequency game logic. For example, this interface can be called at the entry point of one-time events such as **using a rare item, completing a critical quest, or entering a paid dungeon** to effectively block illegal calls from injected DLLs and shellcode. **Note: This function has a non-trivial performance cost and must not be used in logic that executes every frame or at high frequency, such as movement updates or basic attacks.**
-   **Process & Thread Hardening**:
    -   **Hide from Debugger**: In Release mode, the anti-cheat's own monitoring thread is hidden via `NtSetInformationThread`, increasing the difficulty of debugging and reverse engineering.
    -   **Process Mitigation Policies**: Prevents the game client from creating any child processes, closing off a common attack vector.

#### Runtime Analysis

-   **Memory Scanning**:
    -   Detects private, executable memory (`MEM_PRIVATE`) that does not belong to any module, a classic sign of shellcode injection.
-   **Module Integrity Checks**:
    -   Establishes a hash baseline for the `.text` code section of all loaded modules at process startup and compares against it at runtime to detect in-memory code tampering.
-   **Hook Detection**:
    -   **IAT Hooks**: Traverses the main module's Import Address Table, detecting modified function pointers via hash comparison.
    -   **VEH Hooks**: Traverses the Vectored Exception Handling (VEH) chain. **Dynamically locates the VEH list by signature scanning functions in `ntdll.dll` to ensure compatibility with different Windows versions.**
-   **Runtime Activity Monitoring**:
    -   Detects newly created, unknown threads.
    -   Detects newly loaded modules and automatically performs **digital signature verification** on them, effectively identifying unsigned malicious DLLs.
-   **Thread Integrity Scanning**: Checks if a thread's start address is within a legitimate module to identify threads created by shellcode.
-   **Hidden Module Scanning**: Discovers "unlinked" modules hidden via techniques like Manual Mapping by traversing process memory with `VirtualQuery` and performing reverse lookups with `GetModuleHandleExW`.

#### Environment & Integrity

-   **Anti-Debugging**:
    -   Includes a battery of classic anti-debugging techniques, such as `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, PEB flag checks, the `CloseHandle` invalid handle trick, and hardware breakpoint register (DRx) checks.
    -   Can detect the presence of a **kernel debugger** from user-mode (via `NtQuerySystemInformation` and `_KUSER_SHARED_DATA`).
-   **Anti-Virtual Machine**: Detects if the game is running in a VM (like VMware, VirtualBox, Hyper-V) through CPUID, registry artifacts, and virtual network adapter MAC address prefixes.
-   **System State Checks**:
    -   Detects if Windows is in **Test Signing Mode**, a common prerequisite for kernel-level cheats.
-   **Process & Window Scanning**:
    -   Detects known cheating/reversing tools (e.g., Cheat Engine, x64dbg, IDA) via a process blacklist.
    -   Detects window titles containing cheat-related keywords (e.g., "cheat", "外挂") via a keyword blacklist.
    -   Detects and reports suspicious processes holding high-privilege handles to our game process.
    -   Detects unexpected **game window overlays**, which could be used for ESP-style cheats.
-   **Suspicious Behavior Correlation Analysis**:
    -   **Handle Proxy Attacks**: Correlates events where a whitelisted process holds a handle to our process with high-risk cheating behaviors (like memory modification) to detect attacks proxied through legitimate processes.
    -   **Puppet Process Attacks**: Correlates the game having a missing parent process with subsequent high-risk behaviors to identify attacks using Process Hollowing.
-   **Parent Process Validation**: Verifies the game's parent process. **The logic is hardened against race conditions from a fast-closing launcher (`patch.exe`): it requires the parent, if present, to be `patch.exe`, while treating a missing parent as a suspicious event for correlation.**

#### Behavioral Heuristics

-   **Input Automation Detection**: Collects data via low-level hooks to analyze mouse click intervals (standard deviation), movement paths (collinearity), and **repetitive key sequences** (using a high-performance suffix array algorithm) to detect macros and bots.

#### Data Collection & Reporting

-   **Hardware Fingerprint Collection**: On the player's first login, it collects disk serial number, MAC addresses, computer name, OS version, and **CPU brand string** to support machine-based bans.
-   **Efficient Evidence Reporting**:
    -   All reported evidence is de-duplicated within a session to reduce data redundancy.
    -   Uses Protobuf for efficient, cross-platform data serialization.
    -   Employs a server-configurable timed reporting strategy to balance real-time awareness with network overhead.
    -   All configurations (including blacklists/whitelists) can be dynamically updated from the server at runtime.

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