#include "CheatMonitor.h"
#include <Windows.h>
#include <chrono>
#include <iostream>
#include <thread>
#include <string>


int main(int argc, char **argv)
{
  bool quickMode = false;
  bool interactive = false;
  for (int i = 1; i < argc; ++i)
  {
    const std::string arg(argv[i]);
    if (arg == "--quick")
    {
      quickMode = true;
    }
    else if (arg == "--interactive")
    {
      interactive = true;
    }
  }

  const auto baselineWait = quickMode ? std::chrono::seconds(2) : std::chrono::seconds(10);
  const auto detectionWait = quickMode ? std::chrono::seconds(3) : std::chrono::seconds(20);
  const auto testThreadWait = quickMode ? std::chrono::seconds(1) : std::chrono::seconds(5);

  std::cout << "--- Anti-Cheat Test Harness ---" << std::endl;
  std::cout << "This program will test the core functionalities of the CheatMonitor library." << std::endl;

  // 1. 初始化 CheatMonitor
  std::cout << "\n[Step 1] Initializing CheatMonitor..." << std::endl;
  if (!CheatMonitor::GetInstance().Initialize())
  {
    std::cerr << "[FAIL] Failed to initialize CheatMonitor. Exiting." << std::endl;
    return 1;
  }
  std::cout << "[OK] CheatMonitor initialized successfully." << std::endl;

  // 2. 模拟玩家登录
  std::cout << "\n[Step 2] Simulating player login (UserID: 123, Name: TestPlayer)..." << std::endl;
  CheatMonitor::GetInstance().OnPlayerLogin(123, "TestPlayer");
  std::cout << "[OK] Player login processed. Monitor is now active." << std::endl;
  std::cout << "     Note: Snapshot upload should be triggered automatically on login." << std::endl;

  // 3. 等待一段时间，让监控系统建立基线
  std::cout << "\n[Step 3] Waiting for baseline establishment..." << std::endl;
  std::this_thread::sleep_for(baselineWait);

  // 4. 执行一系列应该被检测到的测试行为
  std::cout << "\n[Step 4] Performing test actions to be detected..." << std::endl;

  // 测试 A: 分配可执行内存 (模拟注入的Shellcode)
  std::cout << "  -> Test A: Allocating executable memory..." << std::endl;
  LPVOID pMem = VirtualAlloc(NULL, 1024, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  if (pMem)
  {
    std::cout << "     Executable memory allocated at: " << pMem << ". This should be detected by the VirtualAlloc hook." << std::endl;
  }
  else
  {
    std::cerr << "     [WARN] Could not allocate executable memory for test." << std::endl;
  }

  // 测试 B: 创建一个新线程
  std::cout << "  -> Test B: Creating a new thread..." << std::endl;
  std::thread testThread([&testThreadWait]() {
    std::cout << "[Test Thread] >>>> Hello from the new thread! <<<<" << std::endl;
    std::this_thread::sleep_for(testThreadWait);
    std::cout << "[Test Thread] >>>> Exiting. <<<<" << std::endl;
  });
  std::cout << "     New thread created. This should be detected by the new activity scanner." << std::endl;

  // 5. 等待足够长的时间，让后台扫描线程有机会运行并检测到这些行为
  std::cout << "\n[Step 5] Waiting for scans to detect activities..." << std::endl;
  std::this_thread::sleep_for(detectionWait);

  // 5.5 手动触发快照上报（测试功能）
  std::cout << "\n[Step 5.5] Manually triggering snapshot upload for testing..." << std::endl;
  CheatMonitor::GetInstance().UploadSnapshot();
  std::cout << "[OK] Snapshot upload triggered. Check logs for thread/module counts." << std::endl;

  // 6. 清理测试资源
  std::cout << "\n[Step 6] Cleaning up test resources..." << std::endl;
  if (pMem)
  {
    VirtualFree(pMem, 0, MEM_RELEASE);
    std::cout << "  -> Freed allocated memory." << std::endl;
  }
  if (testThread.joinable())
  {
    testThread.join();
    std::cout << "  -> Joined test thread." << std::endl;
  }

  // 7. 模拟玩家登出
  std::cout << "\n[Step 7] Simulating player logout..." << std::endl;
  CheatMonitor::GetInstance().OnPlayerLogout();
  std::cout << "[OK] Player logout processed. A report should have been generated and printed to the console." << std::endl;

  // 8. 关闭 CheatMonitor
  std::cout << "\n[Step 8] Shutting down CheatMonitor..." << std::endl;
  CheatMonitor::GetInstance().Shutdown();
  std::cout << "[OK] CheatMonitor shut down." << std::endl;

  std::cout << "\n--- Test Harness Finished ---" << std::endl;
  std::cout << "Please review the console output for detection logs and error messages." << std::endl;
  if (interactive)
  {
    std::cout << "Press Enter to exit..." << std::endl;
    std::cin.get();
  }
  return 0;
}
