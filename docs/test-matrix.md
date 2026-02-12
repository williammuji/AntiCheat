# AntiCheat Test Matrix

## Scope

- Unit tests: deterministic logic and parsing behavior.
- Smoke tests: full library startup and basic runtime actions.
- Regression hooks: OS/version capability seams for future sensor mocks.

## Unit Tests (Implemented)

1. `test/unit/SystemUtilsHashTest.cpp`
   - FNV-1a known vectors.
   - Windows capability matrix using test override seam.
2. `test/unit/UtilsStringTest.cpp`
   - UTF-8/wide conversion roundtrip.
   - Path file-name extraction.
3. `test/unit/CheatConfigManagerTest.cpp`
   - Default config sanity.
   - Protobuf server update parsing and field override behavior.
4. `test/unit/HdeDisasmTest.cpp`
   - Instruction decode length/opcode baseline.
5. `test/unit/SensorMemorySecurityTest.cpp`
   - Safe-region filter sanity.
   - Hidden PE-like memory region report trigger.
   - RWX/RX helper classification and low-address-small-RWX skip boundary.
6. `test/unit/SensorProcessHandleTest.cpp`
   - Handle buffer resize behavior.
   - Suspicious access mask classification.
   - Severe overflow and retry-abort boundaries.
7. `test/unit/SensorVehHookTest.cpp`
   - VEH structure access for known layout.
   - VEH traversal extracts handlers.
   - Executable protection and normalized module-file extraction helpers.
8. `test/unit/SensorAdvancedAntiDebugTest.cpp`
   - Mocked NT API signals for debug flag and kernel debugger checks.
   - No-debug-signal mock path does not produce false positives.
9. `test/unit/SensorModuleIntegrityTest.cpp`
   - Writable code protection classification.
   - Baseline learn / tamper emission decision helpers.
10. `test/unit/SensorThreadActivityTest.cpp`
   - Ignorable NTSTATUS set classification.
   - Hardware breakpoint register detection helper.
   - Non-ignorable NtQuery thread error path sets failure reason.
11. `test/unit/SensorModuleActivityTest.cpp`
   - Unknown-module reporting decision helper.
   - Empty module-cache failure path.
   - Timeout branch and trusted-module insertion path.

## Smoke Test (Implemented)

- `test/main.cpp` supports CI-friendly non-interactive mode with `--quick`.
- Configure with `-DBUILD_TESTING=ON`.
- `ctest` target `smoke.quick` executes harness with bounded duration.

## Next Regression Targets (Priority Order)

1. `ProcessHandleSensor`: cursor推进、PID节流TTL与签名缓存命中路径的确定性测试。
2. `MemorySecuritySensor`:二次确认路径（线程起点命中/签名不可信）与白名单边界。
3. `VehHookSensor`: handler 来源归属（基线模块非代码区/白名单模块）证据分支。
4. `ModuleIntegritySensor`: baseline mismatch 在 self/whitelist/untrusted 三分支的证据断言。
5. `ThreadActivitySensor`: AnalyzeNewThread 对未知起点线程上报路径（需可控上下文）。
6. `AdvancedAntiDebugSensor`: API异常与VBS门控协同路径覆盖。
