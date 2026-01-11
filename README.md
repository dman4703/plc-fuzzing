# plc-fuzzing

This repo documents turning OpenPLC v4 Runtime into an efficient AFL++ fuzz target. This implementation creates a standalone in-process harness that directly loads a compiled PLC program <!-- (`libplc_*.so`) --> and executes exactly one scan cycle per testcase. This approach bypasses the full runtime environment (web server, real-time scheduling, background threads) to maximize fuzzing throughput.

> **Prerequisites**: [Install AFL++](https://aflplus.plus/docs/install/) on your system.

## Overview

The goal is to apply coverage-guided fuzzing to PLC logic to discover crashes, assertion failures, or unexpected behaviors. This is achieved by:

1. **Instrumenting the OpenPLC runtime core** with AFL++ compile-time instrumentation (`afl-clang-fast`).
2. **Instrumenting the compiled PLC program** by adapting the build scripts to use AFL++ compilers.
3. **Creating a dedicated fuzz harness** (`openplc_fuzz_target`) that loads the PLC program, reads fuzzed input, maps it to OpenPLC's internal image tables (`%MW`, `%IX`, etc.), and executes one scan cycle.
4. **Using AFL++ persistent mode** to run thousands of testcases per second in a single process.
5. **Ensuring deterministic execution** by resetting all relevant state (timers, debug flags, input buffers, force flags) between iterations to achieve high stability (> 98%).

## Development Process

### 1. Environment Setup
- Cloned [OpenPLC v4 Runtime](https://autonomylogic.com/runtime) source on WSL and verified it builds from source.
- Installed [AFL++](https://aflplus.plus/docs/install/) on WSL and confirmed basic functionality.
- Installed [OpenPLC v4 Editor](https://autonomylogic.com/download) on Windows for generating and compiling PLC programs.

### 2. AFL++ Instrumentation of Runtime Core
- Modified `openplc-runtime/core/src/CMakeLists.txt` to add a `FUZZING` build option.
- Configured the build system to compile with `CC=afl-clang-fast` and `CXX=afl-clang-fast++`.
- Created a new build directory (`build-afl`) to separate instrumented builds from normal builds.

### 3. Fuzz Target Implementation
- Created `openplc-runtime/core/src/plc_app/openplc_fuzz_target.c`:
  - Initializes the OpenPLC plugin manager and image tables.
  - Uses `dlopen()` to load the compiled PLC program (`libplc_*.so`) at runtime.
  - Implements AFL++ persistent mode with `__AFL_LOOP(1000)` for efficiency.
  - Reads testcase bytes from `__AFL_FUZZ_TESTCASE_BUF` (or stdin in non-persistent mode).
  - Maps fuzzed bytes to OpenPLC input memory regions (`%MW0..%MW7`, `%IX0.0..%IX3.7`).
  - Calls `ext_config_run__()` to execute exactly one PLC scan cycle.
  - Resets critical state between iterations: `tick__`, `__CURRENT_TIME`, `__DEBUG`, input buffers, and force flags (`trace_reset()`).

### 4. Stripped-Down Runtime Environment
In fuzz mode, the harness completely bypasses

- REST API server and Modbus/DNP3 protocol handlers
- Real-time OS scheduling (`SCHED_FIFO`) and sleep/timer operations
- Background monitoring and logging threads
- Interactive debugger and web UI

to ensure maximum exec/sec and deterministic behavior.

### 5. PLC Program Instrumentation
- Modified `openplc-runtime/scripts/compile.sh` to respect `CC`, `CXX`, `CFLAGS`, `CXXFLAGS`, and `OPENPLC_BUILD_DIR` environment variables.
- Modified `openplc-runtime/scripts/compile-clean.sh` to use `OPENPLC_BUILD_DIR`.
- This allows the generated PLC program (`libplc_*.so`) to be compiled with AFL++ instrumentation, ensuring coverage data is collected from the actual PLC logic, not just the harness.
- Used `AFL_PRELOAD` to ensure the dynamically loaded library contributes to the coverage map.

### 6. Determinism & Stability Tuning
Initial runs showed 94.55% stability due to non-deterministic state.

- **Root cause**: `__CURRENT_TIME`, `__DEBUG`, and `tick__` were persisting across iterations, causing different execution paths for identical inputs.
- **Solution**: Explicitly reset these globals and clear input memory regions at the start of each `__AFL_LOOP` iteration. Added `trace_reset()` call to clear IEC force flags.
- **Result**: Stability improved to ~98.7%, with remaining instability from a single "first-run vs. later runs" edge in persistent mode (acceptable for AFL++).

### 7. Validation: Intentional Crash
- Added a controllable crash condition: if `OPENPLC_FUZZ_CRASH=1` is set and `%MW0 == 0x1337`, the harness calls `__builtin_trap()`.
- Created a seed file (`in/mw0_1337.bin`) with the crash-triggering value.
- Verified end-to-end crash detection: AFL++ finds and saves the crash in `out/default/crashes/`.

### 8. Automation & Seed Corpus
- Created `run_afl.sh` to automate:
  - Building the instrumented runtime core.
  - Compiling the PLC program with AFL++ instrumentation.
  - Setting `AFL_PRELOAD` for `dlopen()` coverage.
  - Temporarily adjusting `/proc/sys/kernel/core_pattern` for reliable crash capture (requires `sudo`).
  - Running `afl-fuzz` with appropriate flags (`-G 20` to cap max input size).
- Created an initial seed corpus in `in/` with representative inputs for different PLC variables.

### 9. Testing & Verification
- Confirmed high exec/sec (varies by machine; typical: 1000–5000+ exec/sec in persistent mode).
- Verified crashes are saved to `out/default/crashes/` and are reproducible by replaying the testcase.
- Confirmed that both the runtime harness and the PLC program contribute to coverage (checked via `AFL_PRELOAD` for dynamically loaded library).

## What was implemented

### Fuzz Harness: `openplc_fuzz_target.c`
- **Location**: `openplc-runtime/core/src/plc_app/openplc_fuzz_target.c`
- **Key Features**:
  - Reads testcase bytes from AFL++ shared memory (`__AFL_FUZZ_TESTCASE_BUF`) or stdin fallback.
  - Maps up to 20 bytes into OpenPLC image tables:
    - Bytes 0–15 → `%MW0..%MW7` (8 × 16-bit words, little-endian)
    - Bytes 16–19 → `%IX0.0..%IX3.7` (32 input bits)
  - Executes exactly **one** PLC scan cycle per testcase via `ext_config_run__(tick__)`.
  - Implements **AFL++ persistent mode** with `__AFL_LOOP(1000)` to run 1000 iterations per fork.
  - Resets state between iterations:
    - `tick__` counter and `__CURRENT_TIME` (PLC timing)
    - `__DEBUG` flag
    - Input memory regions (`int_memory`, `bool_input`)
    - IEC force flags via `trace_reset()`
  - Optional intentional crash: `if (OPENPLC_FUZZ_CRASH=1 && %MW0==0x1337) __builtin_trap();`

### Build System Changes
- **CMake flag**: `openplc-runtime/core/src/CMakeLists.txt` adds `-DFUZZING=ON` option.
  - When enabled, builds `openplc_fuzz_target` executable and links against `libdl`, `libpthread`, and Python libraries.
- **PLC build script**: `openplc-runtime/scripts/compile.sh` now respects:
  - `CC` and `CXX` (defaults to `gcc`/`g++` if unset, but can be overridden with `afl-clang-fast`/`afl-clang-fast++`)
  - `CFLAGS` and `CXXFLAGS` for custom compiler flags
  - `OPENPLC_BUILD_DIR` for output directory (defaults to `build`)
- **PLC clean script**: `openplc-runtime/scripts/compile-clean.sh` uses `OPENPLC_BUILD_DIR` for consistency.

### Automation: `run_afl.sh`
- **Handles:**
  - Setting up and restoring `/proc/sys/kernel/core_pattern` (requires `sudo`) for reliable crash capture.
  - Building the OpenPLC core with AFL++ instrumentation (`-DFUZZING=ON`, `CC=afl-clang-fast`, `CXX=afl-clang-fast++`).
  - Compiling the PLC program with AFL++ compilers into `build-afl/libplc_*.so`.
  - Exporting `AFL_PRELOAD` with the path to `libplc_*.so` so `dlopen()` coverage is captured.
  - Running `afl-fuzz -i in -o out -G 20 -- ./openplc-runtime/build-afl/openplc_fuzz_target`.

- **Flags:**
  - `-G 20` caps max input size at 20 bytes (matching the harness input format).
  - `AFL_PRELOAD` ensures the dynamically loaded PLC library is instrumented and contributes to coverage.

### Seed Corpus: `in/`
- Contains initial seed files for AFL++:
  - `mw0_1337.bin`: Triggers the intentional crash (when `OPENPLC_FUZZ_CRASH=1`).
  - `mw0_0.bin`, `mw0_100.bin`, etc.: Various valid `%MW0` values.
  - `mixed_20.bin`: 20 bytes covering multiple input regions.

## Usage

### Running AFL++

```bash
./run_afl.sh
```

- You do not need to start the normal OpenPLC runtime service or connect the OpenPLC Editor to fuzz with this harness.
- `run_afl.sh` builds the instrumented runtime and PLC program into `openplc-runtime/build-afl/`.
- The script requires `sudo` access to temporarily adjust `/proc/sys/kernel/core_pattern` for reliable crash detection (it restores the original value on exit).
- AFL++ will create an `out/` directory with fuzzing results (queue, crashes, hangs, stats).
- when terminated, The script will automatically restore the original `core_pattern` setting.

## Harness Input Format

The fuzz target consumes a **small fixed input image** (maximum 20 bytes):

- **Bytes 0–15**: 8 little-endian 16-bit words → `%MW0..%MW7` (`int_memory[0..7]`)
  - These map to IEC 61131-3 `INT` memory words (e.g., `Temp AT %MW0 : INT`).
- **Bytes 16–19**: 4 bytes → `%IX0.0..%IX3.7` (32 input bits in `bool_input[0..3][0..7]`)
  - These map to IEC 61131-3 `BOOL` inputs (e.g., `Sensor AT %IX0.0 : BOOL`).

The harness maps all provided bytes and pads with zeros if the testcase is shorter than 20 bytes. `run_afl.sh` sets `-G 20` to cap AFL++'s max generation size (override with `AFL_MAX_LEN=<bytes>`).

## Validating the Setup (Intentional Crash)

To verify that AFL++ can detect crashes end-to-end, enable a controlled crash condition:

```bash
OPENPLC_FUZZ_CRASH=1 ./run_afl.sh
```

- The fuzz target checks if `%MW0 == 0x1337` (little-endian) and calls `__builtin_trap()` if true.
- A matching seed exists in `in/mw0_1337.bin`, so AFL++ should find the crash within seconds.
- Crashes are saved to `out/default/crashes/`.


## Reproducing a Saved Crash

To manually replay a crash outside of `afl-fuzz`:

```bash
# Find the PLC library
LIBPLC="$(ls -1 openplc-runtime/build-afl/libplc_*.so | head -n 1)"

# Replay the crash
LD_PRELOAD="$LIBPLC" OPENPLC_BUILD_DIR="$(pwd)/openplc-runtime/build-afl" \
  ./openplc-runtime/build-afl/openplc_fuzz_target < out/default/crashes/id:000000*
```

### Minimal PLC Program: Temperature Control Scenario

### Variables

| Name      | Class | Type | Location  | Initial Value | Comment                               |
| --------- | ----- | ---- | --------- | ------------- | ------------------------------------- |
| `Temp`    | Local | INT  | `%MW0`    | `260`         | Simulated temperature in tenths of °C |
| `FanCmd`  | Local | BOOL | `%QX0.0`  | `FALSE`       | Cooling fan ON/OFF output             |
| `HighT`   | Local | INT  | blank     | `230`         | High threshold = 23.0 °C              |
| `LowT`    | Local | INT  | blank     | `210`         | Low threshold = 21.0 °C               |

### Code

```
(* If temp is high enough, turn fan ON *)
IF Temp >= HighT THEN
    FanCmd := TRUE;

(* If tempe is low enough, turn fan OFF *)
ELSIF Temp <= LowT THEN
    FanCmd := FALSE;
END_IF;
```
