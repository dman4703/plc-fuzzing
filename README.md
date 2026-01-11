# plc-fuzzing

This repo documents turning OpenPLC into something AFL++ can drive efficiently.

> [Ensure you have AFL++ installed on your system](https://aflplus.plus/docs/install/)

<!-- 
## Temporarily change core_pattern for fuzzing

This is the “correct” approach if you want reliable crash handling.

### Set it to a plain file (“core”)

```bash
# save current WSL value so you can restore it
cat /proc/sys/kernel/core_pattern > /tmp/core_pattern.bak

# switch to plain core files
echo core | sudo tee /proc/sys/kernel/core_pattern
cat /proc/sys/kernel/core_pattern
```

Now run AFL normally:

```bash
afl-fuzz -i in -o out -m none -- ./toy @@
```

### Restore WSL crash capture afterward

```bash
sudo sh -c "cat /tmp/core_pattern.bak > /proc/sys/kernel/core_pattern"
cat /proc/sys/kernel/core_pattern
``` 
-->

<!-- 
(base) dman4703@DMAN:~/plc-fuzzing$ which afl-cc afl-clang-fast afl-gcc || true
/usr/local/bin/afl-cc
/usr/local/bin/afl-clang-fast
/usr/local/bin/afl-gcc
(base) dman4703@DMAN:~/plc-fuzzing$ afl-cc -V 2>/dev/null || afl-cc -h | head
afl-cc++4.35c by Michal Zalewski, Laszlo Szekeres, Marc Heuse

afl-cc/afl-c++ [options]

This is a helper application for afl-fuzz. It serves as a drop-in replacement
for gcc and clang, letting you recompile third-party code with the required
runtime instrumentation. A common use pattern would be one of the following:

  CC=afl-cc CXX=afl-c++ ./configure --disable-shared
  cmake -DCMAKE_C_COMPILERC=afl-cc -DCMAKE_CXX_COMPILER=afl-c++ .
(base) dman4703@DMAN:~/plc-fuzzing$
 -->

## Runtime

The OpenPLC Runtime v4 was forked and installed as a submodule:

```
git submodule add https://github.com/dman4703/openplc-runtime openplc-runtime
cd openplc-runtime

sudo ./install.sh
```

### Using the default runtime:

```
sudo systemctl start openplc-runtime.service
sudo systemctl stop openplc-runtime.service
sudo systemctl restart openplc-runtime.service
```

## Approach

1. Clone OpenPLC v4 Runtime source on WSL and build it from source.
2. Rebuild the runtime core with AFL++ instrumentation (`CC=afl-clang-fast`, `CXX=afl-clang-fast++`; optionally enable ASan).
3. Add a new “fuzz mode” build flag (e.g., `FUZZING=1`) in the runtime build system.
4. Create a fuzz target binary (`openplc_fuzz_target`) that:
   * reads a testcase from `stdin`
   * maps bytes → OpenPLC input image (coils/registers)
   * runs exactly **one** PLC scan cycle
   * resets state (as needed) and loops
5. Implement AFL++ persistent mode in the fuzz target (`__AFL_LOOP(...)`).
6. In fuzz mode, disable/skip:
   * REST API server startup
   * real-time scheduling (SCHED_FIFO) and any sleeps/timers
   * background threads that aren’t required for a single scan
7. Build a minimal PLC program that consumes the fuzzed inputs (or a native C/C++ function block).
8. Add an intentional, controllable crash condition (for end-to-end validation).
9. Create a seed corpus directory (`in/`) with 10–30 small seed inputs.
10. Run AFL++:
    * `afl-fuzz -i in -o out -- ./openplc_fuzz_target`
11. Verify:
    * high exec/sec (relative to your machine)
    * crashes/hangs are saved in `out/`
    * each crash is reproducible by replaying the saved testcase
12. Deliverables:
    * `openplc_fuzz_target`
    * `run_afl.sh`
    * `in/` seeds (+ optional seed generator)
    * `README.md` with build + run + reproduce commands

### Minimal PLC Program: Temperature Control Scenario

> Taken directly from the sample PLC project

#### Variables

| Name      | Class | Type | Location  | Initial Value | Comment                               |
| --------- | ----- | ---- | --------- | ------------- | ------------------------------------- |
| `Temp`    | Local | INT  | `%MW0`    | `260`         | Simulated temperature in tenths of °C |
| `FanCmd`  | Local | BOOL | `%QX0.0`  | `FALSE`       | Cooling fan ON/OFF output             |
| `HighT`   | Local | INT  | blank     | `230`         | High threshold = 23.0 °C              |
| `LowT`    | Local | INT  | blank     | `210`         | Low threshold = 21.0 °C               |

#### Code

```
(* If temp is high enough, turn fan ON *)
IF Temp >= HighT THEN
    FanCmd := TRUE;

(* If tempe is low enough, turn fan OFF *)
ELSIF Temp <= LowT THEN
    FanCmd := FALSE;
END_IF;
```

#### Accompanying Python Script (just for reference)

```python
from pymodbus.client import ModbusTcpClient
import time

# ================================
# Connection settings
# ================================
PLC_HOST = "127.0.0.1"   # OpenPLC Runtime host
PLC_PORT = 502           # Modbus TCP default

# ================================
# Modbus addresses (match your vars)
# ================================
# Temp   -> INT at %MW0   -> holding register 1024
# FanCmd -> BOOL at %QX0.0 -> coil 0
TEMP_HREG_ADDR = 1024
FAN_COIL_ADDR = 0

# Thresholds:
#   HighT = 230 (23.0 °C)
#   LowT  = 210 (21.0 °C)


def c_to_raw(temp_c: float) -> int:
    """
    Convert temperature in deg C to 'tenths of °C' INT.
    Example: 23.0 -> 230
    """
    return int(round(temp_c * 10))


def write_temperature(temp_c: float, client: ModbusTcpClient) -> None:
    """Write temperature to holding register 1024 (%MW0)."""
    raw = c_to_raw(temp_c)
    print(f"[+] Writing {temp_c:.1f} °C (raw={raw}) to holding register {TEMP_HREG_ADDR}")
    result = client.write_register(address=TEMP_HREG_ADDR, value=raw, device_id=1)
    if result.isError():
        print(f"    Write error: {result}")


def read_fan_state(client: ModbusTcpClient) -> bool:
    """Read coil 0 (%QX0.0). Returns True = ON, False = OFF."""
    result = client.read_coils(address=FAN_COIL_ADDR, count=1, device_id=1)
    if result.isError():
        print(f"    Read error: {result}")
        return False
    return bool(result.bits[0])


def main():
    client = ModbusTcpClient(PLC_HOST, port=PLC_PORT)

    print(f"Connecting to PLC at {PLC_HOST}:{PLC_PORT} ...")
    if not client.connect():
        print("ERROR: Could not connect to OpenPLC Modbus server.")
        return
    print("Connected.\n")

    # LowT = 21.0 °C, HighT = 23.0 °C
    test_temps = [20.0, 21.0, 22.0, 23.0, 24.0, 22.0, 21.0, 20.0]

    for t in test_temps:
        write_temperature(t, client)
        time.sleep(0.5)  # give PLC a scan cycle

        fan_on = read_fan_state(client)
        state_str = "ON" if fan_on else "OFF"
        print(f"    Fan state from PLC: {state_str}\n")

        time.sleep(1.0)

    client.close()
    print("Done. Connection closed.")


if __name__ == "__main__":
    main()
```

