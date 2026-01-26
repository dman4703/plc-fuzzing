from pymodbus.client import ModbusTcpClient
import time

# ================================
# Connection settings
# ================================
PLC_HOST = "127.0.0.1"   # OpenPLC Runtime host
PLC_PORT = 1502           # Modbus TCP default

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
