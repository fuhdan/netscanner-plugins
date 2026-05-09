# Modbus/TCP Plugin

Scans for Modbus/TCP devices on port 502. Common in PLCs, SCADA systems,
industrial controllers, and building automation equipment.

## Protocol

Modbus/TCP wraps the Modbus application protocol in TCP (port 502). The plugin
probes each host with a Read Holding Registers (FC3) request. If the device
returns a Modbus exception, it falls back to Read Coils (FC1). Both unit IDs
0 and 1 are tested independently — many devices respond on one but not the other.

## Usage

```bash
python3 netscanner.py 10.0.0.0/24 --protocol modbus
python3 netscanner.py 10.0.0.1 --protocol modbus --port 502
```

## Output fields

| Field | Description | Example |
|-------|-------------|---------|
| `unit_id` | Modbus unit/slave ID that responded | `0`, `1` |
| `fc` | Function code used for the successful read | `3`, `1` |
| `register_value` | First register or coil value returned | `0x6400` |

## Status codes

| Status | Meaning |
|--------|---------|
| `OPEN` | Device responded correctly to the Modbus probe |
| `NO_MODBUS` | TCP connected but response was not valid Modbus |
| `EXCEPTION` | Device returned a Modbus exception on both FC3 and FC1 |

## Example output

```
[10.0.0.1]    OPEN    unit_id=0  fc=3  register_value=0x6400   45ms
[10.0.0.2]    OPEN    unit_id=1  fc=1  register_value=0x01     52ms
[10.0.0.3]    NO_MODBUS                                         12ms
[10.0.0.4]    REFUSED                                           1ms
```

## Known limitations

- Only probes unit IDs 0 and 1. Devices configured for other unit IDs will not respond.
- Reads one register/coil at address 0 only.
- Does not support Modbus RTU over TCP.
- ZeroWindow from some devices (notably Siemens S7) is detected and reported — include the pcap if you see unexpected results.
