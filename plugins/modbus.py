"""Modbus TCP protocol plugin for netscanner."""
import socket
import struct
import threading
import time
from typing import List, Optional

from netscanner import (
    ProtocolPlugin, ProbeChannel, ScanResult, ScanConfig, PcapWriter,
    ZeroWindowError,
    STATUS_OPEN, STATUS_TIMEOUT_RESPONSE, STATUS_ZERO_WINDOW,
)

STATUS_NO_MODBUS = "NO_MODBUS"
STATUS_EXCEPTION = "EXCEPTION"

_thread_local = threading.local()


def _next_tid() -> int:
    if not hasattr(_thread_local, "tid"):
        _thread_local.tid = 0
    _thread_local.tid = (_thread_local.tid % 65535) + 1
    return _thread_local.tid


def build_modbus_request(tid: int, unit_id: int, fc: int,
                         addr: int, qty: int) -> bytes:
    pdu = struct.pack(">BHH", fc, addr, qty)
    mbap = struct.pack(">HHHB", tid, 0, len(pdu) + 1, unit_id)
    return mbap + pdu


def parse_modbus_response(data: bytes, expected_tid: int):
    if len(data) < 8:
        return None
    tid, proto, length, uid = struct.unpack(">HHHB", data[:7])
    if tid != expected_tid or proto != 0:
        return None
    if len(data) < 6 + length:
        return None
    payload = data[7:]
    fc = payload[0]
    if fc & 0x80:
        if len(payload) < 2:
            return None
        return (tid, uid, fc, payload, payload[1])
    return (tid, uid, fc, payload[1:], None)


def _probe(channel: ProbeChannel, unit_id: int, fc: int) -> tuple:
    tid = _next_tid()
    frame = build_modbus_request(tid=tid, unit_id=unit_id, fc=fc, addr=0, qty=1)

    parsed = parse_modbus_response(channel.exchange(frame), expected_tid=tid)
    if parsed is None:
        return (STATUS_NO_MODBUS, fc, None, "invalid or mismatched response")

    _, _, resp_fc, payload, exc_code = parsed

    if exc_code is not None:
        return (STATUS_EXCEPTION, fc, None, f"Modbus exception code {exc_code}")

    value = None
    if len(payload) >= 3:
        value = struct.unpack(">H", payload[1:3])[0]
    elif len(payload) >= 2:
        value = payload[1]

    return (STATUS_OPEN, fc, value, "")


def _elapsed_ms(start: float) -> float:
    return round((time.monotonic() - start) * 1000, 1)


class ModbusPlugin(ProtocolPlugin):
    name = "modbus"
    default_port = 502

    def probe(self, sock: socket.socket, ip: str, cfg: ScanConfig,
              pcap_writers: Optional[List[PcapWriter]]) -> List[ScanResult]:
        channel = ProbeChannel(sock, ip, cfg, pcap_writers)
        results: List[ScanResult] = []
        fallback_used = False

        for unit_id in [0, 1]:
            t_probe = time.monotonic()
            try:
                status, fc_used, value, detail = _probe(channel, unit_id, 3)

                if status == STATUS_EXCEPTION:
                    try:
                        status, fc_used, value, detail = _probe(
                            channel, unit_id, 1)
                        fallback_used = True
                    except (TimeoutError, OSError, ZeroWindowError):
                        pass

                results.append(ScanResult(
                    ip=ip, status=status, latency_ms=_elapsed_ms(t_probe), detail=detail,
                    extra={
                        "unit_id": unit_id,
                        "fc": fc_used,
                        "register_value": hex(value) if value is not None else None,
                    },
                ))

                if status != STATUS_OPEN or fallback_used:
                    break

            except ZeroWindowError:
                channel.note_reset()
                results.append(ScanResult(
                    ip=ip, status=STATUS_ZERO_WINDOW, latency_ms=_elapsed_ms(t_probe),
                    detail="TCP ZeroWindow on send",
                    extra={"unit_id": unit_id}))
                return results

            except TimeoutError:
                channel.note_reset()
                results.append(ScanResult(
                    ip=ip, status=STATUS_TIMEOUT_RESPONSE, latency_ms=_elapsed_ms(t_probe),
                    detail="no Modbus response within timeout",
                    extra={"unit_id": unit_id}))
                return results

            except OSError as exc:
                channel.note_reset(from_scanner=False)
                results.append(ScanResult(
                    ip=ip, status=STATUS_NO_MODBUS, latency_ms=_elapsed_ms(t_probe),
                    detail=str(exc), extra={"unit_id": unit_id}))
                return results

        if all(r.status == STATUS_OPEN for r in results):
            channel.note_finished()

        return results
