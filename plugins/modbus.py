"""Modbus TCP protocol plugin for netscanner."""
import socket
import struct
import threading
import time
from typing import List, Optional


class _SelectWrapper:
    """Thin wrapper so plugins.modbus.select.select is patchable independently
    from netscanner.select.select even though both delegate to the same stdlib."""

    @staticmethod
    def select(*args, **kwargs):
        import select as _sel
        return _sel.select(*args, **kwargs)


select = _SelectWrapper()

from netscanner import (
    ProtocolPlugin, ScanResult, ScanConfig, PcapWriter,
    STATUS_OPEN, STATUS_TIMEOUT_RESPONSE, STATUS_ZERO_WINDOW,
    TCP_PSH_ACK, TCP_RST, TCP_FIN_ACK,
)

STATUS_NO_MODBUS = "NO_MODBUS"
STATUS_EXCEPTION = "EXCEPTION"

_thread_local = threading.local()


class _ZeroWindowError(Exception):
    pass


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


def _probe(sock: socket.socket, unit_id: int, fc: int,
           response_timeout: float, pcap_log=None) -> tuple:
    tid = _next_tid()
    frame = build_modbus_request(tid=tid, unit_id=unit_id, fc=fc, addr=0, qty=1)

    w_ready = select.select([], [sock], [], response_timeout)
    if not w_ready[1]:
        raise _ZeroWindowError()

    t_send = time.time()
    sock.sendall(frame)
    if pcap_log:
        pcap_log('send', t_send, frame)

    r_ready = select.select([sock], [], [], response_timeout)
    if not r_ready[0]:
        raise TimeoutError("response timeout")

    data = sock.recv(4096)
    t_recv = time.time()
    if not data:
        raise OSError("connection closed during recv")
    if pcap_log:
        pcap_log('recv', t_recv, data)

    parsed = parse_modbus_response(data, expected_tid=tid)
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


class ModbusPlugin(ProtocolPlugin):
    name = "modbus"
    default_port = 502

    def probe(self, sock: socket.socket, ip: str, cfg: ScanConfig,
              pcap_writers: Optional[List[PcapWriter]]) -> List[ScanResult]:
        local_ip = "0.0.0.0"  # nosec B104 — pcap source IP, not a socket bind
        src_port = 0
        if pcap_writers:
            local_ip, src_port = sock.getsockname()

        _scanner_seq = [1]
        _device_seq  = [1]

        def _pcap_log(direction: str, ts: float, raw_bytes: bytes) -> None:
            assert pcap_writers is not None
            if direction == 'send':
                for _w in pcap_writers:
                    _w.write_packet(ts, local_ip, ip, src_port, cfg.port,
                                    TCP_PSH_ACK, _scanner_seq[0], _device_seq[0],
                                    raw_bytes)
                _scanner_seq[0] += len(raw_bytes)
            else:
                for _w in pcap_writers:
                    _w.write_packet(ts, ip, local_ip, cfg.port, src_port,
                                    TCP_PSH_ACK, _device_seq[0], _scanner_seq[0],
                                    raw_bytes)
                _device_seq[0] += len(raw_bytes)

        _log = _pcap_log if pcap_writers else None
        results: List[ScanResult] = []
        fallback_used = False

        for unit_id in [0, 1]:
            t_probe = time.monotonic()
            try:
                status, fc_used, value, detail = _probe(
                    sock, unit_id, 3, cfg.response_timeout, pcap_log=_log)

                if status == STATUS_EXCEPTION:
                    try:
                        status, fc_used, value, detail = _probe(
                            sock, unit_id, 1, cfg.response_timeout, pcap_log=_log)
                        fallback_used = True
                    except (TimeoutError, OSError, _ZeroWindowError):
                        pass

                results.append(ScanResult(
                    ip=ip, status=status,
                    latency_ms=round((time.monotonic() - t_probe) * 1000, 1),
                    detail=detail,
                    extra={
                        "unit_id": unit_id,
                        "fc": fc_used,
                        "register_value": hex(value) if value is not None else None,
                    },
                ))

                if status != STATUS_OPEN or fallback_used:
                    break

            except _ZeroWindowError:
                if pcap_writers:
                    t_rst = time.time()
                    for _w in pcap_writers:
                        _w.write_packet(t_rst, local_ip, ip, src_port, cfg.port,
                                        TCP_RST, _scanner_seq[0], _device_seq[0])
                results.append(ScanResult(
                    ip=ip, status=STATUS_ZERO_WINDOW,
                    latency_ms=round((time.monotonic() - t_probe) * 1000, 1),
                    detail="TCP ZeroWindow on send",
                    extra={"unit_id": unit_id},
                ))
                return results

            except TimeoutError:
                if pcap_writers:
                    t_rst = time.time()
                    for _w in pcap_writers:
                        _w.write_packet(t_rst, local_ip, ip, src_port, cfg.port,
                                        TCP_RST, _scanner_seq[0], _device_seq[0])
                results.append(ScanResult(
                    ip=ip, status=STATUS_TIMEOUT_RESPONSE,
                    latency_ms=round((time.monotonic() - t_probe) * 1000, 1),
                    detail="no Modbus response within timeout",
                    extra={"unit_id": unit_id},
                ))
                return results

            except OSError as exc:
                if pcap_writers:
                    t_dev_rst = time.time()
                    for _w in pcap_writers:
                        _w.write_packet(t_dev_rst, ip, local_ip, cfg.port, src_port,
                                        TCP_RST, _device_seq[0], _scanner_seq[0])
                results.append(ScanResult(
                    ip=ip, status=STATUS_NO_MODBUS,
                    latency_ms=round((time.monotonic() - t_probe) * 1000, 1),
                    detail=str(exc),
                    extra={"unit_id": unit_id},
                ))
                return results

        if pcap_writers and all(r.status == STATUS_OPEN for r in results):
            t_fin = time.time()
            for _w in pcap_writers:
                _w.write_packet(t_fin, local_ip, ip, src_port, cfg.port,
                                TCP_FIN_ACK, _scanner_seq[0], _device_seq[0])

        return results
