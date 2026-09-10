"""OPC-UA TCP protocol plugin for netscanner."""
import socket
import struct
import time
from typing import List, Optional


class _SelectWrapper:
    """Thin wrapper so plugins.opcua.select.select is patchable independently
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

STATUS_NO_OPCUA = "NO_OPCUA"
STATUS_UA_ERROR = "UA_ERROR"


class _ZeroWindowError(Exception):
    pass


# --- OPC UA Connection Protocol (UACP), OPC UA Part 6 -----------------------
#
# Every UACP message starts with an 8-byte header:
#
#     MessageType   Byte[3]   "HEL" | "ACK" | "ERR" | ...
#     ChunkType     Byte[1]   'F' (0x46) — always Final for HEL/ACK/ERR
#     MessageSize   UInt32    total length INCLUDING these 8 bytes
#
# All integers are little-endian. A String is a signed Int32 byte-length
# followed by UTF-8; -1 means null.

UA_HEADER_FMT = "<3sBI"
UA_HEADER_LEN = 8
UA_CHUNK_FINAL = 0x46           # ord('F')

UA_ACK_LEN = 28                 # 8-byte header + five UInt32 = fixed by spec
UA_ERR_MIN_LEN = 16             # header + StatusCode + Int32 reason length
UA_MAX_REASON_LEN = 4096        # Part 6 caps the Error reason string
UA_MAX_MESSAGE_LEN = UA_ERR_MIN_LEN + UA_MAX_REASON_LEN

# Part 6 requires buffer sizes of at least 8192 bytes. These mirror what
# opcua-asyncio sends, so servers see a completely ordinary client Hello.
UA_PROTOCOL_VERSION = 0
UA_RECV_BUFFER = 65535
UA_SEND_BUFFER = 65535
UA_MAX_MESSAGE_SIZE = 0         # 0 = no limit
UA_MAX_CHUNK_COUNT = 0          # 0 = no limit

# Status codes a server may return in an ERR during the handshake.
# Names follow the Part 6 prose spelling (underscored).
UA_STATUS_NAMES = {
    0x800A0000: "Bad_Timeout",
    0x800B0000: "Bad_ServiceUnsupported",
    0x80130000: "Bad_SecurityChecksFailed",
    0x807D0000: "Bad_TcpServerTooBusy",
    0x807E0000: "Bad_TcpMessageTypeInvalid",
    0x807F0000: "Bad_TcpSecureChannelUnknown",
    0x80800000: "Bad_TcpMessageTooLarge",
    0x80810000: "Bad_TcpNotEnoughResources",
    0x80820000: "Bad_TcpInternalError",
    0x80830000: "Bad_TcpEndpointUrlInvalid",
    0x80840000: "Bad_RequestInterrupted",
    0x80850000: "Bad_RequestTimeout",
    0x80860000: "Bad_SecureChannelClosed",
    0x80870000: "Bad_SecureChannelTokenUnknown",
    0x80880000: "Bad_SequenceNumberInvalid",
    0x80BE0000: "Bad_ProtocolVersionUnsupported",
}


def _ua_string(text: str) -> bytes:
    raw = text.encode("utf-8")
    return struct.pack("<i", len(raw)) + raw


def build_hello_frame(endpoint_url: str) -> bytes:
    """Build a UACP Hello message advertising endpoint_url."""
    body = struct.pack(
        "<IIIII",
        UA_PROTOCOL_VERSION,
        UA_RECV_BUFFER,
        UA_SEND_BUFFER,
        UA_MAX_MESSAGE_SIZE,
        UA_MAX_CHUNK_COUNT,
    ) + _ua_string(endpoint_url)
    header = struct.pack(UA_HEADER_FMT, b"HEL", UA_CHUNK_FINAL,
                         UA_HEADER_LEN + len(body))
    return header + body


def status_name(code: int) -> str:
    return UA_STATUS_NAMES.get(code, f"0x{code:08x}")


def parse_ua_response(data: bytes):
    """Classify a server reply to our Hello.

    Returns ("ACK", fields) or ("ERR", fields), or None if the bytes are not a
    well-formed Acknowledge/Error. Every length is validated against the
    declared MessageSize before it is used, so a hostile or accidental
    length never drives an allocation or a slice past the buffer.
    """
    if len(data) < UA_HEADER_LEN:
        return None

    msg_type, _chunk, msg_size = struct.unpack(
        UA_HEADER_FMT, data[:UA_HEADER_LEN])

    if msg_type not in (b"ACK", b"ERR"):
        return None
    # Bound an attacker-controlled length before it is used for anything.
    # The upper bound is deliberately redundant -- the per-type checks below
    # already constrain the size -- but it keeps the guard next to the read.
    if not UA_HEADER_LEN <= msg_size <= UA_MAX_MESSAGE_LEN:
        return None
    if len(data) < msg_size:
        return None

    if msg_type == b"ACK":
        if msg_size != UA_ACK_LEN:
            return None
        proto, recv, send, max_msg, max_chunk = struct.unpack(
            "<IIIII", data[UA_HEADER_LEN:UA_ACK_LEN])
        return ("ACK", {
            "protocol_version": proto,
            "receive_buffer": recv,
            "send_buffer": send,
            "max_message_size": max_msg,
            "max_chunk_count": max_chunk,
        })

    if msg_size < UA_ERR_MIN_LEN:
        return None
    code = struct.unpack("<I", data[8:12])[0]
    reason_len = struct.unpack("<i", data[12:16])[0]
    if reason_len < -1 or reason_len > UA_MAX_REASON_LEN:
        return None
    # Ties the two independent length fields together — the single strongest
    # check against garbage that happens to start with "ERRF".
    if msg_size != UA_ERR_MIN_LEN + max(0, reason_len):
        return None
    reason = ""
    if reason_len > 0:
        reason = data[16:16 + reason_len].decode("utf-8", errors="replace")
    return ("ERR", {
        "status_code": code,
        "status_name": status_name(code),
        "reason": reason,
    })


def _hello_exchange(sock: socket.socket, endpoint_url: str,
                    response_timeout: float, pcap_log=None):
    """Send one Hello and classify the reply.

    Returns whatever parse_ua_response() makes of the server's answer, or
    raises _ZeroWindowError / TimeoutError / OSError for the transport
    failures the framework reports as distinct statuses.
    """
    frame = build_hello_frame(endpoint_url)

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

    # An Error may carry a 4096-byte reason, so read past the 4096 mark.
    data = sock.recv(8192)
    t_recv = time.time()
    if not data:
        raise OSError("connection closed during recv")
    if pcap_log:
        pcap_log('recv', t_recv, data)

    return parse_ua_response(data)


class OpcuaPlugin(ProtocolPlugin):
    name = "opcua"
    default_port = 4840

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

        def _rst(from_scanner: bool) -> None:
            if not pcap_writers:
                return
            ts = time.time()
            for _w in pcap_writers:
                if from_scanner:
                    _w.write_packet(ts, local_ip, ip, src_port, cfg.port,
                                    TCP_RST, _scanner_seq[0], _device_seq[0])
                else:
                    _w.write_packet(ts, ip, local_ip, cfg.port, src_port,
                                    TCP_RST, _device_seq[0], _scanner_seq[0])

        _log = _pcap_log if pcap_writers else None
        endpoint_url = "opc.tcp://{}:{}".format(ip, cfg.port)
        t_probe = time.monotonic()

        def _elapsed() -> float:
            return round((time.monotonic() - t_probe) * 1000, 1)

        # Unlike Modbus, OPC-UA gets exactly one shot per connection: after a
        # Hello the server expects an OpenSecureChannel, and it closes the
        # connection once it has sent an Error. So there is no retry loop here.
        try:
            parsed = _hello_exchange(sock, endpoint_url,
                                     cfg.response_timeout, pcap_log=_log)
        except _ZeroWindowError:
            _rst(from_scanner=True)
            return [ScanResult(ip=ip, status=STATUS_ZERO_WINDOW,
                               latency_ms=_elapsed(),
                               detail="TCP ZeroWindow on send")]
        except TimeoutError:
            _rst(from_scanner=True)
            return [ScanResult(ip=ip, status=STATUS_TIMEOUT_RESPONSE,
                               latency_ms=_elapsed(),
                               detail="no OPC-UA response within timeout")]
        except OSError as exc:
            _rst(from_scanner=False)
            return [ScanResult(ip=ip, status=STATUS_NO_OPCUA,
                               latency_ms=_elapsed(), detail=str(exc))]

        latency = _elapsed()

        if parsed is None:
            return [ScanResult(ip=ip, status=STATUS_NO_OPCUA,
                               latency_ms=latency,
                               detail="not a valid OPC-UA Acknowledge or Error")]

        kind, fields = parsed

        if kind == "ACK":
            if pcap_writers:
                t_fin = time.time()
                for _w in pcap_writers:
                    _w.write_packet(t_fin, local_ip, ip, src_port, cfg.port,
                                    TCP_FIN_ACK, _scanner_seq[0], _device_seq[0])
            return [ScanResult(ip=ip, status=STATUS_OPEN,
                               latency_ms=latency, extra=dict(fields))]

        # An Error is still a positive identification: only an OPC-UA server
        # answers a Hello with a well-formed UACP Error frame.
        return [ScanResult(
            ip=ip, status=STATUS_UA_ERROR, latency_ms=latency,
            detail=fields["reason"] or fields["status_name"],
            extra={
                "status_code": "0x{:08x}".format(fields["status_code"]),
                "status_name": fields["status_name"],
            },
        )]
