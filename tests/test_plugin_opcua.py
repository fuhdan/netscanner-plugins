"""Tests for the OPC-UA TCP plugin."""
import struct

from plugins.opcua import (
    build_hello_frame, parse_ua_response,
    UA_RECV_BUFFER, UA_SEND_BUFFER,
)


# ---------------------------------------------------------------------------
# build_hello_frame
# ---------------------------------------------------------------------------

def test_hello_header_is_hel_final_chunk():
    frame = build_hello_frame("opc.tcp://10.0.0.1:4840")
    assert frame[0:3] == b"HEL"
    assert frame[3:4] == b"F"


def test_hello_message_size_is_little_endian_and_includes_header():
    frame = build_hello_frame("opc.tcp://10.0.0.1:4840")
    assert struct.unpack("<I", frame[4:8])[0] == len(frame)


def test_hello_body_field_order():
    frame = build_hello_frame("opc.tcp://10.0.0.1:4840")
    proto, recv, send, max_msg, max_chunk = struct.unpack("<IIIII", frame[8:28])
    assert proto == 0
    assert recv == UA_RECV_BUFFER
    assert send == UA_SEND_BUFFER
    assert max_msg == 0
    assert max_chunk == 0


def test_hello_endpoint_url_is_length_prefixed_utf8():
    url = "opc.tcp://10.0.0.1:4840"
    frame = build_hello_frame(url)
    assert struct.unpack("<i", frame[28:32])[0] == len(url.encode())
    assert frame[32:] == url.encode()


def test_hello_total_length_formula():
    url = "opc.tcp://10.0.0.1:4840"
    frame = build_hello_frame(url)
    assert len(frame) == 8 + 20 + 4 + len(url.encode())


def test_hello_buffer_sizes_meet_spec_minimum():
    # OPC UA Part 6: buffer sizes shall be at least 8192 bytes.
    assert UA_RECV_BUFFER >= 8192
    assert UA_SEND_BUFFER >= 8192


def test_hello_matches_reference_capture_byte_for_byte():
    # Real 56-byte HEL emitted by opcua-asyncio for opc.tcp://localhost:4840.
    expected = bytes.fromhex(
        "48454c4638000000"          # "HELF", MessageSize = 56
        "00000000"                  # ProtocolVersion   = 0
        "ffff0000"                  # ReceiveBufferSize = 65535
        "ffff0000"                  # SendBufferSize    = 65535
        "00000000"                  # MaxMessageSize    = 0 (no limit)
        "00000000"                  # MaxChunkCount     = 0 (no limit)
        "18000000"                  # EndpointUrl length = 24
        "6f70632e7463703a2f2f6c6f63616c686f73743a34383430"  # the URL
    )
    assert build_hello_frame("opc.tcp://localhost:4840") == expected


def test_hello_handles_non_ascii_url_by_byte_length():
    url = "opc.tcp://übel:4840"
    frame = build_hello_frame(url)
    declared = struct.unpack("<i", frame[28:32])[0]
    assert declared == len(url.encode("utf-8")) > len(url)


# ---------------------------------------------------------------------------
# parse_ua_response — Acknowledge
# ---------------------------------------------------------------------------

def _make_ack(proto=0, recv=65536, send=65536, max_msg=16777216, max_chunk=5):
    body = struct.pack("<IIIII", proto, recv, send, max_msg, max_chunk)
    return struct.pack("<3sBI", b"ACK", 0x46, 8 + len(body)) + body


def _make_err(code=0x80830000, reason="Bad_TcpEndpointUrlInvalid"):
    raw = reason.encode("utf-8")
    body = struct.pack("<I", code) + struct.pack("<i", len(raw)) + raw
    return struct.pack("<3sBI", b"ERR", 0x46, 8 + len(body)) + body


def test_parse_ack_returns_negotiated_limits():
    kind, fields = parse_ua_response(_make_ack())
    assert kind == "ACK"
    assert fields == {
        "protocol_version": 0,
        "receive_buffer": 65536,
        "send_buffer": 65536,
        "max_message_size": 16777216,
        "max_chunk_count": 5,
    }


def test_parse_ack_is_exactly_28_bytes():
    assert len(_make_ack()) == 28


def test_parse_ack_rejects_wrong_declared_size():
    # 32 bytes present AND declared, so the truncation guard cannot fire --
    # only the "an Acknowledge is exactly 28 bytes" rule can reject this.
    frame = struct.pack("<3sBI", b"ACK", 0x46, 32) + \
        struct.pack("<IIIII", 0, 65536, 65536, 0, 0) + b"\x00\x00\x00\x00"
    assert len(frame) == 32
    assert parse_ua_response(frame) is None


# ---------------------------------------------------------------------------
# parse_ua_response — Error
# ---------------------------------------------------------------------------

def test_parse_err_returns_status_code_and_reason():
    kind, fields = parse_ua_response(_make_err())
    assert kind == "ERR"
    assert fields["status_code"] == 0x80830000
    assert fields["status_name"] == "Bad_TcpEndpointUrlInvalid"
    assert fields["reason"] == "Bad_TcpEndpointUrlInvalid"


def test_parse_err_with_null_reason_is_16_bytes():
    frame = struct.pack("<3sBI", b"ERR", 0x46, 16) + \
        struct.pack("<I", 0x807D0000) + struct.pack("<i", -1)
    assert len(frame) == 16
    kind, fields = parse_ua_response(frame)
    assert kind == "ERR"
    assert fields["status_code"] == 0x807D0000
    assert fields["reason"] == ""


def test_parse_err_unknown_status_code_still_parses():
    kind, fields = parse_ua_response(_make_err(code=0x80FF0000, reason="nope"))
    assert kind == "ERR"
    assert fields["status_code"] == 0x80FF0000
    assert fields["status_name"] == "0x80ff0000"


def test_parse_err_rejects_inconsistent_reason_length():
    # ReasonLength claims 99 bytes but MessageSize accounts for none of them.
    # All 99 bytes are actually present, so the truncation guard cannot fire --
    # only the MessageSize == 16 + ReasonLength invariant can reject this.
    frame = struct.pack("<3sBI", b"ERR", 0x46, 20) + \
        struct.pack("<I", 0x807D0000) + struct.pack("<i", 99) + b"x" * 99
    assert len(frame) > 20
    assert parse_ua_response(frame) is None


def test_parse_err_rejects_negative_reason_length():
    # -1 means null, but any other negative length is malformed.
    frame = struct.pack("<3sBI", b"ERR", 0x46, 16) + \
        struct.pack("<I", 0x807D0000) + struct.pack("<i", -5)
    assert parse_ua_response(frame) is None


# ---------------------------------------------------------------------------
# parse_ua_response — rejection of non-OPC-UA traffic
# ---------------------------------------------------------------------------

def test_parse_rejects_http_banner():
    assert parse_ua_response(b"HTTP/1.1 200 OK\r\n\r\n") is None


def test_parse_rejects_ssh_banner():
    assert parse_ua_response(b"SSH-2.0-OpenSSH_8.9\r\n") is None


def test_parse_rejects_tls_server_hello():
    assert parse_ua_response(b"\x16\x03\x03\x00\x50\x02\x00\x00\x4c") is None


def test_parse_rejects_short_header():
    assert parse_ua_response(b"ACK") is None


def test_parse_rejects_empty():
    assert parse_ua_response(b"") is None


def test_parse_rejects_valid_err_body_under_wrong_message_type():
    # Byte-for-byte a well-formed Error body, but carried by an OPN message.
    # Only the message-type whitelist can reject this -- every downstream
    # check would happily accept it.
    frame = struct.pack("<3sBI", b"OPN", 0x46, 16) + \
        struct.pack("<I", 0x807D0000) + struct.pack("<i", -1)
    assert parse_ua_response(frame) is None


def test_parse_rejects_unknown_message_type():
    frame = struct.pack("<3sBI", b"XXX", 0x46, 28) + struct.pack("<IIIII", 0, 0, 0, 0, 0)
    assert parse_ua_response(frame) is None


def test_parse_rejects_hel_echoed_back():
    # A server echoing our own Hello is not an Acknowledge.
    assert parse_ua_response(build_hello_frame("opc.tcp://10.0.0.1:4840")) is None


def test_parse_rejects_implausible_message_size():
    frame = struct.pack("<3sBI", b"ACK", 0x46, 0xFFFFFFFF)
    assert parse_ua_response(frame) is None


def test_parse_rejects_truncated_ack_body():
    assert parse_ua_response(_make_ack()[:20]) is None


def test_parse_accepts_ack_with_trailing_bytes_from_stream():
    # recv() may hand back the ACK plus the start of a following message.
    kind, _ = parse_ua_response(_make_ack() + b"MSGF\x10\x00\x00\x00")
    assert kind == "ACK"


# ---------------------------------------------------------------------------
# Plugin behaviour via scan_host
#
# Dual select patch, exactly as the modbus suite does:
#   @patch("netscanner.socket.socket")      -> mock_socket_cls (outermost/last)
#   @patch("plugins.opcua.select.select")   -> mock_ua_select
#   @patch("netscanner.select.select")      -> mock_ns_select  (innermost/first)
# ---------------------------------------------------------------------------

import errno as errno_mod          # noqa: E402
import os                          # noqa: E402
import socket                      # noqa: E402
import tempfile                    # noqa: E402

from unittest.mock import MagicMock, patch   # noqa: E402

from netscanner import (           # noqa: E402
    ScanConfig, PcapWriter, scan_host, write_csv, format_result_line,
    STATUS_OPEN, STATUS_REFUSED, STATUS_TIMEOUT_CONNECT,
    STATUS_TIMEOUT_RESPONSE, STATUS_ZERO_WINDOW, STATUS_CLOSED_IMMEDIATELY,
    TCP_SYN, TCP_ACK, TCP_SYN_ACK, TCP_PSH_ACK, TCP_FIN_ACK, TCP_RST,
    _discover_plugins,
)
from plugins.opcua import (        # noqa: E402
    OpcuaPlugin, STATUS_NO_OPCUA, STATUS_UA_ERROR,
)

import io                          # noqa: E402


def _parse_pcap_records(data: bytes):
    records = []
    pos = 24
    while pos + 16 <= len(data):
        _s, _u, incl_len, _ = struct.unpack("<IIII", data[pos:pos + 16])
        records.append(data[pos + 16: pos + 16 + incl_len])
        pos += 16 + incl_len
    return records


def _pkt_tcp_flags(pkt: bytes) -> int:
    return pkt[33]


def _pkt_payload(pkt: bytes) -> bytes:
    return pkt[40:]


def _ready(sock):
    """select side effects for one successful send + one successful recv."""
    return [([], [sock], []), ([sock], [], [])]


# --- plugin metadata -------------------------------------------------------

def test_plugin_name_and_default_port():
    p = OpcuaPlugin()
    assert p.name == "opcua"
    assert p.default_port == 4840


def test_plugin_is_discovered_by_framework():
    assert "opcua" in _discover_plugins()


# --- happy path ------------------------------------------------------------

@patch("netscanner.socket.socket")
@patch("plugins.opcua.select.select")
@patch("netscanner.select.select")
def test_scan_host_open_on_acknowledge(mock_ns_select, mock_ua_select, mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    sock.getsockname.return_value = ("10.0.0.250", 12345)
    mock_ns_select.side_effect = [([], [], [])]
    mock_ua_select.side_effect = _ready(sock)
    sock.recv.side_effect = [_make_ack()]

    results = scan_host("10.0.0.1", ScanConfig(port=4840), OpcuaPlugin())

    assert len(results) == 1
    r = results[0]
    assert r.status == STATUS_OPEN
    assert r.extra["protocol_version"] == 0
    assert r.extra["receive_buffer"] == 65536
    assert r.extra["send_buffer"] == 65536
    assert r.extra["max_message_size"] == 16777216
    assert r.extra["max_chunk_count"] == 5


@patch("netscanner.socket.socket")
@patch("plugins.opcua.select.select")
@patch("netscanner.select.select")
def test_hello_advertises_the_scanned_ip_and_port(mock_ns_select, mock_ua_select,
                                                  mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    sock.getsockname.return_value = ("10.0.0.250", 12345)
    mock_ns_select.side_effect = [([], [], [])]
    mock_ua_select.side_effect = _ready(sock)
    sock.recv.side_effect = [_make_ack()]

    scan_host("10.0.0.7", ScanConfig(port=4841), OpcuaPlugin())

    sent = sock.sendall.call_args[0][0]
    url_len = struct.unpack("<i", sent[28:32])[0]
    assert sent[32:32 + url_len].decode() == "opc.tcp://10.0.0.7:4841"


# --- error / rejection paths ----------------------------------------------

@patch("netscanner.socket.socket")
@patch("plugins.opcua.select.select")
@patch("netscanner.select.select")
def test_scan_host_ua_error_is_a_positive_identification(mock_ns_select, mock_ua_select,
                                                         mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    sock.getsockname.return_value = ("10.0.0.250", 12345)
    mock_ns_select.side_effect = [([], [], [])]
    mock_ua_select.side_effect = _ready(sock)
    sock.recv.return_value = _make_err()

    results = scan_host("10.0.0.1", ScanConfig(port=4840), OpcuaPlugin())

    r = results[0]
    assert r.status == STATUS_UA_ERROR
    assert r.extra["status_code"] == "0x80830000"
    assert r.extra["status_name"] == "Bad_TcpEndpointUrlInvalid"
    assert "Bad_TcpEndpointUrlInvalid" in r.detail


@patch("netscanner.socket.socket")
@patch("plugins.opcua.select.select")
@patch("netscanner.select.select")
def test_scan_host_no_opcua_on_http_response(mock_ns_select, mock_ua_select,
                                             mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    sock.getsockname.return_value = ("10.0.0.250", 12345)
    mock_ns_select.side_effect = [([], [], [])]
    mock_ua_select.side_effect = _ready(sock)
    sock.recv.return_value = b"HTTP/1.1 400 Bad Request\r\n\r\n"

    results = scan_host("10.0.0.1", ScanConfig(port=4840), OpcuaPlugin())
    assert results[0].status == STATUS_NO_OPCUA


@patch("netscanner.socket.socket")
@patch("plugins.opcua.select.select")
@patch("netscanner.select.select")
def test_scan_host_zero_window(mock_ns_select, mock_ua_select, mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    sock.getsockname.return_value = ("10.0.0.250", 12345)
    mock_ns_select.side_effect = [([], [], [])]
    mock_ua_select.side_effect = [([], [], [])]      # never write-ready
    results = scan_host("10.0.0.1", ScanConfig(port=4840), OpcuaPlugin())
    assert results[0].status == STATUS_ZERO_WINDOW
    assert sock.sendall.called is False


@patch("netscanner.socket.socket")
@patch("plugins.opcua.select.select")
@patch("netscanner.select.select")
def test_scan_host_timeout_response(mock_ns_select, mock_ua_select, mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    sock.getsockname.return_value = ("10.0.0.250", 12345)
    mock_ns_select.side_effect = [([], [], [])]
    mock_ua_select.side_effect = [([], [sock], []), ([], [], [])]
    results = scan_host("10.0.0.1", ScanConfig(port=4840), OpcuaPlugin())
    assert results[0].status == STATUS_TIMEOUT_RESPONSE


@patch("netscanner.socket.socket")
@patch("plugins.opcua.select.select")
@patch("netscanner.select.select")
def test_scan_host_connection_reset(mock_ns_select, mock_ua_select, mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    sock.getsockname.return_value = ("10.0.0.250", 12345)
    mock_ns_select.side_effect = [([], [], [])]
    mock_ua_select.side_effect = _ready(sock)
    sock.recv.side_effect = OSError(errno_mod.ECONNRESET, "Connection reset by peer")
    results = scan_host("10.0.0.1", ScanConfig(port=4840), OpcuaPlugin())
    assert results[0].status == STATUS_NO_OPCUA


@patch("netscanner.socket.socket")
@patch("plugins.opcua.select.select")
@patch("netscanner.select.select")
def test_scan_host_server_closes_without_replying(mock_ns_select, mock_ua_select,
                                                  mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    sock.getsockname.return_value = ("10.0.0.250", 12345)
    mock_ns_select.side_effect = [([], [], [])]
    mock_ua_select.side_effect = _ready(sock)
    sock.recv.return_value = b""             # FIN after our Hello
    results = scan_host("10.0.0.1", ScanConfig(port=4840), OpcuaPlugin())
    assert results[0].status == STATUS_NO_OPCUA


# --- framework-level statuses still reachable ------------------------------

@patch("netscanner.socket.socket")
def test_scan_host_refused(mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    sock.connect.side_effect = ConnectionRefusedError()
    results = scan_host("10.0.0.1", ScanConfig(port=4840), OpcuaPlugin())
    assert results[0].status == STATUS_REFUSED


@patch("netscanner.socket.socket")
def test_scan_host_timeout_connect(mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    sock.connect.side_effect = socket.timeout()
    results = scan_host("10.0.0.1", ScanConfig(port=4840), OpcuaPlugin())
    assert results[0].status == STATUS_TIMEOUT_CONNECT


@patch("netscanner.socket.socket")
@patch("netscanner.select.select")
def test_scan_host_closed_immediately(mock_ns_select, mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    mock_ns_select.return_value = ([sock], [], [])
    sock.recv.return_value = b""
    results = scan_host("10.0.0.1", ScanConfig(port=4840), OpcuaPlugin())
    assert results[0].status == STATUS_CLOSED_IMMEDIATELY


# --- pcap integration ------------------------------------------------------

@patch("netscanner.socket.socket")
@patch("plugins.opcua.select.select")
@patch("netscanner.select.select")
def test_pcap_open_writes_handshake_hello_and_fin(mock_ns_select, mock_ua_select,
                                                  mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    sock.getsockname.return_value = ("10.0.0.250", 12345)
    mock_ns_select.side_effect = [([], [], [])]
    mock_ua_select.side_effect = _ready(sock)
    sock.recv.side_effect = [_make_ack()]

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        path = f.name
    try:
        w = PcapWriter(path)
        scan_host("10.0.0.1", ScanConfig(port=4840), OpcuaPlugin(), pcap_writers=[w])
        w.close()
        with open(path, "rb") as fh:
            records = _parse_pcap_records(fh.read())
        flags = [_pkt_tcp_flags(p) for p in records]
        assert flags[0] == TCP_SYN
        assert flags[1] == TCP_SYN_ACK
        assert flags[2] == TCP_ACK
        assert flags[-1] == TCP_FIN_ACK
        payloads = [_pkt_payload(p) for p in records
                    if _pkt_tcp_flags(p) == TCP_PSH_ACK]
        assert payloads[0][:4] == b"HELF"       # our Hello, on the wire
        assert payloads[1][:4] == b"ACKF"       # the server's Acknowledge
    finally:
        os.unlink(path)


@patch("netscanner.socket.socket")
@patch("plugins.opcua.select.select")
@patch("netscanner.select.select")
def test_pcap_zero_window_writes_rst_and_no_fin(mock_ns_select, mock_ua_select,
                                                mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    sock.getsockname.return_value = ("10.0.0.250", 12345)
    mock_ns_select.side_effect = [([], [], [])]
    mock_ua_select.side_effect = [([], [], [])]

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        path = f.name
    try:
        w = PcapWriter(path)
        scan_host("10.0.0.1", ScanConfig(port=4840), OpcuaPlugin(), pcap_writers=[w])
        w.close()
        with open(path, "rb") as fh:
            records = _parse_pcap_records(fh.read())
        flags = [_pkt_tcp_flags(p) for p in records]
        assert TCP_RST in flags
        assert TCP_FIN_ACK not in flags
    finally:
        os.unlink(path)


@patch("netscanner.socket.socket")
@patch("plugins.opcua.select.select")
@patch("netscanner.select.select")
def test_pcap_sequence_numbers_advance_by_payload_length(mock_ns_select, mock_ua_select,
                                                         mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    sock.getsockname.return_value = ("10.0.0.250", 12345)
    mock_ns_select.side_effect = [([], [], [])]
    mock_ua_select.side_effect = _ready(sock)
    sock.recv.side_effect = [_make_ack()]

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        path = f.name
    try:
        w = PcapWriter(path)
        scan_host("10.0.0.1", ScanConfig(port=4840), OpcuaPlugin(), pcap_writers=[w])
        w.close()
        with open(path, "rb") as fh:
            records = _parse_pcap_records(fh.read())
        hello = next(p for p in records
                     if _pkt_tcp_flags(p) == TCP_PSH_ACK
                     and _pkt_payload(p)[:3] == b"HEL")
        fin = records[-1]
        hello_seq = struct.unpack(">I", hello[24:28])[0]
        fin_seq = struct.unpack(">I", fin[24:28])[0]
        assert hello_seq == 1
        assert fin_seq == 1 + len(_pkt_payload(hello))
    finally:
        os.unlink(path)


# --- output integration ----------------------------------------------------

def test_csv_contains_opcua_columns():
    from netscanner import ScanResult
    results = [ScanResult(ip="10.0.0.1", status=STATUS_OPEN,
                          extra={"protocol_version": 0, "receive_buffer": 65536})]
    buf = io.StringIO()
    write_csv(results, buf)
    header = buf.getvalue().splitlines()[0]
    assert "protocol_version" in header and "receive_buffer" in header


def test_result_line_renders_negotiated_limits():
    from netscanner import ScanResult
    line = format_result_line(
        ScanResult(ip="10.0.0.1", status=STATUS_OPEN, latency_ms=14.0,
                   extra={"protocol_version": 0, "receive_buffer": 65536}),
        color=False)
    assert "protocol_version=0" in line and "receive_buffer=65536" in line
