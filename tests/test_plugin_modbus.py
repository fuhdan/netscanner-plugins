"""All 47 original modbus_scanner tests, migrated to plugin architecture."""
import errno as errno_mod
import io
import os
import socket
import struct
import tempfile
import threading

import pytest
from unittest.mock import MagicMock, patch

from netscanner import (
    ScanResult, ScanConfig, PcapWriter,
    TCP_SYN, TCP_ACK, TCP_SYN_ACK, TCP_PSH_ACK, TCP_FIN_ACK, TCP_RST,
    _ip_checksum, expand_targets,
    STATUS_OPEN, STATUS_REFUSED, STATUS_TIMEOUT_CONNECT,
    STATUS_CLOSED_IMMEDIATELY, STATUS_ZERO_WINDOW, STATUS_TIMEOUT_RESPONSE,
    STATUS_NO_PROTOCOL,
    scan_host, run_scan, format_result_line, format_summary, write_csv,
)
from plugins.modbus import (
    ModbusPlugin, STATUS_NO_MODBUS, STATUS_EXCEPTION,
    build_modbus_request, parse_modbus_response, _probe,
)
import plugins.modbus as _modbus_mod


@pytest.fixture(autouse=True)
def reset_tid():
    if hasattr(_modbus_mod._thread_local, "tid"):
        del _modbus_mod._thread_local.tid


def _make_fc3_response(tid=1, uid=0, value=0x1234):
    pdu = b"\x03\x02" + struct.pack(">H", value)
    mbap = struct.pack(">HHHB", tid, 0, len(pdu) + 1, uid)
    return mbap + pdu


def _make_exception_response(tid=1, uid=0, fc=0x83, exc_code=2):
    pdu = bytes([fc, exc_code])
    mbap = struct.pack(">HHHB", tid, 0, len(pdu) + 1, uid)
    return mbap + pdu


def _make_fc1_response(tid=1, uid=0):
    pdu = b"\x01\x01\x01"
    mbap = struct.pack(">HHHB", tid, 0, len(pdu) + 1, uid)
    return mbap + pdu


def _parse_pcap_records(data: bytes):
    records = []
    pos = 24
    while pos + 16 <= len(data):
        ts_sec, ts_usec, incl_len, _ = struct.unpack("<IIII", data[pos:pos + 16])
        pkt = data[pos + 16: pos + 16 + incl_len]
        records.append((ts_sec + ts_usec / 1_000_000, pkt))
        pos += 16 + incl_len
    return records


def _pkt_tcp_flags(pkt: bytes) -> int:
    return pkt[33]


def _pkt_payload(pkt: bytes) -> bytes:
    return pkt[40:]


# ---------------------------------------------------------------------------
# expand_targets
# ---------------------------------------------------------------------------

def test_expand_single_ip():
    assert expand_targets(["10.0.0.1"], file_path=None) == ["10.0.0.1"]


def test_expand_cidr():
    result = expand_targets(["10.0.0.0/30"], file_path=None)
    assert "10.0.0.1" in result and "10.0.0.2" in result
    assert "10.0.0.0" not in result and len(result) == 2


def test_expand_mixed():
    result = expand_targets(["10.0.0.1", "10.0.0.0/30"], file_path=None)
    assert "10.0.0.1" in result and "10.0.0.2" in result


def test_deduplication():
    assert expand_targets(["10.0.0.1", "10.0.0.1"], file_path=None).count("10.0.0.1") == 1


def test_expand_from_file():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("10.0.0.5\n10.0.0.0/30\n# comment\n\n10.0.0.10\n")
        fname = f.name
    try:
        result = expand_targets([], file_path=fname)
        assert "10.0.0.5" in result and "10.0.0.1" in result and "10.0.0.10" in result
    finally:
        os.unlink(fname)


def test_file_and_args_merged():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("10.0.0.20\n")
        fname = f.name
    try:
        result = expand_targets(["10.0.0.1"], file_path=fname)
        assert "10.0.0.1" in result and "10.0.0.20" in result
    finally:
        os.unlink(fname)


def test_invalid_target_skipped(capsys):
    result = expand_targets(["not-an-ip"], file_path=None)
    assert result == []
    assert "not-an-ip" in capsys.readouterr().err


def test_nonexistent_file_warns_and_returns_args(capsys):
    result = expand_targets(["10.0.0.1"], file_path="/tmp/does_not_exist_xyz.txt")
    assert result == ["10.0.0.1"]
    assert "does_not_exist_xyz.txt" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# build_modbus_request / parse_modbus_response
# ---------------------------------------------------------------------------

def test_build_fc3_request():
    frame = build_modbus_request(tid=1, unit_id=0, fc=3, addr=0, qty=1)
    assert len(frame) == 12
    assert frame[0:2] == b"\x00\x01"
    assert frame[2:4] == b"\x00\x00"
    assert frame[4:6] == b"\x00\x06"
    assert frame[6:7] == b"\x00"
    assert frame[7:8] == b"\x03"
    assert frame[8:10] == b"\x00\x00"
    assert frame[10:12] == b"\x00\x01"


def test_build_fc1_request():
    frame = build_modbus_request(tid=2, unit_id=1, fc=1, addr=0, qty=1)
    assert frame[7:8] == b"\x01"
    assert frame[6:7] == b"\x01"
    assert frame[8:12] == b"\x00\x00\x00\x01"


def test_parse_valid_fc3_response():
    frame = struct.pack(">HHHB", 1, 0, 5, 0) + b"\x03\x02\x12\x34"
    tid, uid, fc, payload, exc = parse_modbus_response(frame, expected_tid=1)
    assert tid == 1 and uid == 0 and fc == 3
    assert payload == b"\x02\x12\x34" and exc is None


def test_parse_modbus_exception_response():
    frame = struct.pack(">HHHB", 1, 0, 3, 0) + b"\x83\x02"
    tid, uid, fc, payload, exc = parse_modbus_response(frame, expected_tid=1)
    assert fc == 0x83 and exc == 2 and payload == b"\x83\x02"


def test_parse_wrong_transaction_id_returns_none():
    frame = struct.pack(">HHHB", 99, 0, 5, 0) + b"\x03\x02\x12\x34"
    assert parse_modbus_response(frame, expected_tid=1) is None


def test_parse_too_short_returns_none():
    assert parse_modbus_response(b"\x00\x01\x00\x00", expected_tid=1) is None


def test_parse_truncated_frame_returns_none():
    frame = struct.pack(">HHHB", 1, 0, 10, 0) + b"\x03\x02\x12"
    assert parse_modbus_response(frame, expected_tid=1) is None


def test_parse_malformed_exception_returns_none():
    frame = struct.pack(">HHHB", 1, 0, 2, 0) + b"\x83"
    assert parse_modbus_response(frame, expected_tid=1) is None


# ---------------------------------------------------------------------------
# ScanResult / ScanConfig
# ---------------------------------------------------------------------------

def test_scan_result_defaults():
    r = ScanResult(ip="10.0.0.1", status="OPEN")
    assert r.latency_ms == 0 and r.detail == "" and r.extra == {}


def test_scan_config_defaults():
    cfg = ScanConfig()
    assert cfg.port == 502 and cfg.threads == 20
    assert cfg.connect_timeout == 2.0 and cfg.response_timeout == 3.0


# ---------------------------------------------------------------------------
# _probe
# ---------------------------------------------------------------------------

@patch("plugins.modbus.select.select")
def test_probe_pcap_log_events(_mock_select):
    sock = MagicMock()
    _mock_select.side_effect = [([], [sock], []), ([sock], [], [])]
    resp = _make_fc3_response(tid=1, uid=0)
    sock.recv.return_value = resp
    events = []
    _probe(sock, unit_id=0, fc=3, response_timeout=3.0,
           pcap_log=lambda d, ts, r: events.append((d, r)))
    assert len(events) == 2
    assert events[0][0] == 'send' and events[1][0] == 'recv'
    assert events[1][1] == resp


@patch("plugins.modbus.select.select")
def test_probe_pcap_log_send_is_valid_modbus(_mock_select):
    sock = MagicMock()
    _mock_select.side_effect = [([], [sock], []), ([sock], [], [])]
    sock.recv.return_value = _make_fc3_response(tid=1, uid=0)
    sent = []
    _probe(sock, unit_id=0, fc=3, response_timeout=3.0,
           pcap_log=lambda d, ts, r: sent.append(r) if d == 'send' else None)
    assert len(sent) == 1
    frame = sent[0]
    assert len(frame) == 12
    tid, proto, length, unit = struct.unpack(">HHHB", frame[:7])
    assert tid == 1 and proto == 0 and length == 6 and unit == 0
    assert frame[7] == 3


# ---------------------------------------------------------------------------
# scan_host with ModbusPlugin — dual select patch required
# Decorator order: outermost @patch → last param; innermost → first param
# @patch("netscanner.socket.socket")           → mock_socket_cls  (last)
# @patch("plugins.modbus.select.select")       → mock_mb_select   (middle)
# @patch("netscanner.select.select")           → mock_ns_select   (first)
# ---------------------------------------------------------------------------

@patch("netscanner.socket.socket")
@patch("plugins.modbus.select.select")
@patch("netscanner.select.select")
def test_scan_host_open_fc3(mock_ns_select, mock_mb_select, mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    sock.getsockname.return_value = ('10.0.0.250', 12345)
    mock_ns_select.side_effect = [([], [], [])]
    mock_mb_select.side_effect = [
        ([], [sock], []), ([sock], [], []),
        ([], [sock], []), ([sock], [], []),
    ]
    sock.recv.side_effect = [
        _make_fc3_response(tid=1, uid=0),
        _make_fc3_response(tid=2, uid=1),
    ]
    results = scan_host("10.0.0.1", ScanConfig(port=502), ModbusPlugin())
    assert any(r.status == STATUS_OPEN and r.extra.get("unit_id") == 0 for r in results)


@patch("netscanner.socket.socket")
def test_scan_host_refused(mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    sock.connect.side_effect = ConnectionRefusedError()
    results = scan_host("10.0.0.1", ScanConfig(), ModbusPlugin())
    assert len(results) == 1 and results[0].status == STATUS_REFUSED


@patch("netscanner.socket.socket")
def test_scan_host_timeout_connect(mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    sock.connect.side_effect = socket.timeout()
    results = scan_host("10.0.0.1", ScanConfig(), ModbusPlugin())
    assert results[0].status == STATUS_TIMEOUT_CONNECT


@patch("netscanner.socket.socket")
@patch("netscanner.select.select")
def test_scan_host_closed_immediately_a14(mock_ns_select, mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    mock_ns_select.return_value = ([sock], [], [])
    sock.recv.return_value = b""
    results = scan_host("10.0.0.1", ScanConfig(), ModbusPlugin())
    assert results[0].status == STATUS_CLOSED_IMMEDIATELY


@patch("netscanner.socket.socket")
@patch("plugins.modbus.select.select")
@patch("netscanner.select.select")
def test_scan_host_zero_window_a15(mock_ns_select, mock_mb_select, mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    sock.getsockname.return_value = ('10.0.0.250', 12345)
    mock_ns_select.side_effect = [([], [], [])]
    mock_mb_select.side_effect = [([], [], [])]   # write-ready empty → ZeroWindow
    results = scan_host("10.0.0.1", ScanConfig(), ModbusPlugin())
    assert results[0].status == STATUS_ZERO_WINDOW


@patch("netscanner.socket.socket")
@patch("plugins.modbus.select.select")
@patch("netscanner.select.select")
def test_scan_host_timeout_response(mock_ns_select, mock_mb_select, mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    sock.getsockname.return_value = ('10.0.0.250', 12345)
    mock_ns_select.side_effect = [([], [], [])]
    mock_mb_select.side_effect = [([], [sock], []), ([], [], [])]  # write ok, read timeout
    results = scan_host("10.0.0.1", ScanConfig(), ModbusPlugin())
    assert results[0].status == STATUS_TIMEOUT_RESPONSE


@patch("netscanner.socket.socket")
@patch("plugins.modbus.select.select")
@patch("netscanner.select.select")
def test_scan_host_exception_then_fc1_success(mock_ns_select, mock_mb_select,
                                               mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    sock.getsockname.return_value = ('10.0.0.250', 12345)
    mock_ns_select.side_effect = [([], [], [])]
    mock_mb_select.side_effect = [
        ([], [sock], []), ([sock], [], []),   # FC3
        ([], [sock], []), ([sock], [], []),   # FC1 fallback
    ]
    sock.recv.side_effect = [
        _make_exception_response(tid=1, uid=0),
        _make_fc1_response(tid=2, uid=0),
    ]
    results = scan_host("10.0.0.1", ScanConfig(), ModbusPlugin())
    assert any(r.status == STATUS_OPEN and r.extra.get("fc") == 1 for r in results)


@patch("netscanner.socket.socket")
@patch("plugins.modbus.select.select")
@patch("netscanner.select.select")
def test_scan_host_no_modbus(mock_ns_select, mock_mb_select, mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    sock.getsockname.return_value = ('10.0.0.250', 12345)
    mock_ns_select.side_effect = [([], [], [])]
    mock_mb_select.side_effect = [([], [sock], []), ([sock], [], [])]
    sock.recv.return_value = b"HTTP/1.1 200 OK\r\n"
    results = scan_host("10.0.0.1", ScanConfig(), ModbusPlugin())
    assert results[0].status == STATUS_NO_MODBUS


@patch("netscanner.socket.socket")
@patch("plugins.modbus.select.select")
@patch("netscanner.select.select")
def test_scan_host_open_both_units(mock_ns_select, mock_mb_select, mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    sock.getsockname.return_value = ('10.0.0.250', 12345)
    mock_ns_select.side_effect = [([], [], [])]
    mock_mb_select.side_effect = [
        ([], [sock], []), ([sock], [], []),
        ([], [sock], []), ([sock], [], []),
    ]
    sock.recv.side_effect = [
        _make_fc3_response(tid=1, uid=0),
        _make_fc3_response(tid=2, uid=1),
    ]
    results = scan_host("10.0.0.1", ScanConfig(), ModbusPlugin())
    assert len(results) == 2
    assert results[0].status == STATUS_OPEN and results[0].extra.get("unit_id") == 0
    assert results[1].status == STATUS_OPEN and results[1].extra.get("unit_id") == 1


@patch("netscanner.socket.socket")
@patch("plugins.modbus.select.select")
@patch("netscanner.select.select")
def test_scan_host_unit0_open_unit1_timeout(mock_ns_select, mock_mb_select,
                                             mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    sock.getsockname.return_value = ('10.0.0.250', 12345)
    mock_ns_select.side_effect = [([], [], [])]
    mock_mb_select.side_effect = [
        ([], [sock], []), ([sock], [], []),   # unit 0 ok
        ([], [sock], []), ([], [], []),        # unit 1 write ok, read timeout
    ]
    sock.recv.side_effect = [_make_fc3_response(tid=1, uid=0)]
    results = scan_host("10.0.0.1", ScanConfig(), ModbusPlugin())
    assert len(results) == 2
    assert results[0].status == STATUS_OPEN and results[0].extra.get("unit_id") == 0
    assert results[1].status == STATUS_TIMEOUT_RESPONSE and results[1].extra.get("unit_id") == 1


# ---------------------------------------------------------------------------
# scan_host + PcapWriter integration
# ---------------------------------------------------------------------------

@patch("netscanner.socket.socket")
@patch("plugins.modbus.select.select")
@patch("netscanner.select.select")
def test_scan_host_pcap_open(mock_ns_select, mock_mb_select, mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    sock.getsockname.return_value = ('10.0.0.250', 12345)
    mock_ns_select.side_effect = [([], [], [])]
    mock_mb_select.side_effect = [
        ([], [sock], []), ([sock], [], []),
        ([], [sock], []), ([sock], [], []),
    ]
    sock.recv.side_effect = [
        _make_fc3_response(tid=1, uid=0),
        _make_fc3_response(tid=2, uid=1),
    ]
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
        path = f.name
    try:
        w = PcapWriter(path)
        scan_host("10.0.0.1", ScanConfig(), ModbusPlugin(), pcap_writers=[w])
        w.close()
        with open(path, 'rb') as fh:
            data = fh.read()
        records = _parse_pcap_records(data)
        flags_seq = [_pkt_tcp_flags(pkt) for _, pkt in records]
        assert flags_seq[0] == TCP_SYN
        assert flags_seq[1] == TCP_SYN_ACK
        assert flags_seq[2] == TCP_ACK
        assert TCP_PSH_ACK in flags_seq
        assert flags_seq[-1] == TCP_FIN_ACK
        psh_payloads = [_pkt_payload(pkt) for _, pkt in records
                        if _pkt_tcp_flags(pkt) == TCP_PSH_ACK]
        assert any(len(p) == 12 for p in psh_payloads)
    finally:
        os.unlink(path)


@patch("netscanner.socket.socket")
@patch("netscanner.select.select")
def test_scan_host_pcap_closed_immediately(mock_ns_select, mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    sock.getsockname.return_value = ('10.0.0.250', 12345)
    mock_ns_select.return_value = ([sock], [], [])
    sock.recv.return_value = b""
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
        path = f.name
    try:
        w = PcapWriter(path)
        scan_host("10.0.0.1", ScanConfig(), ModbusPlugin(), pcap_writers=[w])
        w.close()
        with open(path, 'rb') as fh:
            data = fh.read()
        records = _parse_pcap_records(data)
        flags_seq = [_pkt_tcp_flags(pkt) for _, pkt in records]
        assert flags_seq[0] == TCP_SYN
        assert flags_seq[1] == TCP_SYN_ACK
        assert flags_seq[2] == TCP_ACK
        assert flags_seq[3] == TCP_FIN_ACK
    finally:
        os.unlink(path)


@patch("netscanner.socket.socket")
@patch("plugins.modbus.select.select")
@patch("netscanner.select.select")
def test_scan_host_pcap_no_modbus_econnreset(mock_ns_select, mock_mb_select,
                                              mock_socket_cls):
    sock = MagicMock()
    mock_socket_cls.return_value = sock
    sock.getsockname.return_value = ('10.0.0.250', 12345)
    mock_ns_select.side_effect = [([], [], [])]
    mock_mb_select.side_effect = [([], [sock], []), ([sock], [], [])]
    sock.recv.side_effect = OSError(errno_mod.ECONNRESET, "Connection reset by peer")
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
        path = f.name
    try:
        w = PcapWriter(path)
        scan_host("10.0.0.1", ScanConfig(), ModbusPlugin(), pcap_writers=[w])
        w.close()
        with open(path, 'rb') as fh:
            data = fh.read()
        records = _parse_pcap_records(data)
        flags_seq = [_pkt_tcp_flags(pkt) for _, pkt in records]
        assert TCP_PSH_ACK in flags_seq
        assert TCP_RST in flags_seq
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# run_scan
# ---------------------------------------------------------------------------

def test_run_scan_returns_all_results():
    def fake_scan(ip, cfg, plugin, pcap_writers=None):
        return [ScanResult(ip=ip, status=STATUS_REFUSED)]

    with patch("netscanner.scan_host", side_effect=fake_scan):
        results = run_scan(["10.0.0.1", "10.0.0.2"], ScanConfig(threads=2),
                           ModbusPlugin())
    assert {r.ip for r in results} == {"10.0.0.1", "10.0.0.2"}


def test_run_scan_empty_targets():
    assert run_scan([], ScanConfig(), ModbusPlugin()) == []


def test_run_scan_flattens_multiple_results_per_host():
    def fake_scan(ip, cfg, plugin, pcap_writers=None):
        return [ScanResult(ip=ip, status=STATUS_OPEN, extra={"unit_id": 0}),
                ScanResult(ip=ip, status=STATUS_OPEN, extra={"unit_id": 1})]

    with patch("netscanner.scan_host", side_effect=fake_scan):
        results = run_scan(["10.0.0.1"], ScanConfig(threads=1), ModbusPlugin())
    assert len(results) == 2


def test_run_scan_exception_returns_no_protocol():
    with patch("netscanner.scan_host", side_effect=RuntimeError("boom")):
        results = run_scan(["10.0.0.9"], ScanConfig(threads=1), ModbusPlugin())
    assert results[0].status == STATUS_NO_PROTOCOL
    assert "boom" in results[0].detail


def test_pcap_dir_creates_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        def fake_scan(ip, cfg, plugin, pcap_writers=None):
            return [ScanResult(ip=ip, status=STATUS_REFUSED)]

        with patch("netscanner.scan_host", side_effect=fake_scan):
            run_scan(["10.0.0.1", "10.0.0.2"], ScanConfig(threads=1),
                     ModbusPlugin(), pcap_dir=tmpdir)

        files = os.listdir(tmpdir)
        combined = [f for f in files if f.startswith("scan_") and f.endswith(".pcap")]
        assert len(combined) == 1
        assert "10.0.0.1.pcap" in files and "10.0.0.2.pcap" in files
        with open(os.path.join(tmpdir, combined[0]), 'rb') as fh:
            magic = struct.unpack("<I", fh.read(4))[0]
        assert magic == 0xa1b2c3d4


def test_pcap_dir_unwritable_warns_and_scan_continues(capsys):
    bad_dir = "/nonexistent_root_xyz/cannot_create"

    def fake_scan(ip, cfg, plugin, pcap_writers=None):
        return [ScanResult(ip=ip, status=STATUS_REFUSED)]

    with patch("netscanner.scan_host", side_effect=fake_scan):
        results = run_scan(["10.0.0.1"], ScanConfig(threads=1), ModbusPlugin(),
                           pcap_dir=bad_dir)
    assert results[0].status == STATUS_REFUSED
    assert bad_dir in capsys.readouterr().err


# ---------------------------------------------------------------------------
# PcapWriter (same tests — verifying import from netscanner)
# ---------------------------------------------------------------------------

def test_pcap_writer_global_header():
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
        path = f.name
    try:
        w = PcapWriter(path)
        w.close()
        with open(path, 'rb') as f:
            data = f.read()
        assert len(data) == 24
        magic, vmaj, vmin, tz, acc, snaplen, network = struct.unpack("<IHHiIII", data)
        assert tz == 0 and acc == 0
        assert magic == 0xa1b2c3d4 and vmaj == 2 and vmin == 4
        assert snaplen == 65535 and network == 101
    finally:
        os.unlink(path)


def test_pcap_writer_single_packet():
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
        path = f.name
    try:
        payload = b'\x00\x01\x00\x00\x00\x06\x00\x03\x00\x00\x00\x01'
        w = PcapWriter(path)
        w.write_packet(1000.5, '10.0.0.1', '10.0.0.2', 12345, 502,
                       TCP_PSH_ACK, 1, 1, payload)
        w.close()
        with open(path, 'rb') as f:
            data = f.read()
        assert len(data) == 24 + 16 + 20 + 20 + len(payload)
        records = _parse_pcap_records(data)
        assert len(records) == 1
        ts, pkt = records[0]
        assert abs(ts - 1000.5) < 0.001
        sport, dport = struct.unpack(">HH", pkt[20:24])
        assert sport == 12345 and dport == 502
        assert _pkt_tcp_flags(pkt) == TCP_PSH_ACK
        assert _pkt_payload(pkt) == payload
    finally:
        os.unlink(path)


def test_pcap_writer_checksum():
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
        path = f.name
    try:
        payload = b'\x01\x02\x03\x04'
        w = PcapWriter(path)
        w.write_packet(0.0, '192.168.1.1', '192.168.1.2', 9999, 502,
                       TCP_PSH_ACK, 100, 200, payload)
        w.close()
        with open(path, 'rb') as f:
            raw = f.read()
        pkt = raw[40:]
        ip_hdr = pkt[:20]
        stored_ip = struct.unpack(">H", ip_hdr[10:12])[0]
        zeroed_ip = ip_hdr[:10] + b'\x00\x00' + ip_hdr[12:]
        assert _ip_checksum(zeroed_ip) == stored_ip
        tcp_hdr = pkt[20:40]
        stored_tcp = struct.unpack(">H", tcp_hdr[16:18])[0]
        pseudo = pkt[12:16] + pkt[16:20] + struct.pack(">BBH", 0, 6, 20 + len(payload))
        zeroed_tcp = tcp_hdr[:16] + b'\x00\x00' + tcp_hdr[18:]
        assert _ip_checksum(pseudo + zeroed_tcp + payload) == stored_tcp
    finally:
        os.unlink(path)


def test_pcap_writer_thread_safety():
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
        path = f.name
    try:
        w = PcapWriter(path)
        threads = [
            threading.Thread(target=lambda wtr=w: [
                wtr.write_packet(1.0, '1.2.3.4', '5.6.7.8', 1234, 502, TCP_ACK, 0, 0)
                for _ in range(10)
            ])
            for _ in range(50)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        w.close()
        with open(path, 'rb') as f:
            data = f.read()
        assert len(data) == 24 + 500 * (16 + 40)
        assert len(_parse_pcap_records(data)) == 500
    finally:
        os.unlink(path)


# ---------------------------------------------------------------------------
# format_result_line — Modbus extra fields
# ---------------------------------------------------------------------------

def test_format_result_line_open():
    r = ScanResult(ip="10.0.0.1", status=STATUS_OPEN, latency_ms=42.0,
                   extra={"unit_id": 0, "fc": 3, "register_value": "0x1234"})
    line = format_result_line(r, color=False)
    assert "10.0.0.1" in line and "OPEN" in line
    assert "unit_id=0" in line and "register_value=0x1234" in line
    assert "42" in line


def test_format_result_line_closed_immediately():
    r = ScanResult(ip="10.0.0.2", status=STATUS_CLOSED_IMMEDIATELY,
                   latency_ms=1.0, detail="server FIN immediately after handshake")
    line = format_result_line(r, color=False)
    assert "CLOSED_IMMEDIATELY" in line and "server FIN" in line


# ---------------------------------------------------------------------------
# format_summary — generic (no FC3/FC1 lines)
# ---------------------------------------------------------------------------

def test_format_summary_counts():
    results = [
        ScanResult(ip="10.0.0.1", status=STATUS_OPEN, extra={"fc": 3}),
        ScanResult(ip="10.0.0.2", status=STATUS_OPEN, extra={"fc": 1}),
        ScanResult(ip="10.0.0.3", status=STATUS_REFUSED),
        ScanResult(ip="10.0.0.4", status=STATUS_CLOSED_IMMEDIATELY),
    ]
    summary = format_summary(results, duration=5.0, cfg=ScanConfig())
    assert "OPEN" in summary and "REFUSED" in summary
    assert "CLOSED_IMMEDIATELY" in summary
    assert "FC3" not in summary and "FC1" not in summary


# ---------------------------------------------------------------------------
# write_csv — generic extra columns
# ---------------------------------------------------------------------------

def test_write_csv_headers_and_rows():
    results = [
        ScanResult(ip="10.0.0.1", status=STATUS_OPEN, latency_ms=42.0,
                   extra={"unit_id": 0, "fc": 3, "register_value": "0x1234"}),
        ScanResult(ip="10.0.0.2", status=STATUS_CLOSED_IMMEDIATELY,
                   latency_ms=1.0, detail="server FIN immediately after handshake"),
    ]
    buf = io.StringIO()
    write_csv(results, buf)
    buf.seek(0)
    content = buf.read()
    assert "ip,status,latency_ms,detail" in content
    assert "unit_id" in content and "register_value" in content
    assert "0x1234" in content and "CLOSED_IMMEDIATELY" in content
