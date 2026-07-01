"""
CyberKit — Banner Grabber engine tests (no network, socket mocked)

Run: python tests/test_banner_grabber.py
"""

import io
import sys
import os
import ssl
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from app.modules.banner_grabber import grab, BannerResult, BANNER_MAX


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_sock(data: bytes, probe_check=True):
    """Return a mock socket that yields data in one recv() call."""
    sock = MagicMock()
    recv_calls = [0]

    def recv(n):
        recv_calls[0] += 1
        if recv_calls[0] == 1:
            return data
        return b""  # EOF

    sock.recv.side_effect = recv
    return sock


# ── clean banner capture ──────────────────────────────────────────────────────

def test_clean_banner():
    banner_data = b"SSH-2.0-OpenSSH_8.9p1\r\n"
    sock = _make_sock(banner_data)

    with patch("socket.create_connection", return_value=sock):
        result = grab("127.0.0.1", 22, probe="\r\n", use_tls=False)

    assert result.error is None
    assert "SSH-2.0-OpenSSH" in result.banner
    assert result.tls is False
    print(f"  clean banner: {result.banner!r}: OK")


def test_probe_sent_before_read():
    """Verify sendall is called with the probe before any recv."""
    sock = _make_sock(b"banner data\r\n")
    call_order = []
    orig_sendall = sock.sendall.side_effect

    def track_sendall(data):
        call_order.append("sendall")
    def track_recv(n):
        call_order.append("recv")
        if len([x for x in call_order if x == "recv"]) == 1:
            return b"banner data\r\n"
        return b""

    sock.sendall.side_effect = track_sendall
    sock.recv.side_effect = track_recv

    with patch("socket.create_connection", return_value=sock):
        grab("127.0.0.1", 80, probe="\r\n")

    assert call_order[0] == "sendall", "Probe must be sent before recv"
    print("  probe sent before recv: OK")


def test_empty_probe_skips_sendall():
    sock = _make_sock(b"FTP service ready\r\n")

    with patch("socket.create_connection", return_value=sock):
        result = grab("127.0.0.1", 21, probe="")

    sock.sendall.assert_not_called()
    assert result.error is None
    print("  empty probe → sendall not called: OK")


# ── TLS ───────────────────────────────────────────────────────────────────────

def test_tls_wraps_socket():
    sock = _make_sock(b"TLS banner\r\n")
    tls_sock = _make_sock(b"TLS banner\r\n")

    mock_ctx = MagicMock()
    mock_ctx.wrap_socket.return_value = tls_sock

    with patch("socket.create_connection", return_value=sock):
        with patch("ssl.create_default_context", return_value=mock_ctx):
            result = grab("example.com", 443, use_tls=True)

    mock_ctx.wrap_socket.assert_called_once()
    assert result.tls is True
    print("  TLS: wrap_socket called, tls=True: OK")


# ── connection error ──────────────────────────────────────────────────────────

def test_connection_error_captured():
    with patch("socket.create_connection", side_effect=ConnectionRefusedError("refused")):
        result = grab("127.0.0.1", 9999)

    assert result.error is not None
    assert result.banner == ""
    print(f"  connection error → result.error={result.error!r}: OK")


def test_timeout_captured():
    import socket as _socket
    with patch("socket.create_connection", side_effect=_socket.timeout("timed out")):
        result = grab("1.2.3.4", 22, timeout=0.1)

    assert result.error is not None
    print(f"  timeout → result.error={result.error!r}: OK")


# ── banner truncation ─────────────────────────────────────────────────────────

def test_banner_truncated_at_max():
    long_banner = b"X" * (BANNER_MAX + 500)
    sock = MagicMock()
    recv_calls = [0]

    def recv(n):
        recv_calls[0] += 1
        if recv_calls[0] == 1:
            return long_banner[:n]
        if recv_calls[0] == 2:
            return long_banner[n : n * 2]
        return b""

    sock.recv.side_effect = recv

    with patch("socket.create_connection", return_value=sock):
        result = grab("127.0.0.1", 1234)

    assert len(result.banner) <= BANNER_MAX
    print(f"  banner truncated to {len(result.banner)} chars (<= {BANNER_MAX}): OK")


# ── null byte stripping ───────────────────────────────────────────────────────

def test_null_bytes_stripped():
    sock = _make_sock(b"hello\x00world\x00\r\n")
    with patch("socket.create_connection", return_value=sock):
        result = grab("127.0.0.1", 9999)
    assert "\x00" not in result.banner
    print("  null bytes stripped from banner: OK")


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_clean_banner,
        test_probe_sent_before_read,
        test_empty_probe_skips_sendall,
        test_tls_wraps_socket,
        test_connection_error_captured,
        test_timeout_captured,
        test_banner_truncated_at_max,
        test_null_bytes_stripped,
    ]
    passed = 0
    print(f"Running {len(tests)} Banner Grabber tests...\n")
    for t in tests:
        try:
            t()
            passed += 1
        except AssertionError as e:
            print(f"  FAIL {t.__name__}: {e}")
        except Exception as e:
            import traceback
            print(f"  ERROR {t.__name__}: {e}")
            traceback.print_exc()
    print(f"\n{passed}/{len(tests)} tests passed")
    sys.exit(0 if passed == len(tests) else 1)
