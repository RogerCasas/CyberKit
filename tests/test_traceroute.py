"""
CyberKit — Traceroute engine tests (no network, Scapy mocked)

Run: python tests/test_traceroute.py
"""

import io
import sys
import os
import threading
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from app.modules.traceroute import TraceHop, scan


# ── helpers ───────────────────────────────────────────────────────────────────

def _icmp_reply(src: str, icmp_type: int):
    """Build a minimal mock Scapy packet for ICMP."""
    pkt = MagicMock()
    pkt.src = src

    icmp_layer = MagicMock()
    icmp_layer.type = icmp_type

    def has(cls):
        # ICMP class object is passed; just return True always for these tests
        return True

    pkt.haslayer.side_effect = has
    pkt.__getitem__ = MagicMock(return_value=icmp_layer)
    return pkt


# ── TraceHop dataclass ────────────────────────────────────────────────────────

def test_tracehop_construction():
    h = TraceHop(hop=1, ip="1.2.3.4", hostname="router.local", rtt_ms=5.2, timed_out=False)
    assert h.hop == 1
    assert h.ip == "1.2.3.4"
    assert not h.timed_out
    print("  TraceHop construction: OK")


def test_tracehop_timed_out():
    h = TraceHop(hop=3, ip=None, hostname=None, rtt_ms=None, timed_out=True)
    assert h.timed_out
    assert h.ip is None
    print("  TraceHop timed_out: OK")


# ── scan — stop_event ─────────────────────────────────────────────────────────

def test_scan_stop_event_before_start():
    ev = threading.Event()
    ev.set()
    with patch("app.modules.traceroute.sr1", return_value=None):
        result = scan("1.2.3.4", stop_event=ev)
    assert result == [], "Pre-set stop_event should yield no hops"
    print("  scan stop_event pre-set → []: OK")


# ── scan — timeout (sr1 returns None) ────────────────────────────────────────

def test_scan_timeout_hop():
    calls = [0]

    def fake_sr1(probe, timeout, verbose):
        calls[0] += 1
        return None   # simulate timeout

    # Only 2 hops max so test is fast
    with patch("app.modules.traceroute.sr1", side_effect=fake_sr1):
        with patch("socket.gethostbyname", return_value="1.2.3.4"):
            result = scan("1.2.3.4", max_hops=2)

    assert len(result) == 2
    assert all(h.timed_out for h in result)
    assert all(h.ip is None for h in result)
    print(f"  scan timeout hops → {len(result)} * (timed out): OK")


# ── scan — on_hop callback ────────────────────────────────────────────────────

def test_scan_on_hop_callback():
    collected = []

    def fake_sr1(probe, timeout, verbose):
        return None  # all timeouts

    with patch("app.modules.traceroute.sr1", side_effect=fake_sr1):
        with patch("socket.gethostbyname", return_value="1.2.3.4"):
            scan("1.2.3.4", max_hops=3, on_hop=collected.append)

    assert len(collected) == 3
    assert all(isinstance(h, TraceHop) for h in collected)
    print(f"  on_hop callback received {len(collected)} hops: OK")


# ── scan — echo reply terminates trace ───────────────────────────────────────

def test_scan_terminates_on_echo_reply():
    """ICMP Echo Reply (type=0) should stop the trace early."""
    call_count = [0]

    def fake_sr1(probe, timeout, verbose):
        call_count[0] += 1
        if call_count[0] == 2:
            return _icmp_reply("5.5.5.5", icmp_type=0)  # Echo Reply
        return _icmp_reply("1.1.1.1", icmp_type=11)     # Time Exceeded

    with patch("app.modules.traceroute.sr1", side_effect=fake_sr1):
        with patch("socket.gethostbyaddr", side_effect=Exception("no rdns")):
            result = scan("5.5.5.5", max_hops=30)

    assert len(result) == 2, f"Should stop after echo reply at hop 2, got {len(result)}"
    assert result[-1].ip == "5.5.5.5"
    print(f"  scan terminates on echo reply at hop {len(result)}: OK")


# ── scan — hop sequence ───────────────────────────────────────────────────────

def test_scan_hop_sequence():
    """Hop indices must be 1, 2, 3, …"""
    def fake_sr1(probe, timeout, verbose):
        return None  # all timeouts

    with patch("app.modules.traceroute.sr1", side_effect=fake_sr1):
        with patch("socket.gethostbyname", return_value="192.0.2.1"):
            result = scan("example.com", max_hops=4)

    assert [h.hop for h in result] == [1, 2, 3, 4]
    print("  hop sequence [1,2,3,4]: OK")


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_tracehop_construction,
        test_tracehop_timed_out,
        test_scan_stop_event_before_start,
        test_scan_timeout_hop,
        test_scan_on_hop_callback,
        test_scan_terminates_on_echo_reply,
        test_scan_hop_sequence,
    ]
    passed = 0
    print(f"Running {len(tests)} Traceroute tests...\n")
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
