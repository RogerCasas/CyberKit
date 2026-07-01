"""
CyberKit — Packet Sniffer engine tests (no network, Scapy mocked)

Run: python tests/test_packet_sniffer.py
"""

import io
import sys
import os
import threading
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from app.modules.packet_sniffer import PacketRow, _parse_packet, capture


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_pkt(layers: set, src="1.1.1.1", dst="2.2.2.2",
              sport=None, dport=None, raw=None,
              arp_psrc=None, arp_pdst=None):
    """Build a minimal mock Scapy packet for _parse_packet."""
    pkt = MagicMock()

    def haslayer(name):
        return name in layers

    def getitem(name):
        m = MagicMock()
        if name == "IP":
            m.src, m.dst = src, dst
        elif name == "IPv6":
            m.src, m.dst = src, dst
        elif name == "TCP":
            m.sport, m.dport = sport, dport
        elif name == "UDP":
            m.sport, m.dport = sport, dport
        elif name == "ARP":
            m.psrc = arp_psrc or src
            m.pdst = arp_pdst or dst
        elif name == "Raw":
            m.load = raw or b""
        return m

    pkt.haslayer.side_effect = haslayer
    pkt.__getitem__ = MagicMock(side_effect=getitem)
    return pkt


# ── _parse_packet ─────────────────────────────────────────────────────────────

def test_parse_tcp():
    pkt = _make_pkt({"IP", "TCP"}, src="1.1.1.1", dst="8.8.8.8", sport=54321, dport=80)
    row = _parse_packet(pkt)
    assert row is not None
    assert row.proto == "TCP"
    assert row.sport == 54321
    assert row.dport == 80
    assert row.src == "1.1.1.1"
    print(f"  TCP parse → {row.proto} {row.src}:{row.sport}->{row.dst}:{row.dport}: OK")


def test_parse_udp():
    pkt = _make_pkt({"IP", "UDP"}, src="10.0.0.1", dst="8.8.8.8", sport=5353, dport=53)
    row = _parse_packet(pkt)
    assert row is not None
    assert row.proto == "UDP"
    assert row.sport == 5353
    assert row.dport == 53
    print(f"  UDP parse → {row.proto} sport={row.sport}: OK")


def test_parse_icmp():
    pkt = _make_pkt({"IP", "ICMP"}, src="1.2.3.4", dst="5.6.7.8")
    row = _parse_packet(pkt)
    assert row is not None
    assert row.proto == "ICMP"
    assert row.sport is None
    assert row.dport is None
    print("  ICMP parse → no ports: OK")


def test_parse_arp():
    pkt = _make_pkt({"ARP"}, arp_psrc="192.168.1.1", arp_pdst="192.168.1.255")
    row = _parse_packet(pkt)
    assert row is not None
    assert row.proto == "ARP"
    assert row.sport is None
    assert row.dport is None
    print(f"  ARP parse → {row.src}->{row.dst}: OK")


def test_parse_payload_preview():
    pkt = _make_pkt({"IP", "TCP", "Raw"},
                    src="1.1.1.1", dst="2.2.2.2", sport=1, dport=2,
                    raw=b"GET / HTTP/1.1\r\nHost: example.com\r\n")
    row = _parse_packet(pkt)
    assert row is not None
    assert "GET" in row.preview
    assert len(row.preview) <= 40
    print(f"  payload preview={row.preview!r}: OK")


def test_parse_no_ip_no_arp_returns_none():
    pkt = _make_pkt(set())  # no recognised layers
    row = _parse_packet(pkt)
    assert row is None
    print("  unknown layers → None: OK")


# ── capture — stop_event ──────────────────────────────────────────────────────

def test_capture_stop_event_before_start():
    ev = threading.Event()
    ev.set()
    called = []

    def fake_sniff(**kwargs):
        called.append(1)

    with patch("scapy.sendrecv.sniff", side_effect=fake_sniff):
        capture("eth0", stop_event=ev, on_packet=lambda r: None)

    assert called == [], "stop_event already set → sniff never called"
    print("  capture stop_event pre-set → sniff not called: OK")


# ── capture — row_limit ───────────────────────────────────────────────────────

def test_capture_row_limit():
    """on_packet should not be called more than row_limit times."""
    tcp_pkt = _make_pkt({"IP", "TCP"}, sport=1, dport=2)

    def fake_sniff(timeout, iface, prn, store, stop_filter, **kw):
        # Emit 10 packets per sniff call
        for _ in range(10):
            if not stop_filter(tcp_pkt):
                prn(tcp_pkt)

    collected = []
    ev = threading.Event()

    # After limit is hit the loop should exit on its own
    def on_pkt(r):
        collected.append(r)
        if len(collected) >= 5:
            ev.set()

    with patch("scapy.sendrecv.sniff", side_effect=fake_sniff):
        with patch("app.modules.packet_sniffer._resolve_iface", return_value="eth0"):
            capture("eth0", row_limit=5, stop_event=ev, on_packet=on_pkt)

    assert len(collected) <= 5
    print(f"  row_limit=5 → {len(collected)} packets collected: OK")


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_parse_tcp,
        test_parse_udp,
        test_parse_icmp,
        test_parse_arp,
        test_parse_payload_preview,
        test_parse_no_ip_no_arp_returns_none,
        test_capture_stop_event_before_start,
        test_capture_row_limit,
    ]
    passed = 0
    print(f"Running {len(tests)} Packet Sniffer tests...\n")
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
