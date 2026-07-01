"""
CyberKit — Packet Sniffer Engine

Passive Scapy capture on a selected network interface. Calls on_packet()
for each frame. Read-only — no packet injection.

Requires administrator / root privileges at runtime.
"""

import sys
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass
class PacketRow:
    src: str
    dst: str
    proto: str
    sport: Optional[int]
    dport: Optional[int]
    preview: str


# BPF filter strings for each protocol filter option
_BPF: dict[str, str] = {
    "All":  "",
    "TCP":  "tcp",
    "UDP":  "udp",
    "ICMP": "icmp",
    "ARP":  "arp",
}


def list_interfaces() -> list[str]:
    """
    Return display names for available network interfaces.
    On Windows with Npcap, these are friendly names (e.g. "Wi-Fi").
    Falls back to network GUIDs if friendly names are unavailable.
    """
    try:
        from scapy.config import conf  # type: ignore
        names = []
        for iface in conf.ifaces.values():
            name = (getattr(iface, "description", None)
                    or getattr(iface, "name", None))
            if name:
                names.append(name)
        return names or ["(no interfaces found)"]
    except ImportError:
        return ["(scapy unavailable)"]
    except Exception:
        return ["(error listing interfaces)"]


def _resolve_iface(display_name: str) -> str:
    """Return the Scapy network name (GUID on Windows) for a display name."""
    try:
        from scapy.config import conf  # type: ignore
        for iface in conf.ifaces.values():
            desc = (getattr(iface, "description", None)
                    or getattr(iface, "name", None))
            if desc == display_name:
                return iface.name
    except Exception:
        pass
    return display_name


def _parse_packet(pkt) -> Optional[PacketRow]:
    """Extract a PacketRow from a raw Scapy packet. Returns None on error."""
    try:
        # Source / destination
        if pkt.haslayer("IP"):
            src = pkt["IP"].src
            dst = pkt["IP"].dst
        elif pkt.haslayer("IPv6"):
            src = pkt["IPv6"].src
            dst = pkt["IPv6"].dst
        elif pkt.haslayer("ARP"):
            src = pkt["ARP"].psrc
            dst = pkt["ARP"].pdst
        else:
            return None

        # Protocol
        if pkt.haslayer("TCP"):
            proto  = "TCP"
            sport  = pkt["TCP"].sport
            dport  = pkt["TCP"].dport
        elif pkt.haslayer("UDP"):
            proto  = "UDP"
            sport  = pkt["UDP"].sport
            dport  = pkt["UDP"].dport
        elif pkt.haslayer("ICMP") or pkt.haslayer("ICMPv6EchoRequest"):
            proto, sport, dport = "ICMP", None, None
        elif pkt.haslayer("ARP"):
            proto, sport, dport = "ARP", None, None
        else:
            proto, sport, dport = "OTHER", None, None

        # Payload preview
        preview = ""
        if pkt.haslayer("Raw"):
            raw = pkt["Raw"].load
            preview = raw[:40].decode("ascii", "replace").replace("\x00", ".")

        return PacketRow(src=src, dst=dst, proto=proto,
                         sport=sport, dport=dport, preview=preview)
    except Exception:
        return None


def capture(
    display_iface: str,
    proto_filter: str = "All",
    row_limit: int = 500,
    stop_event=None,
    on_packet: Optional[Callable[[PacketRow], None]] = None,
) -> None:
    """
    Start passive capture on display_iface. Calls on_packet(PacketRow) for
    each captured frame. Returns when stop_event is set or row_limit reached.
    """
    try:
        from scapy.sendrecv import sniff  # type: ignore
    except ImportError:
        return

    iface = _resolve_iface(display_iface)
    bpf   = _BPF.get(proto_filter, "")
    counter = [0]

    def handle(pkt):
        if stop_event and stop_event.is_set():
            return
        if counter[0] >= row_limit:
            return
        row = _parse_packet(pkt)
        if row is not None:
            counter[0] += 1
            if on_packet:
                on_packet(row)

    def should_stop(_):
        return (stop_event is not None and stop_event.is_set()) or counter[0] >= row_limit

    kwargs = dict(iface=iface, prn=handle, store=False, stop_filter=should_stop)
    if bpf:
        kwargs["filter"] = bpf

    # Loop with 1-second timeouts so stop_event is honoured even with no traffic.
    while True:
        if stop_event and stop_event.is_set():
            break
        if counter[0] >= row_limit:
            break
        try:
            sniff(timeout=1.0, **kwargs)
        except Exception:
            break
