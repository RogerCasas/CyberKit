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
    details: str = ""   # full packet dump shown in the details panel on click


# BPF filter strings for each protocol filter option
_BPF: dict[str, str] = {
    "All":  "",
    "TCP":  "tcp",
    "UDP":  "udp",
    "ICMP": "icmp",
    "ARP":  "arp",
}


# Populated by list_interfaces(); keyed by exactly what the dropdown shows.
# _resolve_iface() reads this so display→NPF mapping is always consistent.
_DISPLAY_TO_NPF: dict[str, str] = {}


def _win_iface_ip(guid: str) -> str:
    """Return the current IP address for a Windows adapter GUID, or ''."""
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            rf"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{guid}",
        )
        for val_name in ("DhcpIPAddress", "IPAddress"):
            try:
                val, _ = winreg.QueryValueEx(key, val_name)
                ip = val[0] if isinstance(val, list) else val
                if ip and ip != "0.0.0.0":
                    winreg.CloseKey(key)
                    return ip
            except OSError:
                pass
        winreg.CloseKey(key)
    except Exception:
        pass
    return ""


def _win_build_mapping() -> dict[str, str]:
    """
    Read the Windows registry to build {display_label: NPF_device_path}.
    Display label is "Friendly Name  (IP)" when an IP is available,
    otherwise just "Friendly Name".
    Returns empty dict on failure or non-Windows.
    """
    if sys.platform != "win32":
        return {}
    try:
        import winreg
        NET_KEY = (r"SYSTEM\CurrentControlSet\Control\Network"
                   r"\{4D36E972-E325-11CE-BFC1-08002BE10318}")
        mapping: dict[str, str] = {}
        root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, NET_KEY)
        i = 0
        while True:
            try:
                guid = winreg.EnumKey(root, i)
                i += 1
            except OSError:
                break
            try:
                conn = winreg.OpenKey(root, rf"{guid}\Connection")
                name, _ = winreg.QueryValueEx(conn, "Name")
                winreg.CloseKey(conn)
                ip = _win_iface_ip(guid)
                label = f"{name}  ({ip})" if ip else name
                mapping[label] = rf"\Device\NPF_{guid}"
            except OSError:
                pass
        winreg.CloseKey(root)
        return mapping
    except Exception:
        return {}


def list_interfaces() -> list[str]:
    """
    Return display labels for available network interfaces and cache the
    display→NPF mapping so _resolve_iface() can translate them back.

    Strategy (first that yields results wins):
    1. conf.ifaces  — older Scapy versions that populate friendly names.
    2. Windows registry — friendly name + current IP (e.g. "Wi-Fi  (192.168.1.5)").
    3. get_if_list() — raw NPF GUIDs; always works when Npcap is installed.
    """
    global _DISPLAY_TO_NPF

    # Method 1: conf.ifaces
    try:
        from scapy.config import conf  # type: ignore
        names = []
        for iface in (conf.ifaces or {}).values():
            name = (getattr(iface, "description", None)
                    or getattr(iface, "name", None))
            if name:
                names.append(name)
        if names:
            _DISPLAY_TO_NPF = {}   # names ARE the NPF names here; pass-through
            return names
    except ImportError:
        return ["(scapy unavailable)"]
    except Exception:
        pass

    # Method 2: Windows registry with friendly name + IP
    mapping = _win_build_mapping()
    if mapping:
        _DISPLAY_TO_NPF = mapping
        return list(mapping.keys())

    # Method 3: raw NPF GUIDs
    try:
        from scapy.arch import get_if_list  # type: ignore
        ifaces = get_if_list()
        if ifaces:
            _DISPLAY_TO_NPF = {}   # GUIDs pass through directly
            return ifaces
    except Exception:
        pass

    if sys.platform == "win32":
        return ["(Npcap not installed)"]
    return ["(no interfaces found)"]


def _resolve_iface(display_name: str) -> str:
    """
    Translate a dropdown display label back to the NPF device path for sniff().
    Falls back to returning the name unchanged for raw NPF paths or unknown names.
    """
    if display_name.startswith("\\Device\\"):
        return display_name
    if display_name in _DISPLAY_TO_NPF:
        return _DISPLAY_TO_NPF[display_name]
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

        try:
            details = pkt.show(dump=True)
        except Exception:
            details = ""

        return PacketRow(src=src, dst=dst, proto=proto,
                         sport=sport, dport=dport, preview=preview,
                         details=details)
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
        from scapy.sendrecv import sniff                           # type: ignore
        from scapy.layers.l2 import Ether                         # type: ignore  # registers DLT_EN10MB=1 → Ether
        from scapy.layers.inet import IP, TCP, UDP, ICMP          # type: ignore  # registers inet layers for haslayer()
        from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest    # type: ignore  # registers IPv6 layers
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
