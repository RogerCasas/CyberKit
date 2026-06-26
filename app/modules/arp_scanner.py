"""
CyberKit — ARP Scanner Engine

Sends ARP requests via Scapy and collects IP/MAC/vendor/hostname per host.
Requires administrator / root privileges at runtime.
"""

import os
import socket
import sys
import threading
from dataclasses import dataclass
from typing import Callable, Optional

from app.data.oui_table import lookup_vendor

STATUS_FOUND = "Found"
STATUS_ERROR = "Error"


@dataclass
class ARPResult:
    index:    int
    ip:       str
    mac:      str
    vendor:   str
    hostname: str


def check_privileges() -> bool:
    """Return True if the current process has admin / root privileges."""
    try:
        if sys.platform == "win32":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def auto_detect_subnet() -> str:
    """
    Best-effort: return the default interface subnet as a CIDR string.
    Falls back to '192.168.1.0/24' if detection fails.
    """
    try:
        from scapy.config import conf  # type: ignore
        iface = conf.iface
        ip    = iface.ip
        mask  = iface.netmask if hasattr(iface, "netmask") else "255.255.255.0"
        # Convert mask to prefix length
        prefix = sum(bin(int(o)).count("1") for o in mask.split("."))
        # Zero out host bits
        ip_parts  = [int(o) for o in ip.split(".")]
        mask_parts = [int(o) for o in mask.split(".")]
        net_parts  = [ip_parts[i] & mask_parts[i] for i in range(4)]
        return f"{'.'.join(str(o) for o in net_parts)}/{prefix}"
    except Exception:
        return "192.168.1.0/24"


class ARPScanner:
    def __init__(self, subnet: str, timeout_s: float = 3.0) -> None:
        self.subnet      = subnet
        self.timeout_s   = timeout_s
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(
        self,
        on_result: Callable[[ARPResult], None],
        on_done:   Callable[[], None],
    ) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, args=(on_result, on_done), daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def _run(
        self,
        on_result: Callable[[ARPResult], None],
        on_done:   Callable[[], None],
    ) -> None:
        try:
            from scapy.layers.l2 import ARP, Ether  # type: ignore
            from scapy.sendrecv import srp          # type: ignore

            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=self.subnet)
            answered, _ = srp(pkt, timeout=self.timeout_s, verbose=False)

            for idx, (_, rcv) in enumerate(answered, 1):
                if self._stop_event.is_set():
                    break
                ip  = rcv.psrc
                mac = rcv.hwsrc.upper()
                vendor = lookup_vendor(mac)
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    hostname = "—"
                on_result(ARPResult(idx, ip, mac, vendor, hostname))
        except Exception:
            pass
        finally:
            on_done()
