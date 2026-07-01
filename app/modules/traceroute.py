"""
CyberKit — Traceroute Engine

TTL-escalating probes via Scapy (ICMP or UDP). Calls on_hop() for each TTL
step with a TraceHop result. Requires administrator / root privileges.
"""

import socket
import sys
import time
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass
class TraceHop:
    hop: int
    ip: Optional[str]
    hostname: Optional[str]
    rtt_ms: Optional[float]
    timed_out: bool


def check_privileges() -> bool:
    """Return True if the current process has admin / root privileges."""
    try:
        if sys.platform == "win32":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return __import__("os").geteuid() == 0
    except Exception:
        return False


def scan(
    host: str,
    max_hops: int = 30,
    timeout: float = 2.0,
    method: str = "ICMP",
    stop_event=None,
    on_hop: Optional[Callable[[TraceHop], None]] = None,
) -> list:
    """
    Send TTL-escalating probes toward host.
    Calls on_hop(TraceHop) for each TTL step as results arrive.
    Returns the full list of TraceHop objects.
    """
    try:
        from scapy.layers.inet import IP, ICMP, UDP  # type: ignore
        from scapy.sendrecv import sr1               # type: ignore
    except ImportError:
        return []

    try:
        target_ip = socket.gethostbyname(host)
    except socket.gaierror:
        target_ip = host

    hops = []
    for ttl in range(1, max_hops + 1):
        if stop_event and stop_event.is_set():
            break

        if method.upper() == "UDP":
            probe = IP(dst=target_ip, ttl=ttl) / UDP(dport=33434 + ttl)
        else:
            probe = IP(dst=target_ip, ttl=ttl) / ICMP()

        t_start = time.perf_counter()
        reply = sr1(probe, timeout=timeout, verbose=False)
        rtt_ms = (time.perf_counter() - t_start) * 1000

        if reply is None:
            hop = TraceHop(hop=ttl, ip=None, hostname=None,
                           rtt_ms=None, timed_out=True)
        else:
            ip = reply.src
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = None
            hop = TraceHop(hop=ttl, ip=ip, hostname=hostname,
                           rtt_ms=round(rtt_ms, 1), timed_out=False)

        hops.append(hop)
        if on_hop:
            on_hop(hop)

        # Terminal condition: destination reached
        if reply is not None and reply.haslayer(ICMP):
            t = reply[ICMP].type
            if t == 0:   # Echo Reply  — ICMP probe reached host
                break
            if t == 3:   # Port Unreachable — UDP probe reached host
                break

    return hops
