"""
CyberKit — Banner Grabber Engine

Raw TCP connect to host:port; sends an optional probe string and reads the
service banner. Optionally wraps the connection in TLS. stdlib-only.
"""

import socket
import ssl
from dataclasses import dataclass
from typing import Optional

BANNER_MAX = 4096


@dataclass
class BannerResult:
    host: str
    port: int
    banner: str
    tls: bool
    error: Optional[str]


def grab(
    host: str,
    port: int,
    probe: str = "\r\n",
    use_tls: bool = False,
    timeout: float = 5.0,
) -> BannerResult:
    """
    Connect to host:port, optionally wrap TLS, send probe, read banner.
    Never raises — errors are captured in BannerResult.error.
    """
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)

        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        if probe:
            sock.sendall(probe.encode("utf-8", "replace"))

        chunks: list[bytes] = []
        total = 0
        while total < BANNER_MAX:
            try:
                chunk = sock.recv(min(4096, BANNER_MAX - total))
            except (socket.timeout, ssl.SSLError):
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)

        try:
            sock.close()
        except Exception:
            pass

        raw = b"".join(chunks)
        banner = raw.decode("utf-8", "replace").replace("\x00", "")[:BANNER_MAX]
        return BannerResult(host=host, port=port, banner=banner, tls=use_tls, error=None)

    except Exception as exc:
        return BannerResult(host=host, port=port, banner="", tls=use_tls, error=str(exc))
