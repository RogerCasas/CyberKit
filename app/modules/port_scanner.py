"""
CyberKit — Port Scanner Engine

TCP connect scan (no raw sockets, no admin required).
Port states: OPEN | CLOSED | FILTERED | ERROR
"""

import errno
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Optional

from app.data.port_lists import WELL_KNOWN_SERVICES

# ── Constants ─────────────────────────────────────────────────────────────────

STATUS_OPEN     = "OPEN"
STATUS_CLOSED   = "CLOSED"
STATUS_FILTERED = "FILTERED"
STATUS_ERROR    = "ERROR"

# connect_ex returns OS error codes; on Windows these are WinSock codes
_CONN_REFUSED: frozenset[int] = frozenset({
    errno.ECONNREFUSED,  # Unix: 111
    10061,               # Windows WSAECONNREFUSED
})


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class PortResult:
    port:        int
    status:      str   # OPEN | CLOSED | FILTERED | ERROR
    service:     str   # from WELL_KNOWN_SERVICES or ""
    banner:      str   # first 120 printable chars or ""
    response_ms: int


@dataclass
class ScanSummary:
    host:    str
    total:   int
    open:    int = 0
    filtered: int = 0
    closed:  int = 0
    errors:  int = 0
    results: list = field(default_factory=list)


# ── Engine ────────────────────────────────────────────────────────────────────

class PortScanEngine:
    """
    Thread-pool based TCP connect scanner.

    Usage:
        engine = PortScanEngine("192.168.1.1", ports, threads=100, timeout_s=1.0)
        engine.start(on_result=cb, on_done=cb)
        engine.stop()   # abort from any thread
    """

    def __init__(
        self,
        host: str,
        ports: list[int],
        threads: int = 100,
        timeout_s: float = 1.0,
        grab_banner: bool = False,
    ) -> None:
        self.host        = self._normalise_host(host)
        self.ports       = ports
        self.threads     = threads
        self.timeout_s   = timeout_s
        self.grab_banner = grab_banner

        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.summary = ScanSummary(host=self.host, total=len(ports))

    # ── Public API ────────────────────────────────────────────────────────────

    def start(
        self,
        on_result: Callable[[PortResult], None],
        on_done:   Callable[[ScanSummary], None],
    ) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, args=(on_result, on_done), daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ── Internal ──────────────────────────────────────────────────────────────

    def _run(
        self,
        on_result: Callable[[PortResult], None],
        on_done:   Callable[[ScanSummary], None],
    ) -> None:
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self._probe, p): p for p in self.ports}
            for future in as_completed(futures):
                if self._stop_event.is_set():
                    for f in futures:
                        f.cancel()
                    break
                result: PortResult = future.result()
                self._update_summary(result)
                on_result(result)
        on_done(self.summary)

    def _probe(self, port: int) -> PortResult:
        start  = time.monotonic()
        banner = ""
        status = STATUS_ERROR

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout_s)
        try:
            code = sock.connect_ex((self.host, port))
            if code == 0:
                status = STATUS_OPEN
                if self.grab_banner:
                    try:
                        sock.settimeout(1.0)
                        data = sock.recv(256)
                        banner = data.decode("utf-8", errors="replace").strip()
                        banner = "".join(c for c in banner if c.isprintable())[:120]
                    except Exception:
                        pass
            elif code in _CONN_REFUSED:
                status = STATUS_CLOSED
            else:
                status = STATUS_FILTERED
        except socket.timeout:
            status = STATUS_FILTERED
        except OSError:
            status = STATUS_FILTERED
        finally:
            elapsed = int((time.monotonic() - start) * 1000)
            try:
                sock.close()
            except Exception:
                pass

        return PortResult(
            port=port,
            status=status,
            service=WELL_KNOWN_SERVICES.get(port, ""),
            banner=banner,
            response_ms=elapsed,
        )

    def _update_summary(self, r: PortResult) -> None:
        self.summary.results.append(r)
        if r.status == STATUS_OPEN:
            self.summary.open += 1
        elif r.status == STATUS_FILTERED:
            self.summary.filtered += 1
        elif r.status == STATUS_CLOSED:
            self.summary.closed += 1
        else:
            self.summary.errors += 1

    @staticmethod
    def _normalise_host(host: str) -> str:
        host = host.strip()
        if "://" in host:
            host = host.split("://", 1)[1]
        host = host.split("/")[0]
        # Strip port suffix (but not IPv6 brackets)
        if ":" in host and not host.startswith("["):
            host = host.rsplit(":", 1)[0]
        return host
