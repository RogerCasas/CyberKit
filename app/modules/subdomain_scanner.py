"""
CyberKit — Subdomain Brute-Force Engine

Resolves {candidate}.{domain} via DNS A/AAAA lookup using a thread pool.
Results are emitted into a queue.Queue for the UI to drain.
"""

import queue
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Optional

import dns.resolver
import dns.exception

STATUS_FOUND     = "Found"
STATUS_NOT_FOUND = "Not Found"
STATUS_ERROR     = "Error"


@dataclass
class SubdomainResult:
    index:     int
    subdomain: str
    ip:        str
    status:    str  # Found | Not Found | Error


class SubdomainScanner:
    """
    Thread-pool subdomain brute-forcer.

    Usage:
        scanner = SubdomainScanner("example.com", wordlist, threads=20)
        scanner.start(on_result=cb, on_done=cb)
        scanner.stop()
    """

    def __init__(
        self,
        domain: str,
        wordlist: list[str],
        threads: int = 20,
    ) -> None:
        self.domain      = domain.strip().lstrip(".")
        self.wordlist    = wordlist
        self.threads     = max(1, threads)
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(
        self,
        on_result: Callable[[SubdomainResult], None],
        on_done:   Callable[[], None],
    ) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, args=(on_result, on_done), daemon=True
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    # ── Internal ──────────────────────────────────────────────────────────────

    def _run(
        self,
        on_result: Callable[[SubdomainResult], None],
        on_done:   Callable[[], None],
    ) -> None:
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {
                pool.submit(self._probe, idx, word): (idx, word)
                for idx, word in enumerate(self.wordlist)
            }
            for future in as_completed(futures):
                if self._stop_event.is_set():
                    for f in futures:
                        f.cancel()
                    break
                on_result(future.result())
        on_done()

    def _probe(self, idx: int, word: str) -> SubdomainResult:
        fqdn = f"{word}.{self.domain}"
        try:
            answer = dns.resolver.resolve(fqdn, "A", lifetime=5)
            ip = answer[0].to_text()
            return SubdomainResult(idx, fqdn, ip, STATUS_FOUND)
        except dns.resolver.NXDOMAIN:
            return SubdomainResult(idx, fqdn, "", STATUS_NOT_FOUND)
        except dns.resolver.NoAnswer:
            return SubdomainResult(idx, fqdn, "", STATUS_NOT_FOUND)
        except dns.resolver.Timeout:
            return SubdomainResult(idx, fqdn, "", STATUS_ERROR)
        except dns.exception.DNSException:
            return SubdomainResult(idx, fqdn, "", STATUS_NOT_FOUND)
