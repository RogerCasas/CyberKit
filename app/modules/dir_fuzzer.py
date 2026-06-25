"""
CyberKit — Directory Fuzzer Engine

Uses HEAD first, falls back to GET if server doesn't support HEAD (405 / 501).
Result categories:
  - FOUND       : 200 OK
  - INTERESTING : 301, 302, 303, 307, 308 (redirect) or 403 Forbidden
  - NOT_FOUND   : 404 or any other status
  - ERROR       : connection / timeout error
"""

import queue
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import urlparse

import requests
from requests.exceptions import ConnectionError, Timeout, RequestException

# ── Constants ─────────────────────────────────────────────────────────────────

TIMEOUT = 6  # seconds per request
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

# Minimal browser headers — many servers reject requests without a realistic Accept header
SESSION_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
}

STATUS_FOUND = "FOUND"           # 200
STATUS_INTERESTING = "INTERESTING"  # 301/302/303/307/308/403
STATUS_NOT_FOUND = "NOT_FOUND"   # 404 + others
STATUS_ERROR = "ERROR"

REDIRECT_CODES = {301, 302, 303, 307, 308}
INTERESTING_CODES = REDIRECT_CODES | {401, 403}
HEAD_UNSUPPORTED = {405, 501}


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    path: str
    full_url: str
    status_code: Optional[int]
    category: str          # FOUND / INTERESTING / NOT_FOUND / ERROR
    response_time_ms: int
    error_msg: str = ""


@dataclass
class ScanSummary:
    total: int = 0
    found: int = 0
    interesting: int = 0
    not_found: int = 0
    errors: int = 0
    results: list = field(default_factory=list)


# ── Engine ────────────────────────────────────────────────────────────────────

class FuzzerEngine:
    """
    Thread-pool based directory fuzzer.

    Usage:
        engine = FuzzerEngine(base_url, wordlist, threads=10)
        engine.start(on_result_callback, on_done_callback)
        engine.stop()   # call from any thread to abort
    """

    def __init__(
        self,
        base_url: str,
        wordlist: list[str],
        threads: int = 10,
    ) -> None:
        self.base_url = self._normalise_url(base_url)
        self.wordlist = wordlist
        self.threads = threads

        self._stop_event = threading.Event()
        self._result_queue: queue.Queue[ScanResult] = queue.Queue()
        self._thread: Optional[threading.Thread] = None

        self.summary = ScanSummary(total=len(wordlist))

    # ── Public API ────────────────────────────────────────────────────────────

    def start(
        self,
        on_result: Callable[[ScanResult], None],
        on_done: Callable[[ScanSummary], None],
    ) -> None:
        """Begin scanning in a background thread."""
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            args=(on_result, on_done),
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal the engine to stop after the current batch."""
        self._stop_event.set()

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ── Internal ──────────────────────────────────────────────────────────────

    def _run(
        self,
        on_result: Callable[[ScanResult], None],
        on_done: Callable[[ScanSummary], None],
    ) -> None:
        session = requests.Session()
        session.headers.update(SESSION_HEADERS)

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {
                pool.submit(self._probe, session, path): path
                for path in self.wordlist
            }
            for future in as_completed(futures):
                if self._stop_event.is_set():
                    for f in futures:
                        f.cancel()
                    break

                result: ScanResult = future.result()
                self._update_summary(result)
                on_result(result)

        on_done(self.summary)

    def _probe(self, session: requests.Session, path: str) -> ScanResult:
        url = self.base_url.rstrip("/") + path
        start = time.monotonic()

        try:
            resp = session.head(url, timeout=TIMEOUT, allow_redirects=True)

            # Fall back to GET if server doesn't support HEAD
            if resp.status_code in HEAD_UNSUPPORTED:
                resp = session.get(
                    url, timeout=TIMEOUT, allow_redirects=True, stream=True
                )
                resp.close()

            elapsed = int((time.monotonic() - start) * 1000)
            category = self._categorise(resp.status_code)

            return ScanResult(
                path=path,
                full_url=url,
                status_code=resp.status_code,
                category=category,
                response_time_ms=elapsed,
            )

        except (ConnectionError, Timeout) as exc:
            elapsed = int((time.monotonic() - start) * 1000)
            return ScanResult(
                path=path,
                full_url=url,
                status_code=None,
                category=STATUS_ERROR,
                response_time_ms=elapsed,
                error_msg=str(exc)[:120],
            )
        except RequestException as exc:
            elapsed = int((time.monotonic() - start) * 1000)
            return ScanResult(
                path=path,
                full_url=url,
                status_code=None,
                category=STATUS_ERROR,
                response_time_ms=elapsed,
                error_msg=str(exc)[:120],
            )

    @staticmethod
    def _categorise(code: int) -> str:
        if code == 200:
            return STATUS_FOUND
        if code in INTERESTING_CODES:
            return STATUS_INTERESTING
        return STATUS_NOT_FOUND

    def _update_summary(self, result: ScanResult) -> None:
        self.summary.results.append(result)
        if result.category == STATUS_FOUND:
            self.summary.found += 1
        elif result.category == STATUS_INTERESTING:
            self.summary.interesting += 1
        elif result.category == STATUS_ERROR:
            self.summary.errors += 1
        else:
            self.summary.not_found += 1

    @staticmethod
    def _normalise_url(url: str) -> str:
        url = url.strip()
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        parsed = urlparse(url)
        # Preserve the path so users can target a sub-directory (e.g. /demoGPT/)
        base_path = parsed.path.rstrip("/")
        return f"{parsed.scheme}://{parsed.netloc}{base_path}"
