"""
CyberKit — HTTP Credential Scanner Engine

Tries username/password combinations against an HTTP endpoint.
Supports HTTP Basic auth and form-based POST auth.
"""

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Optional

import requests

STATUS_SUCCESS = "Success"
STATUS_FAILED  = "Failed"
STATUS_ERROR   = "Error"

_FAILURE_STRINGS = ("invalid", "incorrect", "failed", "wrong", "error",
                    "denied", "unauthorized", "bad credentials")

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/json,*/*;q=0.9",
    "Accept-Language": "en-US,en;q=0.9",
}


@dataclass
class CredResult:
    index:    int
    username: str
    password: str
    status:   str  # Success | Failed | Error
    code:     int  # HTTP response code, 0 on network error


class CredentialHTTPScanner:
    """
    Iterates username × password pairs against a URL.

    auth_mode: "basic" | "post"
    post_user_field / post_pass_field: form field names used in POST mode.
    failure_string: if present in the response body, the attempt is Failed.
    """

    def __init__(
        self,
        url: str,
        usernames: list[str],
        passwords: list[str],
        auth_mode: str = "basic",
        post_user_field: str = "username",
        post_pass_field: str = "password",
        failure_string: str = "",
        delay_s: float = 0.5,
        threads: int = 1,
    ) -> None:
        self.url             = url
        self.usernames       = usernames
        self.passwords       = passwords
        self.auth_mode       = auth_mode
        self.post_user_field = post_user_field
        self.post_pass_field = post_pass_field
        self.failure_string  = failure_string.lower() if failure_string else ""
        self.delay_s         = delay_s
        self.threads         = max(1, threads)
        self._stop_event     = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(
        self,
        on_result: Callable[[CredResult], None],
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
        on_result: Callable[[CredResult], None],
        on_done:   Callable[[], None],
    ) -> None:
        # One future per username; each thread owns a username and tries every
        # password for it sequentially with the configured delay between attempts.
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {
                pool.submit(self._probe_username, u_idx, u, on_result): u
                for u_idx, u in enumerate(self.usernames)
            }
            for future in as_completed(futures):
                if self._stop_event.is_set():
                    for f in futures:
                        f.cancel()
                    break
                future.result()
        on_done()

    def _probe_username(
        self,
        u_idx: int,
        username: str,
        on_result: Callable[[CredResult], None],
    ) -> None:
        for p_idx, password in enumerate(self.passwords):
            if self._stop_event.is_set():
                break
            idx = u_idx * len(self.passwords) + p_idx
            result = self._probe(idx, username, password)
            on_result(result)
            if self.delay_s > 0 and not self._stop_event.is_set():
                time.sleep(self.delay_s)

    def _probe(self, idx: int, username: str, password: str) -> CredResult:
        try:
            if self.auth_mode == "basic":
                resp = requests.get(
                    self.url, auth=(username, password),
                    headers=_HEADERS, timeout=10, allow_redirects=True,
                )
            else:
                resp = requests.post(
                    self.url,
                    data={self.post_user_field: username,
                          self.post_pass_field: password},
                    headers=_HEADERS, timeout=10, allow_redirects=True,
                )

            code = resp.status_code
            body = resp.text.lower()

            if code in (200, 302, 301):
                failure_hit = (
                    any(s in body for s in _FAILURE_STRINGS)
                    or (self.failure_string and self.failure_string in body)
                )
                status = STATUS_FAILED if failure_hit else STATUS_SUCCESS
            else:
                status = STATUS_FAILED

            return CredResult(idx, username, password, status, code)

        except requests.RequestException as exc:
            return CredResult(idx, username, password, STATUS_ERROR, 0)
