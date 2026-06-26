"""
CyberKit — SSH Credential Scanner Engine

Tests username/password pairs against an SSH server using Paramiko.
No raw sockets; no admin privileges required.
"""

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable, Optional

import paramiko

STATUS_SUCCESS = "Success"
STATUS_FAILED  = "Failed"
STATUS_ERROR   = "Error"


@dataclass
class SSHCredResult:
    index:    int
    username: str
    password: str
    status:   str  # Success | Failed | Error
    detail:   str  # short message for Error rows


class CredentialSSHScanner:
    """
    Iterates username × password pairs against an SSH endpoint.
    """

    def __init__(
        self,
        host: str,
        port: int,
        usernames: list[str],
        passwords: list[str],
        delay_s: float = 0.5,
        threads: int = 1,
    ) -> None:
        self.host        = host.strip()
        self.port        = port
        self.usernames   = usernames
        self.passwords   = passwords
        self.delay_s     = delay_s
        self.threads     = max(1, threads)
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(
        self,
        on_result: Callable[[SSHCredResult], None],
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
        on_result: Callable[[SSHCredResult], None],
        on_done:   Callable[[], None],
    ) -> None:
        pairs = [
            (idx, u, p)
            for idx, (u, p) in enumerate(
                (u, p) for u in self.usernames for p in self.passwords
            )
        ]
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {
                pool.submit(self._probe, idx, u, p): (idx, u, p)
                for idx, u, p in pairs
            }
            for future in as_completed(futures):
                if self._stop_event.is_set():
                    for f in futures:
                        f.cancel()
                    break
                result = future.result()
                on_result(result)
                if self.delay_s > 0:
                    time.sleep(self.delay_s)
        on_done()

    def _probe(self, idx: int, username: str, password: str) -> SSHCredResult:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                self.host, port=self.port,
                username=username, password=password,
                timeout=10, banner_timeout=10,
                allow_agent=False, look_for_keys=False,
            )
            client.close()
            return SSHCredResult(idx, username, password, STATUS_SUCCESS, "")
        except paramiko.AuthenticationException:
            return SSHCredResult(idx, username, password, STATUS_FAILED, "Auth failed")
        except (paramiko.SSHException, socket.error, OSError) as exc:
            return SSHCredResult(idx, username, password, STATUS_ERROR, str(exc)[:80])
        finally:
            try:
                client.close()
            except Exception:
                pass
