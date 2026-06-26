"""
CyberKit — HTTP Request Builder engine
"""

import time
from dataclasses import dataclass, field

import requests


@dataclass
class RequestResult:
    status_code: int = 0
    reason: str = ""
    headers: dict = field(default_factory=dict)
    body: str = ""
    elapsed_ms: int = 0
    error: str = ""


def send(
    method: str,
    url: str,
    headers: dict = None,
    body: str = "",
    follow_redirects: bool = True,
    timeout: int = 15,
) -> RequestResult:
    if headers is None:
        headers = {}

    if not url.startswith(("http://", "https://")):
        return RequestResult(error="Invalid URL — must start with http:// or https://")

    try:
        start = time.monotonic()
        resp = requests.request(
            method=method.upper(),
            url=url,
            headers=headers,
            data=body.encode() if body else None,
            allow_redirects=follow_redirects,
            timeout=timeout,
        )
        elapsed_ms = int((time.monotonic() - start) * 1000)
        try:
            body_text = resp.text
        except Exception:
            body_text = "<binary response>"
        return RequestResult(
            status_code=resp.status_code,
            reason=resp.reason or "",
            headers=dict(resp.headers),
            body=body_text,
            elapsed_ms=elapsed_ms,
        )
    except requests.ConnectionError as exc:
        return RequestResult(error=f"Connection error: {exc}")
    except requests.Timeout:
        return RequestResult(error=f"Request timed out after {timeout}s")
    except requests.RequestException as exc:
        return RequestResult(error=f"Request failed: {exc}")
    except Exception as exc:
        return RequestResult(error=f"Unexpected error: {exc}")
