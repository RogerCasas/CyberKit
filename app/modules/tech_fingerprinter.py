"""
CyberKit — Tech Fingerprinter engine.

Single HTTP GET; matches response headers, body, cookies, and meta tags
against the FINGERPRINTS signature database.
"""

import queue
import re
import threading
from dataclasses import dataclass

import requests

from app.data.fingerprints import FINGERPRINTS, Fingerprint

_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
_HEADERS = {
    "User-Agent": _UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

_META_CONTENT_RE = re.compile(
    r'<meta[^>]+content=["\']([^"\']*)["\']', re.IGNORECASE
)


@dataclass
class FingerprintResult:
    category: str
    name:     str
    evidence: str


def _match(fp: Fingerprint, headers: dict, body: str, cookies: dict) -> str:
    """Return the first matching evidence string, or '' if no match."""
    lower_headers = {k.lower(): v.lower() for k, v in headers.items()}
    lower_body    = body.lower()

    for hname, needle in fp.headers.items():
        val = lower_headers.get(hname, "")
        if needle == "" and val:
            return f"Header: {hname}: {headers.get(hname, '')[:60]}"
        if needle and needle.lower() in val:
            return f"Header: {hname}: {headers.get(hname, '')[:60]}"

    for substr in fp.html:
        if substr.lower() in lower_body:
            return f"Body: …{substr}…"

    lower_cookie_names = [k.lower() for k in cookies]
    for ck in fp.cookies:
        for cn in lower_cookie_names:
            if ck.lower() in cn:
                return f"Cookie: {cn}"

    meta_contents = " ".join(_META_CONTENT_RE.findall(body)).lower()
    for m in fp.meta:
        if m.lower() in meta_contents:
            return f"Meta: {m}"

    return ""


class TechFingerprintEngine:
    def __init__(
        self,
        url:          str,
        result_queue: queue.Queue,
        stop_event:   threading.Event,
    ):
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        self._url   = url
        self._queue = result_queue
        self._stop  = stop_event

    def run(self):
        try:
            resp = requests.get(
                self._url,
                headers=_HEADERS,
                timeout=10,
                allow_redirects=True,
            )
        except requests.RequestException as exc:
            self._queue.put(("error", str(exc)))
            return

        headers = dict(resp.headers)
        body    = resp.text
        cookies = dict(resp.cookies)

        found = 0
        for fp in FINGERPRINTS:
            if self._stop.is_set():
                break
            evidence = _match(fp, headers, body, cookies)
            if evidence:
                self._queue.put(("result", FingerprintResult(
                    category=fp.category,
                    name=fp.name,
                    evidence=evidence,
                )))
                found += 1

        self._queue.put(("done", found))
