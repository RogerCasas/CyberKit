"""
CyberKit — Reflected XSS Tester engine (detection only, no browser execution).

Injects reflected-XSS payloads into each GET/POST parameter and inspects the
response body for the payload. A payload reflected *verbatim* (raw angle
brackets intact) would execute in a browser → flagged vulnerable. A payload
that comes back HTML-entity-encoded (``&lt;script&gt;``) is safe → reported as
reflected-but-encoded. No JavaScript is ever executed; this is pure
request/response signature matching.
"""

import html
import uuid
from dataclasses import dataclass

from app.modules.http_builder import send
from app.modules.web_injection import inject, parse_params


@dataclass
class XSSResult:
    parameter: str
    payload: str
    reflected: bool
    encoded: bool
    context: str          # "html" | "attribute" | "script" | "—"
    is_vulnerable: bool


# {MARKER} is replaced per-scan with a unique random token so reflection
# detection cannot be confused by incidental page text.
PAYLOAD_TEMPLATES = [
    "<script>{MARKER}</script>",
    '"><img src=x onerror={MARKER}>',
    "<svg onload={MARKER}>",
    "'><script>{MARKER}</script>",
    "{MARKER}",   # bare marker — confirms basic reflection (not itself an XSS)
]


def make_marker() -> str:
    """Return a unique, HTML-safe reflection marker (unaffected by escaping)."""
    return "ck" + uuid.uuid4().hex[:10]


# ── Helpers exported for unit tests ──────────────────────────────────────────

def _classify_reflection(body: str, payload: str) -> tuple:
    """
    Return ``(reflected, encoded)``.

    reflected → the payload appears in the body in some form.
    encoded   → it appears ONLY in HTML-entity-encoded form (safe).
    """
    if payload in body:
        return True, False
    escaped = html.escape(payload, quote=True)
    if escaped != payload and escaped in body:
        return True, True
    return False, False


def _is_active(payload: str) -> bool:
    """A payload can break out of HTML context only if it carries < or >."""
    return "<" in payload or ">" in payload


def _detect_context(body: str, marker: str) -> str:
    """Heuristically classify where the marker landed in the document."""
    idx = body.find(marker)
    if idx == -1:
        return "—"
    before = body[:idx]
    if before.rfind("<script") > before.rfind("</script>"):
        return "script"
    if before.rfind("<") > before.rfind(">"):
        return "attribute"
    return "html"


# ── Public interface ──────────────────────────────────────────────────────────

def scan(
    url: str,
    method: str,
    params: list,
    timeout: int = 10,
    progress_cb=None,
    result_cb=None,
    stop_event=None,
    marker: str = None,
) -> list:
    if not params:
        params = parse_params(url)
    if marker is None:
        marker = make_marker()

    results = []
    for idx, param in enumerate(params):
        if stop_event and stop_event.is_set():
            break

        result = _probe_param(url, method, param, marker, timeout)
        results.append(result)
        if result_cb:
            result_cb(result)
        if progress_cb:
            progress_cb(idx + 1, len(params))

    return results


def _probe_param(url, method, param, marker, timeout) -> XSSResult:
    fallback = None
    for template in PAYLOAD_TEMPLATES:
        payload = template.replace("{MARKER}", marker)
        inj = inject(url, method, param, payload)
        resp = send(method, inj["url"], body=inj["body"], timeout=timeout)
        reflected, encoded = _classify_reflection(resp.body, payload)

        if reflected and not encoded and _is_active(payload):
            return XSSResult(
                parameter=param, payload=payload, reflected=True, encoded=False,
                context=_detect_context(resp.body, marker), is_vulnerable=True,
            )
        if reflected and fallback is None:
            # Reflected but safe (encoded, or the bare non-active marker).
            fallback = XSSResult(
                parameter=param, payload=payload, reflected=True, encoded=encoded,
                context=_detect_context(resp.body, marker), is_vulnerable=False,
            )

    if fallback is not None:
        return fallback
    return XSSResult(
        parameter=param, payload=f"{len(PAYLOAD_TEMPLATES)} payloads",
        reflected=False, encoded=False, context="—", is_vulnerable=False,
    )
