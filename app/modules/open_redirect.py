"""
CyberKit — Open Redirect Detector engine (detection only).

Injects external-host redirect payloads into each GET/POST parameter, sends the
request with redirects DISABLED, and flags any 3xx whose ``Location`` header
resolves to an external sentinel host. The sentinel is a fixed, non-resolving
domain so a positive match can never accidentally point at a real third party.
"""

from dataclasses import dataclass
from urllib.parse import urlparse

from app.modules.http_builder import send
from app.modules.web_injection import inject, parse_params

# Non-resolving sentinel host used as the redirect target in every payload.
SENTINEL = "cyberkit-redirect-test.example"

PAYLOAD_TEMPLATES = [
    "//{S}",          # scheme-relative
    "https://{S}",    # absolute https
    "http://{S}",     # absolute http
    "/\\{S}",         # slash-backslash (browser-normalised to //)
    "\\/{S}",         # backslash-slash
    "https:{S}",      # scheme without slashes
    "//{S}/%2f..",    # path-traversal suffix
]


@dataclass
class RedirectResult:
    parameter: str
    payload: str
    status_code: int
    location: str
    is_vulnerable: bool


# ── Helpers exported for unit tests ──────────────────────────────────────────

def _get_header(headers: dict, name: str) -> str:
    for k, v in (headers or {}).items():
        if k.lower() == name.lower():
            return v
    return ""


def _is_external_redirect(location: str, sentinel: str = SENTINEL) -> bool:
    """True when *location* resolves to the sentinel host (or a subdomain of it)."""
    if not location:
        return False
    loc = location.strip().replace("\\", "/")
    low = loc.lower()

    if low.startswith("//"):
        test = "http:" + loc
    elif "://" in low:
        test = loc
    elif low.startswith("http:") or low.startswith("https:"):
        scheme, _, rest = loc.partition(":")
        test = scheme + "://" + rest
    else:
        # Relative path → same origin, never external.
        test = "http://_placeholder_/" + loc.lstrip("/")

    host = (urlparse(test).hostname or "").lower()
    return host == sentinel or host.endswith("." + sentinel)


def build_payloads(target_host: str = None) -> list:
    """Concrete payload strings; adds a suffix-bypass when a host is known."""
    payloads = [t.replace("{S}", SENTINEL) for t in PAYLOAD_TEMPLATES]
    if target_host:
        payloads.append(f"https://{target_host}.{SENTINEL}")
    return payloads


# ── Public interface ──────────────────────────────────────────────────────────

def scan(
    url: str,
    method: str,
    params: list,
    timeout: int = 10,
    progress_cb=None,
    result_cb=None,
    stop_event=None,
) -> list:
    if not params:
        params = parse_params(url)
    payloads = build_payloads(urlparse(url).hostname)

    results = []
    for idx, param in enumerate(params):
        if stop_event and stop_event.is_set():
            break

        result = _probe_param(url, method, param, payloads, timeout)
        results.append(result)
        if result_cb:
            result_cb(result)
        if progress_cb:
            progress_cb(idx + 1, len(params))

    return results


def _probe_param(url, method, param, payloads, timeout) -> RedirectResult:
    for payload in payloads:
        inj = inject(url, method, param, payload)
        resp = send(method, inj["url"], body=inj["body"],
                    timeout=timeout, follow_redirects=False)
        location = _get_header(resp.headers, "Location")
        if 300 <= resp.status_code < 400 and _is_external_redirect(location):
            return RedirectResult(
                parameter=param, payload=payload,
                status_code=resp.status_code, location=location,
                is_vulnerable=True,
            )
    return RedirectResult(
        parameter=param, payload=f"{len(payloads)} payloads",
        status_code=0, location="", is_vulnerable=False,
    )
