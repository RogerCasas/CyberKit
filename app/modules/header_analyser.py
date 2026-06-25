"""
CyberKit — HTTP Security Header Analyser Engine

Checks 6 scored security headers + 3 info-leak headers.
Computes a weighted grade A+ through F.
"""

from dataclasses import dataclass
from typing import Callable, Optional

import requests

# ── Browser-like headers (shared constant) ────────────────────────────────────
_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
_SESSION_HEADERS = {
    "User-Agent": _UA,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
}

# ── Status constants ──────────────────────────────────────────────────────────
STATUS_OK      = "ok"
STATUS_WARN    = "warn"
STATUS_MISSING = "missing"
STATUS_SKIPPED = "skipped"
STATUS_INFO    = "info"

# ── Grade thresholds (% of applicable max score) ─────────────────────────────
_GRADE_THRESHOLDS = [
    (95, "A+"),
    (85, "A"),
    (70, "B"),
    (50, "C"),
    (30, "D"),
    (0,  "F"),
]


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class HeaderRule:
    name:       str          # HTTP header name (lowercase)
    display:    str          # human-readable name
    severity:   str          # critical | high | medium | info
    weight:     int          # grade points (0 for info-only)
    https_only: bool         # skip gracefully on HTTP targets
    check_fn:   Callable[[Optional[str]], tuple[str, int, str]]
    # returns (status, score, tip)


@dataclass
class HeaderFinding:
    rule:      HeaderRule
    raw_value: Optional[str]  # None = header absent
    status:    str             # ok | warn | missing | skipped | info
    tip:       str
    score:     int             # points awarded


# ── Check functions ───────────────────────────────────────────────────────────

def _check_csp(value: Optional[str]) -> tuple[str, int, str]:
    if value is None:
        return (STATUS_MISSING, 0,
                "Content-Security-Policy is missing. Without it, browsers allow "
                "inline scripts and external resources from any origin, making XSS "
                "attacks significantly easier. Add a CSP header to restrict resource "
                "loading.")
    v = value.lower()
    bad_kw = ("'unsafe-inline'", "'unsafe-eval'")
    if any(k in v for k in bad_kw):
        return (STATUS_WARN, 12,
                "CSP is present but weakened by 'unsafe-inline' or 'unsafe-eval'. "
                "These directives defeat much of CSP's XSS protection. Remove them "
                "and use nonces or hashes instead.")
    return (STATUS_OK, 25,
            "CSP looks good. Verify all directives are as restrictive as possible "
            "and test with the browser console for any violations.")


def _check_hsts(value: Optional[str], is_https: bool) -> tuple[str, int, str]:
    if not is_https:
        return (STATUS_SKIPPED, 0,
                "HSTS is not applicable to HTTP targets — it can only be enforced "
                "over HTTPS. Re-test after switching to HTTPS.")
    if value is None:
        return (STATUS_MISSING, 0,
                "Strict-Transport-Security is missing. Without it, browsers may "
                "allow HTTP downgrade attacks. Add: "
                "Strict-Transport-Security: max-age=31536000; includeSubDomains")
    try:
        max_age = int(
            next(
                (p.split("=")[1].strip()
                 for p in value.lower().split(";")
                 if "max-age" in p),
                "0",
            )
        )
    except (ValueError, StopIteration):
        max_age = 0
    if max_age < 31536000:
        return (STATUS_WARN, 12,
                f"HSTS max-age is {max_age}s which is less than 1 year (31536000). "
                "Increase it to at least 31536000 to be eligible for HSTS preloading.")
    return (STATUS_OK, 25,
            "HSTS is correctly configured. Consider adding 'preload' and submitting "
            "to the HSTS preload list for maximum protection.")


def _check_xfo(value: Optional[str]) -> tuple[str, int, str]:
    if value is None:
        return (STATUS_MISSING, 0,
                "X-Frame-Options is missing. This allows your page to be embedded "
                "in iframes, enabling clickjacking attacks. Add: "
                "X-Frame-Options: DENY  (or SAMEORIGIN if you embed your own frames)")
    v = value.upper().strip()
    if v in ("DENY", "SAMEORIGIN"):
        return (STATUS_OK, 15,
                "X-Frame-Options is correctly set. Note: CSP's frame-ancestors "
                "directive is the modern replacement and offers finer control.")
    if v.startswith("ALLOW-FROM"):
        return (STATUS_WARN, 7,
                "ALLOW-FROM is deprecated and not supported in modern browsers. "
                "Replace with CSP frame-ancestors.")
    return (STATUS_WARN, 7,
            f"Unrecognised X-Frame-Options value '{value}'. Expected DENY or SAMEORIGIN.")


def _check_xcto(value: Optional[str]) -> tuple[str, int, str]:
    if value is None:
        return (STATUS_MISSING, 0,
                "X-Content-Type-Options is missing. Browsers may MIME-sniff "
                "responses, potentially executing scripts served as other types. "
                "Add: X-Content-Type-Options: nosniff")
    if value.lower().strip() == "nosniff":
        return (STATUS_OK, 15,
                "X-Content-Type-Options: nosniff is correctly set.")
    return (STATUS_WARN, 7,
            f"Unexpected value '{value}' — only 'nosniff' is valid and understood by browsers.")


def _check_rp(value: Optional[str]) -> tuple[str, int, str]:
    if value is None:
        return (STATUS_MISSING, 0,
                "Referrer-Policy is missing. By default browsers send the full "
                "Referer header, which may leak sensitive URL parameters to third "
                "parties. Add: Referrer-Policy: strict-origin-when-cross-origin")
    if value.lower().strip() == "unsafe-url":
        return (STATUS_WARN, 5,
                "Referrer-Policy: unsafe-url sends the full URL to all destinations, "
                "including third parties over HTTP. Use a stricter policy such as "
                "'strict-origin-when-cross-origin'.")
    return (STATUS_OK, 10,
            "Referrer-Policy is set. Confirm the chosen policy matches your needs.")


def _check_pp(value: Optional[str]) -> tuple[str, int, str]:
    if value is None:
        return (STATUS_MISSING, 0,
                "Permissions-Policy is missing. This header lets you disable "
                "browser APIs (camera, microphone, geolocation) that your site "
                "doesn't use. Add at least: Permissions-Policy: geolocation=(), "
                "camera=(), microphone=()")
    return (STATUS_OK, 10,
            "Permissions-Policy is present. Review each directive to ensure only "
            "features your site actually uses are allowed.")


def _check_info_leak(name: str, value: Optional[str]) -> tuple[str, int, str]:
    if value is None:
        return (STATUS_OK, 0, f"{name} is not exposed — good.")
    return (STATUS_INFO, 0,
            f"{name} reveals server details: '{value}'. Remove or mask this header "
            "in your server configuration to reduce fingerprinting surface. For "
            "Apache use 'ServerTokens Prod'; for Nginx set 'server_tokens off'; "
            "for IIS remove the header via web.config.")


# ── Rule definitions ──────────────────────────────────────────────────────────

def _make_rules() -> list[HeaderRule]:
    return [
        HeaderRule(
            name="content-security-policy",
            display="Content-Security-Policy",
            severity="critical", weight=25, https_only=False,
            check_fn=lambda v: _check_csp(v),
        ),
        HeaderRule(
            name="strict-transport-security",
            display="Strict-Transport-Security",
            severity="critical", weight=25, https_only=True,
            check_fn=None,  # handled specially (needs is_https)
        ),
        HeaderRule(
            name="x-frame-options",
            display="X-Frame-Options",
            severity="high", weight=15, https_only=False,
            check_fn=lambda v: _check_xfo(v),
        ),
        HeaderRule(
            name="x-content-type-options",
            display="X-Content-Type-Options",
            severity="high", weight=15, https_only=False,
            check_fn=lambda v: _check_xcto(v),
        ),
        HeaderRule(
            name="referrer-policy",
            display="Referrer-Policy",
            severity="medium", weight=10, https_only=False,
            check_fn=lambda v: _check_rp(v),
        ),
        HeaderRule(
            name="permissions-policy",
            display="Permissions-Policy",
            severity="medium", weight=10, https_only=False,
            check_fn=lambda v: _check_pp(v),
        ),
        # Info-leak headers (weight=0, do not affect grade)
        HeaderRule(
            name="server",
            display="Server",
            severity="info", weight=0, https_only=False,
            check_fn=lambda v: _check_info_leak("Server", v),
        ),
        HeaderRule(
            name="x-powered-by",
            display="X-Powered-By",
            severity="info", weight=0, https_only=False,
            check_fn=lambda v: _check_info_leak("X-Powered-By", v),
        ),
        HeaderRule(
            name="x-aspnet-version",
            display="X-AspNet-Version",
            severity="info", weight=0, https_only=False,
            check_fn=lambda v: _check_info_leak("X-AspNet-Version", v),
        ),
    ]


HEADER_RULES: list[HeaderRule] = _make_rules()


# ── Analysis ──────────────────────────────────────────────────────────────────

def analyse(url: str) -> list[HeaderFinding]:
    """Fetch url and evaluate every HeaderRule. Returns one finding per rule."""
    session = requests.Session()
    session.headers.update(_SESSION_HEADERS)
    resp = session.get(url, timeout=10, allow_redirects=True)

    is_https = resp.url.startswith("https://")
    headers  = {k.lower(): v for k, v in resp.headers.items()}

    findings: list[HeaderFinding] = []
    for rule in HEADER_RULES:
        raw_value = headers.get(rule.name)

        if rule.name == "strict-transport-security":
            status, score, tip = _check_hsts(raw_value, is_https)
        else:
            status, score, tip = rule.check_fn(raw_value)

        # Info-only rules that are missing should show as ok (not a problem)
        if rule.weight == 0 and status == STATUS_OK:
            pass  # header absent → good, status already OK

        findings.append(HeaderFinding(
            rule=rule,
            raw_value=raw_value,
            status=status,
            tip=tip,
            score=score,
        ))

    return findings


def compute_grade(findings: list[HeaderFinding]) -> tuple[str, int, int]:
    """Return (letter_grade, score, max_score) for the scored rules only."""
    scored = [f for f in findings if f.rule.weight > 0 and f.status != STATUS_SKIPPED]
    total_score = sum(f.score for f in scored)
    max_score   = sum(f.rule.weight for f in scored)

    if max_score == 0:
        return ("F", 0, 0)

    pct = (total_score / max_score) * 100
    for threshold, letter in _GRADE_THRESHOLDS:
        if pct >= threshold:
            return (letter, total_score, max_score)
    return ("F", total_score, max_score)
