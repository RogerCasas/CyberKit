"""
CyberKit — CSRF Analyser engine (posture inspection, detection only).

Fetches a target URL and reports its CSRF posture as a list of findings:
  • Set-Cookie SameSite / Secure flags
  • presence of hidden anti-CSRF token fields in forms
  • a best-effort Origin/Referer validation probe (informational)

This module never forges a working CSRF exploit — it inspects and explains.
"""

import re
from dataclasses import dataclass

from app.modules.http_builder import send


@dataclass
class CSRFFinding:
    check: str
    detail: str
    severity: str   # "ok" | "info" | "warn" | "high"


_FORM_RE = re.compile(r"<form\b.*?</form>", re.IGNORECASE | re.DOTALL)
_TOKEN_NAME_RE = re.compile(
    r'name\s*=\s*["\']?[^"\'>\s]*'
    r'(csrf|xsrf|_token|authenticity_token|verificationtoken|token)'
    r'[^"\'>\s]*',
    re.IGNORECASE,
)

_ORIGIN_SPOOF = "https://cyberkit-csrf-test.example"


# ── Helpers exported for unit tests ──────────────────────────────────────────

def _get_header(headers: dict, name: str) -> str:
    for k, v in (headers or {}).items():
        if k.lower() == name.lower():
            return v
    return ""


def _split_cookies(raw: str) -> list:
    """Split a possibly comma-joined Set-Cookie header into individual cookies."""
    if not raw:
        return []
    # Split only on commas that introduce a new `name=` pair (cookie boundary),
    # not the commas inside Expires=Wed, 09 Jun 2021 ... date values.
    parts = re.split(r",(?=\s*[A-Za-z0-9_\-]+=)", raw)
    return [p.strip() for p in parts if p.strip()]


def _check_samesite(cookies: list) -> list:
    findings = []
    for c in cookies:
        name = c.split("=", 1)[0].strip() or "?"
        low = c.lower()
        secure = "secure" in low
        m = re.search(r"samesite\s*=\s*(\w+)", low)
        check = f"Cookie '{name}' SameSite"
        if not m:
            findings.append(CSRFFinding(
                check,
                "No SameSite attribute — cookie is sent on cross-site requests "
                "(CSRF risk).", "warn"))
            continue
        val = m.group(1)
        if val == "none" and not secure:
            findings.append(CSRFFinding(
                check, "SameSite=None without Secure — sent cross-site over any "
                "scheme.", "high"))
        elif val == "none":
            findings.append(CSRFFinding(
                check, "SameSite=None (Secure) — relies on other CSRF defences.",
                "info"))
        elif val == "lax":
            findings.append(CSRFFinding(
                check, "SameSite=Lax — reasonable default protection.", "ok"))
        elif val == "strict":
            findings.append(CSRFFinding(
                check, "SameSite=Strict — strong protection.", "ok"))
        else:
            findings.append(CSRFFinding(
                check, f"SameSite={val} — unrecognised value.", "warn"))
    return findings


def _check_token(body: str) -> list:
    forms = _FORM_RE.findall(body or "")
    if not forms:
        return [CSRFFinding("Anti-CSRF token", "No <form> elements found on the "
                            "page.", "info")]
    findings = []
    for i, form in enumerate(forms, 1):
        if _TOKEN_NAME_RE.search(form):
            findings.append(CSRFFinding(
                f"Form #{i} token", "Hidden anti-CSRF token field present.", "ok"))
        else:
            findings.append(CSRFFinding(
                f"Form #{i} token",
                "No anti-CSRF token field detected — form may be CSRF-able.",
                "warn"))
    return findings


# ── Public interface ──────────────────────────────────────────────────────────

def analyse(url: str, timeout: int = 10) -> list:
    resp = send("GET", url, timeout=timeout)
    if resp.error:
        return [CSRFFinding("Request", resp.error, "high")]

    findings = []
    cookies = _split_cookies(_get_header(resp.headers, "Set-Cookie"))
    if cookies:
        findings.extend(_check_samesite(cookies))
    else:
        findings.append(CSRFFinding(
            "Cookies", "No Set-Cookie headers returned by this URL.", "info"))

    findings.extend(_check_token(resp.body))
    findings.extend(_check_origin(url, timeout))
    return findings


def _check_origin(url: str, timeout: int) -> list:
    """Resend as POST with a foreign Origin/Referer; report acceptance (info)."""
    resp = send("POST", url,
                headers={"Origin": _ORIGIN_SPOOF, "Referer": _ORIGIN_SPOOF + "/"},
                timeout=timeout, follow_redirects=False)
    if resp.error:
        return [CSRFFinding("Origin/Referer check",
                            "Could not complete the cross-origin probe.", "info")]
    if 200 <= resp.status_code < 400:
        return [CSRFFinding(
            "Origin/Referer check",
            f"POST with a foreign Origin returned {resp.status_code} — the server "
            "may not validate Origin/Referer (informational).", "info")]
    return [CSRFFinding(
        "Origin/Referer check",
        f"POST with a foreign Origin returned {resp.status_code} — the server may "
        "reject cross-origin writes.", "ok")]
