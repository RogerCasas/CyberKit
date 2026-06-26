"""
CyberKit — SQL Injection Tester engine (detection only, no data extraction)
"""

import re
from dataclasses import dataclass
from urllib.parse import urlparse, urlencode, parse_qs

from app.modules.http_builder import send


@dataclass
class InjectionResult:
    parameter: str
    payload: str
    detection_type: str   # "error-based" | "boolean-based"
    evidence: str
    is_vulnerable: bool


# ── DB error string patterns ──────────────────────────────────────────────────

_ERROR_PATTERNS = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning:.*mysql",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    # MSSQL
    r"microsoft sql server",
    r"microsoft ole db provider for sql server",
    r"incorrect syntax near",
    r"mssql_query\(\)",
    # Oracle
    r"ora-\d{5}",
    r"oracle.*driver",
    r"warning.*oci_",
    # PostgreSQL
    r"pg_query\(\)",
    r"pg_exec\(\)",
    r"postgresql.*error",
    r"unterminated quoted string at or near",
    # SQLite
    r"sqlite_error",
    r"sqlite3\.operationalerror",
    r"unrecognized token",
]

_COMPILED = [re.compile(p, re.IGNORECASE) for p in _ERROR_PATTERNS]

ERROR_PAYLOADS = [
    "'",    # unclosed single quote
    '"',    # unclosed double quote (MySQL ANSI_QUOTES, generic)
    "\\",   # backslash escape (MySQL)
    "')",   # quote + close paren (bracketed WHERE clause)
]

BOOLEAN_PROBE_SETS = [
    # (true_payload, false_payload, label)
    ("' AND 1=1--",    "' AND 1=2--",    "AND (string)"),
    (" AND 1=1",       " AND 1=2",       "AND (numeric)"),
    ("' OR '1'='1'--", "' OR '1'='2'--", "OR (string)"),
    ("') AND ('1'='1", "') AND ('1'='2", "AND (bracket)"),
    ("' OR 1=1--",     "' OR 1=2--",     "OR (numeric)"),
]
BOOL_THRESHOLD = 0.20  # 20% content-length diff → boolean injection


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
        params = _parse_params(url)

    results = []
    for idx, param in enumerate(params):
        if stop_event and stop_event.is_set():
            break

        err_result = _probe_error(url, method, param, timeout)
        results.append(err_result)
        if result_cb:
            result_cb(err_result)

        if not err_result.is_vulnerable:
            bool_result = _probe_boolean(url, method, param, timeout)
            results.append(bool_result)
            if result_cb:
                result_cb(bool_result)

        if progress_cb:
            progress_cb(idx + 1, len(params))

    return results


# ── Helpers exported for unit tests ──────────────────────────────────────────

def _check_error_patterns(body: str) -> tuple:
    """Return (is_matched, evidence_snippet)."""
    body_lower = body.lower()
    for pattern in _COMPILED:
        m = pattern.search(body_lower)
        if m:
            evidence = body[max(0, m.start() - 30): m.end() + 30].strip()
            return True, evidence[:120]
    return False, ""


def _parse_params(url: str) -> list:
    return list(parse_qs(urlparse(url).query).keys())


# ── Internal probes ───────────────────────────────────────────────────────────

def _probe_error(url, method, param, timeout):
    for payload in ERROR_PAYLOADS:
        inj = _inject(url, method, param, payload)
        resp = send(method, inj["url"], body=inj["body"], timeout=timeout)
        matched, evidence = _check_error_patterns(resp.body)
        if matched:
            return InjectionResult(
                parameter=param, payload=payload,
                detection_type="error-based", evidence=evidence,
                is_vulnerable=True,
            )
    return InjectionResult(
        parameter=param, payload=f"{len(ERROR_PAYLOADS)} payloads",
        detection_type="error-based", evidence="", is_vulnerable=False,
    )


def _probe_boolean(url, method, param, timeout, probe_sets=None):
    if probe_sets is None:
        probe_sets = BOOLEAN_PROBE_SETS

    baseline = send(method, url, timeout=timeout)
    b_len = len(baseline.body)

    for true_payload, false_payload, label in probe_sets:
        true_inj  = _inject(url, method, param, true_payload)
        false_inj = _inject(url, method, param, false_payload)
        resp_true  = send(method, true_inj["url"],  body=true_inj["body"],  timeout=timeout)
        resp_false = send(method, false_inj["url"], body=false_inj["body"], timeout=timeout)

        t_len = len(resp_true.body)
        f_len = len(resp_false.body)

        if b_len < 10 or t_len == 0:
            continue

        t_diff = abs(t_len - b_len) / b_len
        f_diff = abs(f_len - b_len) / b_len

        if t_diff < BOOL_THRESHOLD and f_diff >= BOOL_THRESHOLD:
            evidence = (
                f"[{label}] baseline={b_len}B, "
                f"true={t_len}B (Δ{t_diff:.0%}), "
                f"false={f_len}B (Δ{f_diff:.0%})"
            )
            return InjectionResult(
                parameter=param, payload=true_payload,
                detection_type="boolean-based", evidence=evidence, is_vulnerable=True,
            )

    return InjectionResult(
        parameter=param, payload=f"{len(probe_sets)} probe sets",
        detection_type="boolean-based", evidence="", is_vulnerable=False,
    )


def _inject(url: str, method: str, param: str, payload: str) -> dict:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [payload]

    if method.upper() == "GET":
        new_query = urlencode(qs, doseq=True)
        return {"url": parsed._replace(query=new_query).geturl(), "body": ""}
    else:
        flat = {k: v[0] if len(v) == 1 else v for k, v in qs.items()}
        return {"url": parsed._replace(query="").geturl(), "body": urlencode(flat)}
