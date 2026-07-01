"""
CyberKit — CVE / Vulnerability Lookup Engine

Queries the NIST NVD REST API v2 by keyword (product + version) and
returns CVE entries sorted by CVSS score descending.

Rate limit: 5 requests / 30 s without an API key.
We enforce a 6-second inter-query sleep (per ADR-006).
"""

import threading
import time
from dataclasses import dataclass, field

import requests


@dataclass
class CveEntry:
    cve_id:      str
    cvss_score:  float   # v3.1 base score preferred; v2 fallback; 0.0 if absent
    severity:    str     # CRITICAL / HIGH / MEDIUM / LOW / NONE
    description: str
    published:   str


@dataclass
class CveResult:
    product:       str
    version:       str
    total_results: int
    entries:       list[CveEntry]  # sorted by cvss_score descending
    error:         str             # empty if successful


# ── Parsing helpers (pure functions, testable without network) ────────────────

def _severity_from_score(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score >  0.0: return "LOW"
    return "NONE"


def _extract_cvss(metrics: dict) -> float:
    """Extract the best available CVSS base score from a metrics dict."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key, [])
        if entries:
            try:
                return float(entries[0]["cvssData"]["baseScore"])
            except (KeyError, IndexError, TypeError, ValueError):
                pass
    entries = metrics.get("cvssMetricV2", [])
    if entries:
        try:
            return float(entries[0]["cvssData"]["baseScore"])
        except (KeyError, IndexError, TypeError, ValueError):
            pass
    return 0.0


def _parse_response(json_dict: dict) -> tuple[int, list[CveEntry]]:
    """
    Parse an NVD API v2 response dict into (total_results, entries).
    Pure function — safe to call from tests with fixture data.
    """
    total = int(json_dict.get("totalResults", 0))
    entries: list[CveEntry] = []

    for vuln in json_dict.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id    = cve.get("id", "")
        published = cve.get("published", "")[:10]  # YYYY-MM-DD

        # Description (prefer English)
        description = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description:
            descs = cve.get("descriptions", [])
            description = descs[0].get("value", "") if descs else ""

        metrics    = cve.get("metrics", {})
        cvss_score = _extract_cvss(metrics)
        severity   = _severity_from_score(cvss_score)

        entries.append(CveEntry(
            cve_id=cve_id,
            cvss_score=cvss_score,
            severity=severity,
            description=description,
            published=published,
        ))

    entries.sort(key=lambda e: e.cvss_score, reverse=True)
    return total, entries


# ── Public API ────────────────────────────────────────────────────────────────

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_HEADERS  = {"Accept": "application/json"}
_TIMEOUT  = 20
_RATE_SLEEP = 6  # seconds between requests (unauthenticated NVD limit)


def search(
    product: str,
    version: str,
    stop_event: threading.Event,
    on_progress: "Callable[[str], None] | None" = None,
) -> CveResult:
    """
    Query NVD for CVEs matching product + version.
    Sleeps _RATE_SLEEP seconds before the request (rate-limit compliance).
    Checks stop_event before sleeping and before the request.
    Calls on_progress(message) with status updates if provided.
    Never raises.
    """
    keyword = f"{product} {version}".strip()

    def _notify(msg: str):
        if on_progress:
            on_progress(msg)

    if stop_event.is_set():
        return CveResult(product=product, version=version,
                         total_results=0, entries=[], error="Stopped")

    # Visible rate-limit countdown
    for remaining in range(_RATE_SLEEP, 0, -1):
        if stop_event.is_set():
            return CveResult(product=product, version=version,
                             total_results=0, entries=[], error="Stopped")
        _notify(f"Querying NVD… rate limit cooldown: {remaining}s")
        time.sleep(1)

    if stop_event.is_set():
        return CveResult(product=product, version=version,
                         total_results=0, entries=[], error="Stopped")

    _notify("Sending request to NIST NVD…")
    try:
        resp = requests.get(
            _NVD_URL,
            params={"keywordSearch": keyword, "resultsPerPage": 20},
            headers=_HEADERS,
            timeout=_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.Timeout:
        return CveResult(product=product, version=version,
                         total_results=0, entries=[],
                         error="Request timed out — NVD API may be slow")
    except Exception as exc:
        return CveResult(product=product, version=version,
                         total_results=0, entries=[], error=str(exc))

    _notify("Parsing results…")
    total, entries = _parse_response(data)
    return CveResult(
        product=product,
        version=version,
        total_results=total,
        entries=entries,
        error="",
    )
