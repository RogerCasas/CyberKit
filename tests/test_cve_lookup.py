"""
CyberKit — CVE / Vulnerability Lookup engine tests

Run: python tests/test_cve_lookup.py
All tests use fixture JSON — no network calls.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.modules.cve_lookup import _parse_response, _severity_from_score, CveEntry

# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_vuln(cve_id: str, score: float, description: str = "A vulnerability.",
               published: str = "2024-01-15T00:00:00.000") -> dict:
    """Build a minimal NVD-shaped vulnerability dict."""
    return {
        "cve": {
            "id": cve_id,
            "published": published,
            "descriptions": [{"lang": "en", "value": description}],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {"baseScore": score}
                }]
            },
        }
    }


NVD_RESPONSE_3_ENTRIES = {
    "totalResults": 3,
    "vulnerabilities": [
        _make_vuln("CVE-2024-0001", 7.5, "High severity buffer overflow."),
        _make_vuln("CVE-2024-0002", 9.8, "Critical RCE vulnerability."),
        _make_vuln("CVE-2024-0003", 4.3, "Medium CSRF issue."),
    ],
}

NVD_RESPONSE_EMPTY = {
    "totalResults": 0,
    "vulnerabilities": [],
}

NVD_RESPONSE_V2_ONLY = {
    "totalResults": 1,
    "vulnerabilities": [{
        "cve": {
            "id": "CVE-2020-0001",
            "published": "2020-03-10T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "Old CVSSv2 entry."}],
            "metrics": {
                "cvssMetricV2": [{
                    "cvssData": {"baseScore": 6.4}
                }]
            },
        }
    }],
}


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_parse_response():
    """Fixture response produces correct CVE ID, score, severity, description."""
    total, entries = _parse_response(NVD_RESPONSE_3_ENTRIES)
    assert total == 3, f"Expected totalResults=3, got {total}"
    assert len(entries) == 3, f"Expected 3 entries, got {len(entries)}"

    # After sorting, first entry should be the critical one (9.8)
    top = entries[0]
    assert top.cve_id == "CVE-2024-0002", f"Top entry should be CVE-2024-0002, got {top.cve_id}"
    assert top.cvss_score == 9.8, f"Expected score 9.8, got {top.cvss_score}"
    assert top.severity == "CRITICAL", f"Expected CRITICAL, got {top.severity}"
    assert "RCE" in top.description, f"Description should mention RCE: {top.description}"
    assert top.published == "2024-01-15", f"Published should be YYYY-MM-DD: {top.published}"
    print(f"  parse_response: top={top.cve_id} score={top.cvss_score} severity={top.severity}: OK")


def test_severity_bands():
    """All five severity bands resolve correctly from scores."""
    assert _severity_from_score(9.5) == "CRITICAL", "9.5 → CRITICAL"
    assert _severity_from_score(8.0) == "HIGH",     "8.0 → HIGH"
    assert _severity_from_score(5.5) == "MEDIUM",   "5.5 → MEDIUM"
    assert _severity_from_score(2.0) == "LOW",      "2.0 → LOW"
    assert _severity_from_score(0.0) == "NONE",     "0.0 → NONE"
    print("  severity_bands: CRITICAL/HIGH/MEDIUM/LOW/NONE all correct: OK")


def test_sorted_descending():
    """3 entries at different scores are ordered highest-first."""
    _, entries = _parse_response(NVD_RESPONSE_3_ENTRIES)
    scores = [e.cvss_score for e in entries]
    assert scores == sorted(scores, reverse=True), (
        f"Entries not sorted descending: {scores}"
    )
    print(f"  sorted_descending: scores={scores}: OK")


def test_empty_vulnerabilities():
    """Empty vulnerabilities list produces zero entries without raising."""
    total, entries = _parse_response(NVD_RESPONSE_EMPTY)
    assert total == 0,   f"Expected total=0, got {total}"
    assert entries == [], f"Expected empty list, got {entries}"
    print("  empty_vulnerabilities: OK")


def test_cvss_v2_fallback():
    """When only CVSSv2 metrics are present, score is extracted correctly."""
    total, entries = _parse_response(NVD_RESPONSE_V2_ONLY)
    assert len(entries) == 1
    assert entries[0].cvss_score == 6.4, f"Expected 6.4 from v2 metric, got {entries[0].cvss_score}"
    assert entries[0].severity == "MEDIUM"
    print(f"  cvss_v2_fallback: score={entries[0].cvss_score} severity={entries[0].severity}: OK")


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_parse_response,
        test_severity_bands,
        test_sorted_descending,
        test_empty_vulnerabilities,
        test_cvss_v2_fallback,
    ]
    passed = 0
    print(f"Running {len(tests)} CVE Lookup tests…\n")
    for t in tests:
        try:
            t()
            passed += 1
        except AssertionError as e:
            print(f"  FAIL {t.__name__}: {e}")
        except Exception as e:
            import traceback
            print(f"  ERROR {t.__name__}: {e}")
            traceback.print_exc()
    print(f"\n{passed}/{len(tests)} tests passed")
    sys.exit(0 if passed == len(tests) else 1)
