"""
CyberKit — Header Analyser engine tests (no network)

Run: python tests/test_header_analyser.py
"""

import io
import sys
import os
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from app.modules.header_analyser import (
    HeaderFinding,
    HeaderRule,
    HEADER_RULES,
    analyse,
    compute_grade,
    _check_csp,
    _check_hsts,
    _check_xfo,
    _check_xcto,
    _check_rp,
    _check_pp,
    STATUS_OK,
    STATUS_WARN,
    STATUS_MISSING,
    STATUS_SKIPPED,
    STATUS_INFO,
)


def _make_findings(header_map: dict) -> list[HeaderFinding]:
    """Build a finding list from a {lowercase_name: value_or_None} dict."""
    findings = []
    is_https = not header_map.get("__http__", False)
    for rule in HEADER_RULES:
        raw = header_map.get(rule.name)
        if rule.name == "strict-transport-security":
            from app.modules.header_analyser import _check_hsts
            status, score, tip = _check_hsts(raw, is_https)
        else:
            status, score, tip = rule.check_fn(raw)
        findings.append(HeaderFinding(rule=rule, raw_value=raw,
                                      status=status, tip=tip, score=score))
    return findings


def test_all_headers_present_gives_a_plus():
    headers = {
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=()",
    }
    findings = _make_findings(headers)
    letter, score, max_score = compute_grade(findings)
    assert letter in ("A+", "A"), f"Expected A+ or A with all headers, got {letter}"
    assert score == max_score, f"Expected full score {max_score}, got {score}"
    print(f"✓ All headers present → {letter} ({score}/{max_score})")


def test_no_headers_gives_f():
    headers = {}  # all missing (https=True by default)
    findings = _make_findings(headers)
    letter, score, _ = compute_grade(findings)
    assert letter == "F", f"Expected F with no headers, got {letter}"
    assert score == 0
    print(f"✓ No headers → F (0 pts)")


def test_hsts_skipped_on_http():
    headers = {
        "__http__": True,  # trigger http path
        "strict-transport-security": "max-age=31536000",  # present but should be skipped
    }
    findings = _make_findings(headers)
    hsts = next(f for f in findings if f.rule.name == "strict-transport-security")
    assert hsts.status == STATUS_SKIPPED, f"HSTS should be skipped on HTTP, got {hsts.status}"
    assert hsts.score == 0
    print("✓ HSTS is skipped on HTTP target")


def test_csp_with_unsafe_inline_is_warn():
    status, score, tip = _check_csp("default-src 'self'; script-src 'unsafe-inline'")
    assert status == STATUS_WARN, f"Expected warn for unsafe-inline CSP, got {status}"
    assert 0 < score < 25
    print(f"✓ CSP with unsafe-inline → warn ({score} pts)")


def test_csp_missing_is_missing():
    status, score, tip = _check_csp(None)
    assert status == STATUS_MISSING
    assert score == 0
    print("✓ Missing CSP → missing (0 pts)")


def test_xcto_nosniff_is_ok():
    status, score, tip = _check_xcto("nosniff")
    assert status == STATUS_OK
    assert score == 15
    print("✓ X-Content-Type-Options: nosniff → ok (15 pts)")


def test_xcto_wrong_value_is_warn():
    status, score, tip = _check_xcto("something-else")
    assert status == STATUS_WARN
    assert score < 15
    print("✓ X-Content-Type-Options with wrong value → warn")


def test_info_leak_headers_do_not_affect_grade():
    headers = {
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=31536000",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=()",
        "server": "Apache/2.4.51",
        "x-powered-by": "PHP/8.1",
    }
    findings_with_leak  = _make_findings(headers)
    headers_clean = {k: v for k, v in headers.items()
                     if k not in ("server", "x-powered-by")}
    findings_clean = _make_findings(headers_clean)

    _, score_leak,  max_leak  = compute_grade(findings_with_leak)
    _, score_clean, max_clean = compute_grade(findings_clean)

    assert score_leak == score_clean, \
        "Info-leak headers should not change the score"
    assert max_leak == max_clean
    print("✓ Info-leak headers do not affect grade score")


def test_warning_score_partial():
    status, score, tip = _check_csp("default-src 'self'; script-src 'unsafe-eval'")
    assert status == STATUS_WARN
    assert 0 < score < 25, f"Warn score should be partial credit, got {score}"
    print(f"✓ Warning finding gives partial credit ({score} pts < 25 pts)")


if __name__ == "__main__":
    tests = [
        test_all_headers_present_gives_a_plus,
        test_no_headers_gives_f,
        test_hsts_skipped_on_http,
        test_csp_with_unsafe_inline_is_warn,
        test_csp_missing_is_missing,
        test_xcto_nosniff_is_ok,
        test_xcto_wrong_value_is_warn,
        test_info_leak_headers_do_not_affect_grade,
        test_warning_score_partial,
    ]
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except AssertionError as e:
            print(f"✗ {t.__name__}: {e}")
        except Exception as e:
            print(f"✗ {t.__name__}: unexpected error — {e}")

    print(f"\n{passed}/{len(tests)} tests passed")
    sys.exit(0 if passed == len(tests) else 1)
