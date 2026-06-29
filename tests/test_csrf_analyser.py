"""
CyberKit — CSRF Analyser engine tests (no network)

Run: python tests/test_csrf_analyser.py
"""

import io
import sys
import os
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from app.modules.csrf_analyser import (
    _check_samesite, _check_token, _split_cookies, _get_header, analyse,
)
from app.modules.http_builder import RequestResult


def _sev(findings, check_substr):
    for f in findings:
        if check_substr.lower() in f.check.lower():
            return f.severity
    return None


# ── SameSite checks ───────────────────────────────────────────────────────────

def test_samesite_missing_warns():
    f = _check_samesite(["sid=abc; Path=/"])
    assert f[0].severity == "warn"
    print("  SameSite missing → warn: OK")


def test_samesite_none_without_secure_high():
    f = _check_samesite(["sid=abc; SameSite=None"])
    assert f[0].severity == "high"
    print("  SameSite=None without Secure → high: OK")


def test_samesite_none_with_secure_info():
    f = _check_samesite(["sid=abc; SameSite=None; Secure"])
    assert f[0].severity == "info"
    print("  SameSite=None; Secure → info: OK")


def test_samesite_strict_ok():
    f = _check_samesite(["sid=abc; SameSite=Strict"])
    assert f[0].severity == "ok"
    print("  SameSite=Strict → ok: OK")


def test_samesite_lax_ok():
    f = _check_samesite(["sid=abc; SameSite=Lax"])
    assert f[0].severity == "ok"
    print("  SameSite=Lax → ok: OK")


# ── token checks ──────────────────────────────────────────────────────────────

def test_form_with_token_ok():
    body = '<form><input type="hidden" name="csrf_token" value="x"></form>'
    f = _check_token(body)
    assert f[0].severity == "ok"
    print("  form with token → ok: OK")


def test_form_without_token_warns():
    body = '<form><input type="text" name="username"></form>'
    f = _check_token(body)
    assert f[0].severity == "warn"
    print("  form without token → warn: OK")


def test_authenticity_token_recognised():
    body = '<form><input name="authenticity_token" value="x"></form>'
    f = _check_token(body)
    assert f[0].severity == "ok"
    print("  authenticity_token recognised → ok: OK")


# ── multi-cookie split ────────────────────────────────────────────────────────

def test_split_multiple_cookies():
    raw = "a=1; SameSite=Lax, b=2; Secure; SameSite=None"
    cookies = _split_cookies(raw)
    assert len(cookies) == 2, f"expected 2 cookies, got {cookies}"
    findings = _check_samesite(cookies)
    assert len(findings) == 2
    print(f"  split multiple cookies → {len(findings)} findings: OK")


def test_split_preserves_expires_comma():
    raw = "sid=x; Expires=Wed, 09 Jun 2031 10:18:14 GMT; SameSite=Strict"
    cookies = _split_cookies(raw)
    assert len(cookies) == 1, f"Expires comma must not split the cookie, got {cookies}"
    print("  Expires comma not split → 1 cookie: OK")


# ── analyse integration ───────────────────────────────────────────────────────

def test_analyse_combines_checks():
    page = '<html><form><input name="user"></form></html>'

    def mock_send(method, url, headers=None, body="", timeout=10, follow_redirects=True):
        if method == "GET":
            return RequestResult(status_code=200,
                                 headers={"Set-Cookie": "sid=abc; Path=/"},
                                 body=page)
        return RequestResult(status_code=403)  # rejects foreign Origin

    with patch("app.modules.csrf_analyser.send", side_effect=mock_send):
        findings = analyse("http://example.com/login")

    assert _sev(findings, "SameSite") == "warn", "missing SameSite should warn"
    assert _sev(findings, "token") == "warn", "tokenless form should warn"
    assert _sev(findings, "Origin/Referer") == "ok", "403 on foreign Origin → ok"
    print(f"  analyse combines {len(findings)} findings: OK")


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_samesite_missing_warns,
        test_samesite_none_without_secure_high,
        test_samesite_none_with_secure_info,
        test_samesite_strict_ok,
        test_samesite_lax_ok,
        test_form_with_token_ok,
        test_form_without_token_warns,
        test_authenticity_token_recognised,
        test_split_multiple_cookies,
        test_split_preserves_expires_comma,
        test_analyse_combines_checks,
    ]
    passed = 0
    print(f"Running {len(tests)} CSRF Analyser tests...\n")
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
