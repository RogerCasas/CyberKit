"""
CyberKit — Open Redirect Detector engine tests (no network)

Run: python tests/test_open_redirect.py
"""

import io
import sys
import os
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from app.modules.open_redirect import (
    _is_external_redirect, _get_header, build_payloads, scan, SENTINEL,
)
from app.modules.http_builder import RequestResult


# ── _is_external_redirect ─────────────────────────────────────────────────────

def test_absolute_sentinel_external():
    assert _is_external_redirect(f"https://{SENTINEL}/path")
    print("  absolute https sentinel → external: OK")


def test_scheme_relative_external():
    assert _is_external_redirect(f"//{SENTINEL}")
    print("  scheme-relative //sentinel → external: OK")


def test_backslash_external():
    assert _is_external_redirect(f"/\\{SENTINEL}")
    print("  backslash /\\sentinel → external: OK")


def test_scheme_without_slashes_external():
    assert _is_external_redirect(f"https:{SENTINEL}")
    print("  https:sentinel (no slashes) → external: OK")


def test_suffix_bypass_external():
    assert _is_external_redirect(f"https://target.com.{SENTINEL}")
    print("  suffix-bypass host → external: OK")


def test_same_origin_not_external():
    assert not _is_external_redirect("https://example.com/dashboard")
    print("  same-origin Location → not external: OK")


def test_relative_path_not_external():
    assert not _is_external_redirect("/account/home")
    print("  relative path → not external: OK")


def test_empty_location_not_external():
    assert not _is_external_redirect("")
    print("  empty Location → not external: OK")


# ── header lookup + payloads ──────────────────────────────────────────────────

def test_get_header_case_insensitive():
    assert _get_header({"location": "x"}, "Location") == "x"
    assert _get_header({"LOCATION": "y"}, "location") == "y"
    print("  _get_header case-insensitive: OK")


def test_build_payloads_includes_suffix():
    payloads = build_payloads("victim.com")
    assert any(p == f"https://victim.com.{SENTINEL}" for p in payloads)
    assert any(p == f"//{SENTINEL}" for p in payloads)
    print(f"  build_payloads → {len(payloads)} payloads incl. suffix: OK")


# ── scan integration ──────────────────────────────────────────────────────────

def test_scan_flags_external_302():
    def mock_send(method, url, body="", timeout=10, follow_redirects=True, **kw):
        assert follow_redirects is False, "Open Redirect must disable redirects"
        return RequestResult(status_code=302, headers={"Location": f"https://{SENTINEL}/"})

    with patch("app.modules.open_redirect.send", side_effect=mock_send):
        results = scan("http://example.com/?next=/home", "GET", ["next"])
    assert any(r.is_vulnerable for r in results)
    print("  scan external 302 → vulnerable (redirects disabled): OK")


def test_scan_same_origin_not_flagged():
    with patch("app.modules.open_redirect.send",
               return_value=RequestResult(status_code=302,
                                          headers={"Location": "https://example.com/home"})):
        results = scan("http://example.com/?next=/home", "GET", ["next"])
    assert not any(r.is_vulnerable for r in results)
    print("  scan same-origin 302 → not flagged: OK")


def test_scan_no_redirect_not_flagged():
    with patch("app.modules.open_redirect.send",
               return_value=RequestResult(status_code=200, body="ok")):
        results = scan("http://example.com/?next=/home", "GET", ["next"])
    assert not any(r.is_vulnerable for r in results)
    print("  scan 200 no-redirect → not flagged: OK")


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_absolute_sentinel_external,
        test_scheme_relative_external,
        test_backslash_external,
        test_scheme_without_slashes_external,
        test_suffix_bypass_external,
        test_same_origin_not_external,
        test_relative_path_not_external,
        test_empty_location_not_external,
        test_get_header_case_insensitive,
        test_build_payloads_includes_suffix,
        test_scan_flags_external_302,
        test_scan_same_origin_not_flagged,
        test_scan_no_redirect_not_flagged,
    ]
    passed = 0
    print(f"Running {len(tests)} Open Redirect tests...\n")
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
