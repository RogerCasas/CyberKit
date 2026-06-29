"""
CyberKit — Reflected XSS Tester engine tests (no network)

Run: python tests/test_xss_tester.py
"""

import io
import sys
import os
import html
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from app.modules.xss_tester import (
    _classify_reflection, _detect_context, _is_active, scan,
)
from app.modules.http_builder import RequestResult


# ── classify_reflection ───────────────────────────────────────────────────────

def test_raw_reflection_not_encoded():
    payload = "<script>ckABC123</script>"
    body = f"<html>hello {payload} world</html>"
    reflected, encoded = _classify_reflection(body, payload)
    assert reflected and not encoded
    print("  raw reflection → reflected, not encoded: OK")


def test_encoded_reflection_flagged_encoded():
    payload = "<script>ckABC123</script>"
    body = f"<html>{html.escape(payload, quote=True)}</html>"
    reflected, encoded = _classify_reflection(body, payload)
    assert reflected and encoded
    print("  encoded reflection → reflected, encoded: OK")


def test_no_reflection():
    payload = "<script>ckABC123</script>"
    reflected, encoded = _classify_reflection("nothing here", payload)
    assert not reflected and not encoded
    print("  no reflection → not reflected: OK")


def test_is_active():
    assert _is_active("<svg onload=x>")
    assert not _is_active("ckABC123")
    print("  is_active bracket detection: OK")


# ── context detection ─────────────────────────────────────────────────────────

def test_context_html():
    assert _detect_context("<div>ckM</div>", "ckM") == "html"
    print("  context html: OK")


def test_context_attribute():
    assert _detect_context('<input value="ckM">', "ckM") == "attribute"
    print("  context attribute: OK")


def test_context_script():
    assert _detect_context("<script>var x=ckM;</script>", "ckM") == "script"
    print("  context script: OK")


# ── scan integration ──────────────────────────────────────────────────────────

def test_scan_flags_raw_reflection():
    marker = "ckDEADBEEF1"

    def mock_send(method, url, body="", timeout=10, **kw):
        # Echo the injected payload back verbatim (vulnerable server).
        from urllib.parse import unquote
        return RequestResult(status_code=200, body="<html>" + unquote(url) + body + "</html>")

    with patch("app.modules.xss_tester.send", side_effect=mock_send):
        results = scan("http://example.com/?q=1", "GET", ["q"], marker=marker)
    assert any(r.is_vulnerable for r in results), "Raw echo should be flagged"
    print(f"  scan raw reflection → vulnerable={[r.is_vulnerable for r in results]}: OK")


def test_scan_safe_when_encoded():
    marker = "ckDEADBEEF2"

    def mock_send(method, url, body="", timeout=10, **kw):
        from urllib.parse import unquote
        echoed = unquote(url) + body
        return RequestResult(status_code=200, body="<html>" + html.escape(echoed, quote=True) + "</html>")

    with patch("app.modules.xss_tester.send", side_effect=mock_send):
        results = scan("http://example.com/?q=1", "GET", ["q"], marker=marker)
    assert not any(r.is_vulnerable for r in results), "Encoded echo must NOT be flagged"
    assert any(r.reflected and r.encoded for r in results), "Should note encoded reflection"
    print("  scan encoded reflection → not vulnerable, noted encoded: OK")


def test_scan_not_reflected():
    with patch("app.modules.xss_tester.send",
               return_value=RequestResult(status_code=200, body="static page")):
        results = scan("http://example.com/?q=1", "GET", ["q"], marker="ckNOPE12345")
    assert not any(r.is_vulnerable for r in results)
    assert not any(r.reflected for r in results)
    print("  scan no reflection → clean: OK")


def test_scan_stop_event_aborts():
    import threading
    ev = threading.Event()
    ev.set()
    with patch("app.modules.xss_tester.send",
               return_value=RequestResult(status_code=200, body="x")):
        results = scan("http://example.com/?a=1&b=2", "GET", ["a", "b"],
                       marker="ckSTOP00001", stop_event=ev)
    assert results == [], "Pre-set stop event should yield no results"
    print("  scan stop_event → aborts: OK")


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_raw_reflection_not_encoded,
        test_encoded_reflection_flagged_encoded,
        test_no_reflection,
        test_is_active,
        test_context_html,
        test_context_attribute,
        test_context_script,
        test_scan_flags_raw_reflection,
        test_scan_safe_when_encoded,
        test_scan_not_reflected,
        test_scan_stop_event_aborts,
    ]
    passed = 0
    print(f"Running {len(tests)} XSS Tester tests...\n")
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
