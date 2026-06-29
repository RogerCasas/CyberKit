"""
CyberKit — Shared web-injection helper tests (no network)

Run: python tests/test_web_injection.py
"""

import io
import sys
import os
from urllib.parse import unquote, parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from app.modules.web_injection import parse_params, inject


# ── parse_params ──────────────────────────────────────────────────────────────

def test_parse_params_extracts_multiple():
    params = parse_params("http://example.com/?id=1&name=test&page=2")
    assert set(params) == {"id", "name", "page"}
    print(f"  parse_params multiple → {params}: OK")


def test_parse_params_no_query_string():
    assert parse_params("http://example.com/page") == []
    print("  parse_params no query → []: OK")


# ── inject GET ────────────────────────────────────────────────────────────────

def test_inject_get_mutates_only_target_param():
    inj = inject("http://example.com/?id=1&name=test", "GET", "id", "PAYLOAD")
    assert inj["body"] == "", "GET body should be empty"
    decoded = unquote(inj["url"])
    assert "id=PAYLOAD" in decoded, "Target param must carry the payload"
    assert "name=test" in inj["url"], "Other params must be preserved"
    print(f"  inject GET → url={inj['url']!r}: OK")


def test_inject_get_preserves_all_other_params():
    inj = inject("http://example.com/?a=1&b=2&c=3", "GET", "b", "X")
    qs = parse_qs(urlparse(inj["url"]).query)
    assert qs["a"] == ["1"] and qs["c"] == ["3"], "Untouched params must remain"
    assert qs["b"] == ["X"], "Target param must be replaced"
    print(f"  inject GET preserve → {qs}: OK")


# ── inject POST ───────────────────────────────────────────────────────────────

def test_inject_post_moves_params_to_body():
    inj = inject("http://example.com/login?next=/home", "POST", "username", "admin")
    assert "?" not in inj["url"], "POST URL must have no query string"
    body = parse_qs(inj["body"])
    assert body["username"] == ["admin"], "Payload must be in the body"
    assert body["next"] == ["/home"], "Existing params must move to the body"
    print(f"  inject POST → body={inj['body']!r}: OK")


def test_inject_blank_value_param():
    inj = inject("http://example.com/?q=", "GET", "q", "PAYLOAD")
    decoded = unquote(inj["url"])
    assert "q=PAYLOAD" in decoded
    print(f"  inject blank-value → url={inj['url']!r}: OK")


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_parse_params_extracts_multiple,
        test_parse_params_no_query_string,
        test_inject_get_mutates_only_target_param,
        test_inject_get_preserves_all_other_params,
        test_inject_post_moves_params_to_body,
        test_inject_blank_value_param,
    ]
    passed = 0
    print(f"Running {len(tests)} web-injection tests...\n")
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
