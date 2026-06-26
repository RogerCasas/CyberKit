"""
CyberKit — HTTP Builder engine tests (no network)

Run: python tests/test_http_builder.py
"""

import io
import sys
import os
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import requests
from app.modules.http_builder import send, RequestResult


# ── Helpers ───────────────────────────────────────────────────────────────────

def _mock_response(status_code=200, reason="OK", headers=None, text="hello"):
    resp = MagicMock()
    resp.status_code = status_code
    resp.reason = reason
    resp.headers = headers or {"Content-Type": "text/html"}
    resp.text = text
    return resp


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_successful_get_populates_all_fields():
    mock_resp = _mock_response(
        status_code=200, reason="OK",
        headers={"Content-Type": "application/json", "X-Custom": "value"},
        text='{"key": "value"}',
    )
    with patch("app.modules.http_builder.requests.request", return_value=mock_resp):
        result = send("GET", "http://example.com/api")

    assert result.error == "", f"Expected no error, got: {result.error!r}"
    assert result.status_code == 200
    assert result.reason == "OK"
    assert result.body == '{"key": "value"}'
    assert result.headers["Content-Type"] == "application/json"
    assert result.elapsed_ms >= 0
    print(f"  successful GET → status={result.status_code}, body len={len(result.body)}: OK")


def test_connection_error_populates_error_field():
    with patch("app.modules.http_builder.requests.request",
               side_effect=requests.ConnectionError("connection refused")):
        result = send("GET", "http://192.0.2.1/")

    assert result.error != "", "Expected error field to be non-empty"
    assert result.status_code == 0
    assert "connection" in result.error.lower()
    print(f"  connection error → error={result.error!r}: OK")


def test_invalid_url_no_scheme():
    result = send("GET", "example.com/path")

    assert result.error != "", "Expected error for URL without scheme"
    assert result.status_code == 0
    assert "http" in result.error.lower()
    print(f"  no-scheme URL → error={result.error!r}: OK")


if __name__ == "__main__":
    tests = [
        test_successful_get_populates_all_fields,
        test_connection_error_populates_error_field,
        test_invalid_url_no_scheme,
    ]
    passed = 0
    print(f"Running {len(tests)} HTTP Builder tests...\n")
    for t in tests:
        try:
            t()
            passed += 1
        except AssertionError as e:
            print(f"  FAIL {t.__name__}: {e}")
        except Exception as e:
            print(f"  ERROR {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} tests passed")
    sys.exit(0 if passed == len(tests) else 1)
