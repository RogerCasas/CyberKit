"""
CyberKit — SQL Injection Tester engine tests (no network)

Run: python tests/test_sqli_tester.py
"""

import io
import sys
import os
from unittest.mock import patch
from urllib.parse import unquote

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from app.modules.sqli_tester import (
    _check_error_patterns, _probe_boolean, _probe_error,
    _parse_params, _inject, scan,
)
from app.modules.http_builder import RequestResult


# ── Group A: error pattern matching ──────────────────────────────────────────

def test_mysql_error_detected():
    body = "You have an error in your SQL syntax near '' at line 1"
    matched, evidence = _check_error_patterns(body)
    assert matched, "Expected MySQL error string to be detected"
    assert evidence != ""
    print(f"  MySQL error detected → evidence={evidence!r}: OK")


def test_mssql_error_detected():
    body = "Microsoft SQL Server error 102: Incorrect syntax near ''"
    matched, evidence = _check_error_patterns(body)
    assert matched, "Expected MSSQL error string to be detected"
    print(f"  MSSQL error detected → evidence={evidence!r}: OK")


def test_oracle_error_detected():
    body = "ORA-00907: missing right parenthesis"
    matched, evidence = _check_error_patterns(body)
    assert matched, "Expected Oracle ORA- error to be detected"
    print(f"  Oracle error detected → evidence={evidence!r}: OK")


def test_postgresql_error_detected():
    body = "unterminated quoted string at or near \"'\" LINE 1: SELECT * FROM users WHERE id = '''"
    matched, evidence = _check_error_patterns(body)
    assert matched, "Expected PostgreSQL error string to be detected"
    print(f"  PostgreSQL error detected → evidence={evidence!r}: OK")


def test_sqlite_error_detected():
    body = "sqlite3.OperationalError: unrecognized token: \"'1\""
    matched, evidence = _check_error_patterns(body)
    assert matched, "Expected SQLite error string to be detected"
    print(f"  SQLite error detected → evidence={evidence!r}: OK")


def test_clean_response_not_flagged():
    body = "Welcome to the site! Everything is fine here."
    matched, evidence = _check_error_patterns(body)
    assert not matched, "Expected clean response to not be flagged"
    assert evidence == ""
    print("  clean response → not flagged: OK")


# ── Group B: boolean probe detection ─────────────────────────────────────────

def _make_length_mock(baseline_body, true_body, false_body):
    call_count = [0]

    def mock_send(method, url, body="", timeout=10, **kw):
        n = call_count[0]
        call_count[0] += 1
        if n == 0:
            return RequestResult(status_code=200, body=baseline_body)
        elif n == 1:
            return RequestResult(status_code=200, body=true_body)
        else:
            return RequestResult(status_code=200, body=false_body)

    return mock_send


def test_boolean_AND_string_detected():
    base = "Welcome to the site! Here are your results." * 3
    mock = _make_length_mock(base, base, "")
    with patch("app.modules.sqli_tester.send", side_effect=mock):
        result = _probe_boolean(
            "http://example.com/?id=1", "GET", "id", timeout=5,
            probe_sets=[("' AND 1=1--", "' AND 1=2--", "AND (string)")],
        )
    assert result.is_vulnerable, "Expected AND (string) boolean to be detected"
    assert result.detection_type == "boolean-based"
    assert "AND (string)" in result.evidence
    print(f"  boolean AND (string) detected → evidence={result.evidence!r}: OK")


def test_boolean_AND_numeric_detected():
    base = "Product listing for category 3." * 5
    mock = _make_length_mock(base, base, "No results found.")
    with patch("app.modules.sqli_tester.send", side_effect=mock):
        result = _probe_boolean(
            "http://example.com/?cat=3", "GET", "cat", timeout=5,
            probe_sets=[(" AND 1=1", " AND 1=2", "AND (numeric)")],
        )
    assert result.is_vulnerable, "Expected AND (numeric) boolean to be detected"
    assert "AND (numeric)" in result.evidence
    print(f"  boolean AND (numeric) detected → evidence={result.evidence!r}: OK")


def test_boolean_OR_string_detected():
    base = "Your search returned 3 results for 'admin'." * 4
    mock = _make_length_mock(base, base, "Your search returned 0 results.")
    with patch("app.modules.sqli_tester.send", side_effect=mock):
        result = _probe_boolean(
            "http://example.com/?q=admin", "GET", "q", timeout=5,
            probe_sets=[("' OR '1'='1'--", "' OR '1'='2'--", "OR (string)")],
        )
    assert result.is_vulnerable, "Expected OR (string) boolean to be detected"
    assert "OR (string)" in result.evidence
    print(f"  boolean OR (string) detected → evidence={result.evidence!r}: OK")


def test_boolean_same_length_not_flagged():
    base = "Normal response page with standard content." * 2
    mock = _make_length_mock(base, base, base)
    with patch("app.modules.sqli_tester.send", side_effect=mock):
        result = _probe_boolean(
            "http://example.com/?id=1", "GET", "id", timeout=5,
            probe_sets=[("' AND 1=1--", "' AND 1=2--", "AND (string)")],
        )
    assert not result.is_vulnerable, "Expected identical-length responses to not be flagged"
    print("  boolean same-length responses → not flagged: OK")


# ── Group C: _probe_error multi-payload ───────────────────────────────────────

def test_probe_error_detects_on_second_payload():
    """Engine tries all payloads; stops at first match even if first payload is clean."""
    call_count = [0]

    def mock_send(method, url, body="", timeout=10, **kw):
        n = call_count[0]
        call_count[0] += 1
        if n == 0:
            return RequestResult(status_code=200, body="Normal response")
        return RequestResult(status_code=200, body="Microsoft SQL Server syntax error")

    with patch("app.modules.sqli_tester.send", side_effect=mock_send):
        result = _probe_error("http://example.com/?id=1", "GET", "id", timeout=5)

    assert result.is_vulnerable
    assert result.detection_type == "error-based"
    assert call_count[0] == 2, "Should have stopped after the second payload matched"
    print(f"  error-based stops on 2nd payload → payload={result.payload!r}: OK")


def test_probe_error_clean_when_no_match():
    with patch("app.modules.sqli_tester.send",
               return_value=RequestResult(status_code=200, body="Normal response")):
        result = _probe_error("http://example.com/?id=1", "GET", "id", timeout=5)
    assert not result.is_vulnerable
    assert result.detection_type == "error-based"
    print("  error-based all-clean → not vulnerable: OK")


# ── Group D: _inject mechanics ────────────────────────────────────────────────

def test_inject_GET_modifies_query_string():
    original = "http://example.com/?id=1&name=test"
    inj = _inject(original, "GET", "id", "'")
    assert inj["url"] != original, "URL should be modified"
    assert inj["body"] == "", "GET should have empty body"
    decoded = unquote(inj["url"])
    assert "id='" in decoded, "Injected quote should appear in query string"
    assert "name=test" in inj["url"], "Other params must be preserved"
    print(f"  _inject GET → url={inj['url']!r}: OK")


def test_inject_POST_builds_body():
    inj = _inject("http://example.com/login", "POST", "username", "'")
    assert inj["body"] != "", "POST should have non-empty body"
    assert "username" in inj["body"], "Param name must appear in body"
    assert "?" not in inj["url"], "POST URL should have no query string"
    print(f"  _inject POST → body={inj['body']!r}: OK")


# ── Group E: _parse_params ────────────────────────────────────────────────────

def test_parse_params_extracts_multiple():
    params = _parse_params("http://example.com/?id=1&name=test&page=2")
    assert set(params) == {"id", "name", "page"}
    print(f"  _parse_params → {params}: OK")


def test_parse_params_no_query_string():
    params = _parse_params("http://example.com/page")
    assert params == []
    print("  _parse_params empty URL → []: OK")


# ── Group F: scan() integration ───────────────────────────────────────────────

def test_scan_detects_error_based_injection():
    error_body = "You have an error in your SQL syntax near '1' at line 1"
    with patch("app.modules.sqli_tester.send",
               return_value=RequestResult(status_code=200, body=error_body)):
        results = scan("http://example.com/?id=1", "GET", ["id"], timeout=5)
    vuln = [r for r in results if r.is_vulnerable]
    assert len(vuln) >= 1
    assert vuln[0].detection_type == "error-based"
    print(f"  scan() error-based injection → {len(vuln)} vulnerable result(s): OK")


def test_scan_auto_parses_params_from_url():
    clean_body = "Normal response body with no database errors present."
    with patch("app.modules.sqli_tester.send",
               return_value=RequestResult(status_code=200, body=clean_body)):
        results = scan("http://example.com/?id=1&name=test", "GET", [], timeout=5)
    tested = {r.parameter for r in results}
    assert "id" in tested
    assert "name" in tested
    print(f"  scan() auto-parse → tested params={sorted(tested)}: OK")


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_mysql_error_detected,
        test_mssql_error_detected,
        test_oracle_error_detected,
        test_postgresql_error_detected,
        test_sqlite_error_detected,
        test_clean_response_not_flagged,
        test_boolean_AND_string_detected,
        test_boolean_AND_numeric_detected,
        test_boolean_OR_string_detected,
        test_boolean_same_length_not_flagged,
        test_probe_error_detects_on_second_payload,
        test_probe_error_clean_when_no_match,
        test_inject_GET_modifies_query_string,
        test_inject_POST_builds_body,
        test_parse_params_extracts_multiple,
        test_parse_params_no_query_string,
        test_scan_detects_error_based_injection,
        test_scan_auto_parses_params_from_url,
    ]
    passed = 0
    print(f"Running {len(tests)} SQLi Tester tests...\n")
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
