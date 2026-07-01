"""
CyberKit — Log Analyser engine tests

Run: python tests/test_log_analyser.py
All tests use fixture strings / temp files — no network calls.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.modules.log_analyser import _detect_format, _parse_apache, _parse_auth, analyse

# ── Fixtures ──────────────────────────────────────────────────────────────────

APACHE_LINES = [
    '192.168.1.1 - - [01/Jan/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234',
    '10.0.0.1 - - [01/Jan/2024:10:01:00 +0000] "POST /api HTTP/1.1" 404 56',
]

AUTH_LINES = [
    "Jul  1 12:00:00 server sshd[1234]: Failed password for admin from 1.2.3.4 port 22 ssh2",
    "Jul  1 12:01:00 server sshd[1235]: Invalid user guest from 5.6.7.8 port 22 ssh2",
]

APACHE_5_LINES = [
    '1.1.1.1 - - [01/Jan/2024:10:00:00 +0000] "GET / HTTP/1.1" 200 100',
    '1.1.1.1 - - [01/Jan/2024:10:01:00 +0000] "GET / HTTP/1.1" 200 100',
    '2.2.2.2 - - [01/Jan/2024:10:02:00 +0000] "GET / HTTP/1.1" 200 100',
    '3.3.3.3 - - [01/Jan/2024:10:03:00 +0000] "GET / HTTP/1.1" 404 50',
    '1.1.1.1 - - [01/Jan/2024:10:04:00 +0000] "GET / HTTP/1.1" 500 10',
]

APACHE_STATUS_LINES = [
    '1.1.1.1 - - [01/Jan/2024:10:00:00 +0000] "GET / HTTP/1.1" 200 100',
    '2.2.2.2 - - [01/Jan/2024:10:01:00 +0000] "GET / HTTP/1.1" 404 50',
    '3.3.3.3 - - [01/Jan/2024:10:02:00 +0000] "GET / HTTP/1.1" 404 50',
    '4.4.4.4 - - [01/Jan/2024:10:03:00 +0000] "GET / HTTP/1.1" 500 10',
]

AUTH_FAILED_LINES = [
    "Jul  1 12:00:00 server sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2",
    "Jul  1 12:01:00 server sshd[2]: Failed password for root from 5.6.7.8 port 22 ssh2",
    "Jul  1 12:02:00 server sshd[3]: Accepted publickey for admin from 9.9.9.9 port 22",
]

RANDOM_LINES = [
    "hello world",
    "this is not a log",
    "random text here",
]


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_detect_apache():
    fmt = _detect_format(APACHE_LINES)
    assert fmt == "apache", f"Expected 'apache', got '{fmt}'"
    print("  detect_apache: OK")


def test_detect_auth():
    fmt = _detect_format(AUTH_LINES)
    assert fmt == "auth", f"Expected 'auth', got '{fmt}'"
    print("  detect_auth: OK")


def test_parse_apache_top_ips():
    summary = _parse_apache(APACHE_5_LINES)
    assert summary.format == "apache"
    assert len(summary.top_ips) >= 3, f"Expected ≥3 IPs, got {len(summary.top_ips)}"
    top_ip, top_count = summary.top_ips[0]
    assert top_ip == "1.1.1.1", f"Expected 1.1.1.1 at top, got {top_ip}"
    assert top_count == 3, f"Expected count=3, got {top_count}"
    # Ensure descending order
    counts = [c for _, c in summary.top_ips]
    assert counts == sorted(counts, reverse=True), f"Not sorted: {counts}"
    print(f"  parse_apache_top_ips: top={top_ip} count={top_count}: OK")


def test_parse_apache_status_counts():
    summary = _parse_apache(APACHE_STATUS_LINES)
    sc = summary.status_counts
    assert sc.get("2xx", 0) == 1, f"Expected 2xx=1, got {sc}"
    assert sc.get("4xx", 0) == 2, f"Expected 4xx=2, got {sc}"
    assert sc.get("5xx", 0) == 1, f"Expected 5xx=1, got {sc}"
    print(f"  parse_apache_status_counts: {sc}: OK")


def test_parse_auth_failed():
    summary = _parse_auth(AUTH_FAILED_LINES)
    assert summary.format == "auth"
    assert summary.parsed_lines == 2, f"Expected 2 failed lines, got {summary.parsed_lines}"
    failed_users = dict(summary.failed_auth)
    assert failed_users.get("root", 0) == 2, f"Expected root=2, got {failed_users}"
    failed_ips = dict(summary.failed_auth_ips)
    assert len(failed_ips) == 2, f"Expected 2 source IPs, got {failed_ips}"
    print(f"  parse_auth_failed: users={failed_users}, ips={list(failed_ips.keys())}: OK")


def test_unknown_format():
    summary = _parse_apache.__module__ and None  # just to import
    from app.modules.log_analyser import analyse as _analyse
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as fh:
        fh.write("\n".join(RANDOM_LINES))
        tmp = fh.name
    try:
        result = _analyse(tmp)
        assert result.format == "unknown", f"Expected 'unknown', got '{result.format}'"
        assert result.parsed_lines == 0, f"Expected parsed_lines=0, got {result.parsed_lines}"
    finally:
        os.unlink(tmp)
    print("  unknown_format: OK")


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_detect_apache,
        test_detect_auth,
        test_parse_apache_top_ips,
        test_parse_apache_status_counts,
        test_parse_auth_failed,
        test_unknown_format,
    ]
    passed = 0
    print(f"Running {len(tests)} Log Analyser tests…\n")
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
