"""
CyberKit — JWT Forge & Verify engine tests

Run: python tests/test_jwt_tool.py
"""

import base64
import hashlib
import hmac
import json
import os
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.modules.jwt_tool import (
    BruteResult,
    JwtParts,
    brute_force,
    decode,
    forge_none_alg,
    verify_hs256,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _make_hs256_token(payload: dict, secret: str, header: dict = None) -> str:
    hdr = header or {"alg": "HS256", "typ": "JWT"}
    h = _b64url(json.dumps(hdr, separators=(",", ":")).encode())
    p = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"


# ── Group 2 tests ─────────────────────────────────────────────────────────────

def test_decode_valid_hs256():
    token = _make_hs256_token({"sub": "user1", "iat": 1700000000}, "mysecret")
    parts = decode(token)
    assert parts.header["alg"] == "HS256", f"Expected alg=HS256, got {parts.header['alg']}"
    assert parts.payload["sub"] == "user1"
    assert parts.payload["iat"] == 1700000000
    print("  decode_valid_hs256: OK")


def test_decode_malformed():
    for bad in ["notajwt", "only.two", "", "a.b.c.d"]:
        try:
            decode(bad)
            assert False, f"Expected ValueError for {bad!r}"
        except ValueError:
            pass
    print("  decode_malformed: OK")


def test_forge_none_alg():
    token = _make_hs256_token({"sub": "victim"}, "secret")
    original_parts = decode(token)
    forged = forge_none_alg(token)
    segments = forged.split(".")
    assert len(segments) == 3, f"Expected 3 segments, got {len(segments)}"
    assert segments[2] == "", f"Signature must be empty, got {segments[2]!r}"
    assert segments[1] == original_parts.payload_b64, "Payload must be unchanged"
    forged_header = decode(forged).header
    assert forged_header["alg"] == "none", f"Expected alg=none, got {forged_header['alg']}"
    print("  forge_none_alg: OK")


def test_verify_hs256_correct():
    secret = "supersecret"
    token = _make_hs256_token({"user": "alice"}, secret)
    assert verify_hs256(token, secret) is True
    print("  verify_hs256_correct: OK")


def test_verify_hs256_wrong_secret():
    token = _make_hs256_token({"user": "alice"}, "correct")
    assert verify_hs256(token, "wrong") is False
    print("  verify_hs256_wrong_secret: OK")


def test_brute_force_finds_secret():
    secret = "hunter2"
    token = _make_hs256_token({"id": 42}, secret)
    results = []
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
        f.write("password\n")
        f.write("123456\n")
        f.write("hunter2\n")
        f.write("letmein\n")
        fname = f.name
    try:
        stop = threading.Event()
        result = brute_force(token, fname, stop, lambda r: results.append(r))
    finally:
        os.unlink(fname)
    assert result.found is True, f"Expected found=True, got {result}"
    assert result.secret == secret, f"Expected secret={secret!r}, got {result.secret!r}"
    print(f"  brute_force_finds_secret: found={result.secret!r} in {result.attempts} attempts: OK")


def test_brute_force_stop_event():
    token = _make_hs256_token({"x": 1}, "secret")
    stop = threading.Event()
    stop.set()
    result = brute_force(token, "/nonexistent/path.txt", stop, lambda r: None)
    assert result.found is False
    assert result.attempts == 0
    print("  brute_force_stop_event: OK")


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_decode_valid_hs256,
        test_decode_malformed,
        test_forge_none_alg,
        test_verify_hs256_correct,
        test_verify_hs256_wrong_secret,
        test_brute_force_finds_secret,
        test_brute_force_stop_event,
    ]
    passed = 0
    print(f"Running {len(tests)} JWT Tool tests...\n")
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
