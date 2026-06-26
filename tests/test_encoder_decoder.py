"""
CyberKit — Encoder / Decoder engine tests (no UI, no network)

Run: python tests/test_encoder_decoder.py
"""

import io
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from app.modules.encoder_decoder_ops import (
    url_encode, url_decode,
    base64_encode, base64_decode,
    base64url_encode, base64url_decode,
    html_encode, html_decode,
    hex_encode, hex_decode,
    rot13,
    jwt_inspect,
)


def test_url_encode_decode_roundtrip():
    original = "hello world & more?"
    encoded  = url_encode(original)
    assert encoded == "hello%20world%20%26%20more%3F", f"Got: {encoded}"
    assert url_decode(encoded) == original
    print(f"  url round-trip: OK  ({encoded!r})")


def test_url_decode_plus_sign():
    result = url_decode("hello%2Bworld")
    assert result == "hello+world", f"Got: {result}"
    print(f"  url %2B → '+': OK")


def test_base64_encode_decode_roundtrip():
    original = "CyberKit"
    encoded  = base64_encode(original)
    assert encoded == "Q3liZXJLaXQ=", f"Got: {encoded}"
    assert base64_decode(encoded) == original
    print(f"  base64 round-trip: OK  ({encoded!r})")


def test_base64_decode_invalid_raises():
    try:
        base64_decode("not_valid_b64!!")
        assert False, "Should have raised ValueError"
    except ValueError:
        print("  base64 invalid input → ValueError: OK")


def test_base64url_roundtrip():
    original = "data+with/special=chars"
    encoded  = base64url_encode(original)
    decoded  = base64url_decode(encoded)
    assert decoded == original, f"Got: {decoded!r}"
    assert "+" not in encoded and "/" not in encoded
    print(f"  base64url round-trip: OK")


def test_html_encode():
    original = '<script>alert("xss")</script>'
    encoded  = html_encode(original)
    assert "&lt;" in encoded
    assert "&quot;" in encoded
    assert "<" not in encoded
    print(f"  html encode: OK  ({encoded[:30]}…)")


def test_html_decode_roundtrip():
    original = '<a href="test">click & go</a>'
    assert html_decode(html_encode(original)) == original
    print("  html encode/decode round-trip: OK")


def test_hex_encode():
    assert hex_encode("hello") == "68656c6c6f"
    print("  hex encode 'hello' → '68656c6c6f': OK")


def test_hex_decode():
    assert hex_decode("68656c6c6f") == "hello"
    print("  hex decode '68656c6c6f' → 'hello': OK")


def test_hex_decode_invalid_raises():
    try:
        hex_decode("zzzz")
        assert False, "Should have raised ValueError"
    except ValueError:
        print("  hex invalid input → ValueError: OK")


def test_rot13_double_application():
    original = "CyberKit 2026"
    assert rot13(rot13(original)) == original
    print(f"  ROT-13 self-inverse: OK")


def test_jwt_inspect_valid():
    # HS256 token: header={"alg":"HS256","typ":"JWT"}, payload={"sub":"1234","name":"test"}
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0IiwibmFtZSI6InRlc3QifQ"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    header, payload = jwt_inspect(token)
    assert header.get("alg") == "HS256"
    assert header.get("typ") == "JWT"
    assert payload.get("sub") == "1234"
    print(f"  jwt_inspect valid token: OK  (alg={header['alg']})")


def test_jwt_inspect_wrong_parts_raises():
    try:
        jwt_inspect("not.a.jwt.with.too.many.parts")
        assert False, "Should have raised ValueError"
    except ValueError:
        print("  jwt_inspect wrong part count → ValueError: OK")


def test_jwt_inspect_invalid_base64_raises():
    try:
        jwt_inspect("!!!.notbase64.sig")
        assert False, "Should have raised ValueError"
    except ValueError:
        print("  jwt_inspect invalid base64 → ValueError: OK")


if __name__ == "__main__":
    tests = [
        test_url_encode_decode_roundtrip,
        test_url_decode_plus_sign,
        test_base64_encode_decode_roundtrip,
        test_base64_decode_invalid_raises,
        test_base64url_roundtrip,
        test_html_encode,
        test_html_decode_roundtrip,
        test_hex_encode,
        test_hex_decode,
        test_hex_decode_invalid_raises,
        test_rot13_double_application,
        test_jwt_inspect_valid,
        test_jwt_inspect_wrong_parts_raises,
        test_jwt_inspect_invalid_base64_raises,
    ]
    passed = 0
    print(f"Running {len(tests)} encoder/decoder tests...\n")
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
