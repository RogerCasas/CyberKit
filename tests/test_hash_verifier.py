"""
CyberKit — Hash Verifier engine tests

Run: python tests/test_hash_verifier.py
"""

import hashlib
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.modules.hash_verifier import HashResult, VerifyResult, compute, verify

# ── Known test data ───────────────────────────────────────────────────────────

KNOWN_BYTES = b"CyberKit hash verifier test data 1234567890"
KNOWN_SHA256 = hashlib.sha256(KNOWN_BYTES).hexdigest()
KNOWN_MD5    = hashlib.md5(KNOWN_BYTES).hexdigest()


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_compute_known_hash():
    """SHA-256 of known bytes matches hashlib reference."""
    with tempfile.NamedTemporaryFile(delete=False) as fh:
        fh.write(KNOWN_BYTES)
        tmp = fh.name
    try:
        result = compute(tmp)
        assert result.error == "", f"Unexpected error: {result.error}"
        assert result.sha256 == KNOWN_SHA256, (
            f"SHA-256 mismatch:\n  got:      {result.sha256}\n  expected: {KNOWN_SHA256}"
        )
        assert result.md5 == KNOWN_MD5, f"MD5 mismatch: {result.md5}"
        assert len(result.sha1)   == 40,  f"SHA-1 should be 40 hex chars, got {len(result.sha1)}"
        assert len(result.sha512) == 128, f"SHA-512 should be 128 hex chars, got {len(result.sha512)}"
    finally:
        os.unlink(tmp)
    print(f"  compute_known_hash: sha256={KNOWN_SHA256[:16]}…: OK")


def test_verify_match():
    """verify() with the correct SHA-256 → match=True, matched_algorithm='SHA-256'."""
    r = HashResult("dummy.bin", md5=KNOWN_MD5, sha1="a"*40, sha256=KNOWN_SHA256, sha512="b"*128)
    v = verify(r, KNOWN_SHA256)
    assert v.match is True, f"Expected match=True, got {v.match}"
    assert v.matched_algorithm == "SHA-256", f"Expected SHA-256, got '{v.matched_algorithm}'"
    print("  verify_match: OK")


def test_verify_no_match():
    """verify() with wrong hash → match=False."""
    r = HashResult("dummy.bin", md5=KNOWN_MD5, sha1="a"*40, sha256=KNOWN_SHA256, sha512="b"*128)
    v = verify(r, "0" * 64)
    assert v.match is False, f"Expected match=False, got {v.match}"
    assert v.matched_algorithm == "", f"Expected empty algorithm, got '{v.matched_algorithm}'"
    print("  verify_no_match: OK")


def test_verify_case_insensitive():
    """Uppercase expected hash still matches correctly."""
    r = HashResult("dummy.bin", md5=KNOWN_MD5, sha1="a"*40, sha256=KNOWN_SHA256, sha512="b"*128)
    v = verify(r, KNOWN_SHA256.upper())
    assert v.match is True, f"Expected case-insensitive match, got {v.match}"
    assert v.matched_algorithm == "SHA-256"
    print("  verify_case_insensitive: OK")


def test_compute_error():
    """compute() on a non-existent file → error field non-empty, no exception."""
    result = compute("nonexistent_file_that_does_not_exist.bin")
    assert result.error != "", f"Expected an error message, got empty string"
    assert result.sha256 == "", f"Expected empty sha256 on error, got '{result.sha256}'"
    print(f"  compute_error: error='{result.error[:40]}…': OK")


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_compute_known_hash,
        test_verify_match,
        test_verify_no_match,
        test_verify_case_insensitive,
        test_compute_error,
    ]
    passed = 0
    print(f"Running {len(tests)} Hash Verifier tests…\n")
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
