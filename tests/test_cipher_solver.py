"""
CyberKit — Cipher Identifier & Solver engine tests

Run: python tests/test_cipher_solver.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.modules.cipher_solver import (
    CipherCandidate,
    identify,
    solve_caesar,
    solve_railfence,
    solve_vigenere,
    solve_xor,
)

# ── helpers ───────────────────────────────────────────────────────────────────

PLAINTEXT = (
    "the quick brown fox jumps over the lazy dog and then it sat down "
    "to rest for a while before getting up again to roam the countryside"
)

# Prose with natural English letter frequencies — needed for Vigenère frequency analysis
PROSE = (
    "in the beginning there was a great silence and then out of the darkness "
    "came a single light that grew stronger with each passing moment until it "
    "filled the entire world with warmth and the people who lived there were "
    "filled with wonder at this remarkable and most unexpected transformation"
)


def _encrypt_caesar(text: str, shift: int) -> str:
    result = []
    for c in text:
        if c.isalpha():
            base = ord("A") if c.isupper() else ord("a")
            result.append(chr((ord(c) - base + shift) % 26 + base))
        else:
            result.append(c)
    return "".join(result)


def _encrypt_vigenere(text: str, key: str) -> str:
    key = key.lower()
    ki = 0
    result = []
    for c in text:
        if c.isalpha():
            base = ord("A") if c.isupper() else ord("a")
            shift = ord(key[ki % len(key)]) - ord("a")
            result.append(chr((ord(c) - base + shift) % 26 + base))
            ki += 1
        else:
            result.append(c)
    return "".join(result)


def _encrypt_railfence(text: str, rails: int) -> str:
    fence = [[] for _ in range(rails)]
    rail = 0
    direction = 1
    for c in text:
        fence[rail].append(c)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction
    return "".join(c for row in fence for c in row)


# ── Tests ──────────────────────────────────────────────────────────────────────

def test_caesar_roundtrip():
    for shift in [1, 13, 25]:
        encrypted = _encrypt_caesar(PLAINTEXT, shift)
        decrypted = solve_caesar(encrypted, shift)
        assert decrypted == PLAINTEXT, f"Caesar shift={shift} roundtrip failed"
    print("  caesar_roundtrip: OK")


def test_caesar_identify_top():
    encrypted = _encrypt_caesar(PLAINTEXT, 13)
    candidates = identify(encrypted)
    assert candidates, "identify() returned empty list"
    assert candidates[0].cipher == "Caesar", (
        f"Expected Caesar as top candidate, got {candidates[0].cipher}"
    )
    print(f"  caesar_identify_top: top={candidates[0].cipher} key={candidates[0].key}: OK")


def test_vigenere_roundtrip():
    key = "KEY"
    encrypted = _encrypt_vigenere(PLAINTEXT, key)
    decrypted = solve_vigenere(encrypted, key)
    assert decrypted == PLAINTEXT, "Vigenère roundtrip failed"
    print("  vigenere_roundtrip: OK")


def test_vigenere_identify_top():
    key = "key"
    encrypted = _encrypt_vigenere(PROSE * 2, key)
    candidates = identify(encrypted)
    assert candidates, "identify() returned empty list"
    names = [c.cipher for c in candidates[:2]]
    assert "Vigenère" in names, (
        f"Expected Vigenère in top 2, got {names}"
    )
    print(f"  vigenere_identify_top: top2={names}: OK")


def test_xor_roundtrip_single_byte():
    raw = PLAINTEXT.encode("latin-1")
    encrypted_bytes = bytes(b ^ 0x42 for b in raw)
    encrypted = encrypted_bytes.decode("latin-1")
    decrypted = solve_xor(encrypted, "42")
    assert decrypted == PLAINTEXT, "XOR single-byte roundtrip failed"
    print("  xor_roundtrip_single_byte: OK")


def test_xor_solve_multibyte():
    key_bytes = bytes([0xAB, 0xCD, 0xEF])
    key_hex = "abcdef"
    raw = PLAINTEXT.encode("latin-1")
    encrypted_bytes = bytes(b ^ key_bytes[i % 3] for i, b in enumerate(raw))
    encrypted = encrypted_bytes.decode("latin-1")
    decrypted = solve_xor(encrypted, key_hex)
    assert decrypted == PLAINTEXT, "XOR multi-byte roundtrip failed"
    print("  xor_solve_multibyte: OK")


def test_railfence_roundtrip():
    for rails in [2, 3, 4]:
        encrypted = _encrypt_railfence(PLAINTEXT, rails)
        decrypted = solve_railfence(encrypted, rails)
        assert decrypted == PLAINTEXT, f"Rail Fence rails={rails} roundtrip failed"
    print("  railfence_roundtrip: OK")


def test_identify_returns_list():
    for text in ["", "   ", "abc", PLAINTEXT, "XKQJZ VMLP WQNRT"]:
        result = identify(text)
        assert isinstance(result, list), f"identify() must return a list, got {type(result)}"
        assert len(result) > 0, "identify() must return a non-empty list"
    print("  identify_returns_list: OK")


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_caesar_roundtrip,
        test_caesar_identify_top,
        test_vigenere_roundtrip,
        test_vigenere_identify_top,
        test_xor_roundtrip_single_byte,
        test_xor_solve_multibyte,
        test_railfence_roundtrip,
        test_identify_returns_list,
    ]
    passed = 0
    print(f"Running {len(tests)} Cipher Solver tests...\n")
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
