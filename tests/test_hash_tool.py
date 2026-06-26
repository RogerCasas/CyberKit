"""
CyberKit — Hash Identifier & Cracker engine tests (no UI, no network)

Run: python tests/test_hash_tool.py
"""

import io
import queue
import sys
import os
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from app.modules.hash_identifier import identify
from app.modules.hash_cracker import HashCrackEngine, CrackResult


# ── Identifier tests ──────────────────────────────────────────────────────────

def test_identify_md5():
    matches = identify("5f4dcc3b5aa765d61d8327deb882cf99")  # MD5("password")
    names = [m.name for m in matches]
    assert any("MD5" in n for n in names), f"MD5 not found in {names}"
    print(f"  identify MD5(password): OK  → {names}")


def test_identify_sha1():
    matches = identify("da39a3ee5e6b4b0d3255bfef95601890afd80709")  # SHA1("")
    names = [m.name for m in matches]
    assert any("SHA-1" in n for n in names), f"SHA-1 not found in {names}"
    print(f"  identify SHA-1(empty): OK  → {names}")


def test_identify_sha256():
    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    matches = identify(h)
    names = [m.name for m in matches]
    assert any("SHA-256" in n for n in names), f"SHA-256 not found in {names}"
    print(f"  identify SHA-256(empty): OK  → {names}")


def test_identify_sha512():
    h = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    # SHA-512 is 128 chars; pad to 128
    h = h + "0" * (128 - len(h))
    matches = identify(h)
    names = [m.name for m in matches]
    assert any("SHA-512" in n for n in names), f"SHA-512 not found in {names}"
    print(f"  identify SHA-512: OK  → {names}")


def test_identify_mysql5():
    matches = identify("*0A4A5CAD341293FFF8A0B2FA9C4F3E8B5A2D3C1E")
    names = [m.name for m in matches]
    assert any("MySQL" in n for n in names), f"MySQL5 not found in {names}"
    print(f"  identify MySQL5: OK  → {names}")


def test_identify_bcrypt():
    matches = identify("$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW")
    names = [m.name for m in matches]
    assert any("bcrypt" in n.lower() for n in names), f"bcrypt not found in {names}"
    print(f"  identify bcrypt: OK  → {names}")


def test_identify_empty_returns_empty():
    matches = identify("")
    assert matches == [], f"Expected [], got {matches}"
    print("  identify empty string → []: OK")


# ── Cracker tests ─────────────────────────────────────────────────────────────

def _run_crack(hash_str, algo, wordlist, timeout=5.0):
    q      = queue.Queue()
    stop   = threading.Event()
    engine = HashCrackEngine(hash_str, algo, wordlist, q, stop)
    t      = threading.Thread(target=engine.run, daemon=True)
    t.start()
    t.join(timeout)
    results = []
    while not q.empty():
        results.append(q.get_nowait())
    return results


def test_crack_md5_found():
    md5_password = "5f4dcc3b5aa765d61d8327deb882cf99"
    results = _run_crack(md5_password, "md5", ["wrong", "alsobad", "password", "notthis"])
    done_items = [r for r in results if r.done]
    assert done_items, "No done result received"
    done = done_items[0]
    assert done.found, "Expected crack to find 'password'"
    assert done.word == "password"
    print(f"  crack MD5(password) found: OK  → '{done.word}'")


def test_crack_not_found():
    md5_password = "5f4dcc3b5aa765d61d8327deb882cf99"
    results = _run_crack(md5_password, "md5", ["wrong", "nope", "notthere"])
    done_items = [r for r in results if r.done]
    assert done_items, "No done result received"
    done = done_items[0]
    assert not done.found, "Should not have found the hash"
    print("  crack MD5 not-found: OK")


def test_crack_stop_halts():
    import hashlib
    # Create a wordlist where the match is near the end
    wordlist = [f"word{i}" for i in range(5000)] + ["secretword"]
    target = hashlib.md5("secretword".encode()).hexdigest()

    q    = queue.Queue()
    stop = threading.Event()
    engine = HashCrackEngine(target, "md5", wordlist, q, stop)
    t = threading.Thread(target=engine.run, daemon=True)
    t.start()
    stop.set()  # signal stop immediately
    t.join(timeout=2.0)
    assert not t.is_alive(), "Engine thread should have stopped within 2s"
    print("  crack stop() halts within 2s: OK")


def test_crack_unsupported_algo_raises():
    try:
        HashCrackEngine("abc", "bcrypt", ["a"], queue.Queue(), threading.Event())
        assert False, "Should have raised ValueError"
    except ValueError as e:
        print(f"  unsupported algo raises ValueError: OK  ({e})")


if __name__ == "__main__":
    tests = [
        test_identify_md5,
        test_identify_sha1,
        test_identify_sha256,
        test_identify_sha512,
        test_identify_mysql5,
        test_identify_bcrypt,
        test_identify_empty_returns_empty,
        test_crack_md5_found,
        test_crack_not_found,
        test_crack_stop_halts,
        test_crack_unsupported_algo_raises,
    ]
    passed = 0
    print(f"Running {len(tests)} hash tool tests...\n")
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
