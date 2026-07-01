"""
CyberKit — Cipher Identifier & Solver Engine

Identifies and solves classical ciphers: Caesar, Vigenère, XOR, Rail Fence.
Pure Python stdlib — no numpy or scipy.
"""

import string
from dataclasses import dataclass

# ── English letter frequencies (percentages) ─────────────────────────────────
_EN_FREQ: dict[str, float] = {
    "a": 8.167, "b": 1.492, "c": 2.782, "d": 4.253, "e": 12.702,
    "f": 2.228, "g": 2.015, "h": 6.094, "i": 6.966, "j": 0.153,
    "k": 0.772, "l": 4.025, "m": 2.406, "n": 6.749, "o": 7.507,
    "p": 1.929, "q": 0.095, "r": 5.987, "s": 6.327, "t": 9.056,
    "u": 2.758, "v": 0.978, "w": 2.360, "x": 0.150, "y": 1.974,
    "z": 0.074,
}

# Top English letter bigrams (per-mille, lower-cased)
_EN_BIGRAMS: dict[str, float] = {
    "th": 38.0, "he": 33.0, "in": 28.0, "er": 27.0, "an": 25.0,
    "re": 23.0, "on": 22.0, "en": 22.0, "at": 21.0, "ou": 20.0,
    "es": 20.0, "ea": 19.0, "ti": 19.0, "st": 18.0, "to": 18.0,
    "it": 17.0, "is": 17.0, "nd": 17.0, "al": 16.0, "ar": 16.0,
    "te": 15.0, "se": 15.0, "ng": 15.0, "ha": 14.0, "or": 14.0,
    "as": 14.0, "ed": 14.0, "hi": 13.0, "nt": 13.0, "ne": 13.0,
}

ENGLISH_IC = 0.0667


@dataclass
class CipherCandidate:
    cipher:     str
    confidence: float    # 0.0–1.0
    key:        str
    plaintext:  str


# ── Core analysis helpers ─────────────────────────────────────────────────────

def _letters_only(text: str) -> str:
    """ASCII letters only, lower-cased."""
    return "".join(c for c in text.lower() if c.isascii() and c.isalpha())


def _ascii_alpha_ratio(text: str) -> float:
    """Fraction of characters that are plain ASCII letters."""
    if not text:
        return 0.0
    return sum(1 for c in text if c.isascii() and c.isalpha()) / len(text)


def _ascii_printable_ratio(text: str) -> float:
    """Fraction of characters in the printable ASCII range (0x20–0x7E)."""
    if not text:
        return 0.0
    return sum(1 for c in text if 0x20 <= ord(c) <= 0x7E) / len(text)


def _index_of_coincidence(text: str) -> float:
    """IC of a string (ASCII letters only)."""
    letters = _letters_only(text)
    n = len(letters)
    if n < 2:
        return 0.0
    freq: dict[str, int] = {}
    for c in letters:
        freq[c] = freq.get(c, 0) + 1
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


def _letter_freq(text: str) -> dict[str, float]:
    """Normalised ASCII letter frequency map."""
    letters = _letters_only(text)
    n = len(letters)
    if n == 0:
        return {c: 0.0 for c in string.ascii_lowercase}
    counts: dict[str, float] = {c: 0.0 for c in string.ascii_lowercase}
    for c in letters:
        counts[c] += 1
    return {c: v / n for c, v in counts.items()}


def _chi_squared(observed: dict[str, float], expected: dict[str, float]) -> float:
    """Chi-squared goodness-of-fit vs. English letter frequencies."""
    total = 0.0
    for c in string.ascii_lowercase:
        exp = expected.get(c, 0.0) / 100.0
        obs = observed.get(c, 0.0)
        if exp > 0:
            total += (obs - exp) ** 2 / exp
    return total


def _bigram_score(text: str) -> float:
    """
    Score how English-like consecutive letter pairs are (0.0–1.0).
    Works for all ciphers on a comparable scale — unlike chi-squared which
    only looks at individual letter frequencies.
    """
    letters = _letters_only(text)
    if len(letters) < 4:
        return 0.0
    total = 0.0
    for i in range(len(letters) - 1):
        total += _EN_BIGRAMS.get(letters[i: i + 2], 0.0)
    avg = total / max(len(letters) - 1, 1)
    return min(1.0, avg / 18.0)


# ── Caesar ────────────────────────────────────────────────────────────────────

def solve_caesar(text: str, shift: int) -> str:
    """Decrypt a Caesar cipher by applying the reverse shift."""
    result = []
    for c in text:
        if c.isalpha():
            base = ord("A") if c.isupper() else ord("a")
            result.append(chr((ord(c) - base - shift) % 26 + base))
        else:
            result.append(c)
    return "".join(result)


def _analyse_caesar(text: str) -> CipherCandidate:
    """
    Try all 26 shifts; pick by lowest chi-squared; score confidence by bigram
    quality of the decrypted text. Non-alphabetic ciphertext is penalised.
    """
    if _ascii_alpha_ratio(text) < 0.20:
        return CipherCandidate(cipher="Caesar", confidence=0.05, key="0", plaintext=text)

    best_shift, best_chi = 0, float("inf")
    for shift in range(26):
        chi = _chi_squared(_letter_freq(solve_caesar(text, shift)), _EN_FREQ)
        if chi < best_chi:
            best_chi, best_shift = chi, shift

    plaintext = solve_caesar(text, best_shift)
    confidence = _bigram_score(plaintext)
    return CipherCandidate(
        cipher="Caesar",
        confidence=round(confidence, 4),
        key=str(best_shift),
        plaintext=plaintext,
    )


# ── Vigenère ──────────────────────────────────────────────────────────────────

def solve_vigenere(text: str, key: str) -> str:
    """Decrypt a Vigenère cipher with the given key (letters only in key)."""
    key_letters = [c.lower() for c in key if c.isalpha()]
    if not key_letters:
        return text
    result = []
    ki = 0
    for c in text:
        if c.isalpha():
            base = ord("A") if c.isupper() else ord("a")
            shift = ord(key_letters[ki % len(key_letters)]) - ord("a")
            result.append(chr((ord(c) - base - shift) % 26 + base))
            ki += 1
        else:
            result.append(c)
    return "".join(result)


def _recover_key_for_length(letters: str, key_len: int) -> str:
    """Recover Vigenère key for a given key length by per-column frequency analysis."""
    key = []
    for i in range(key_len):
        col = "".join(letters[j::key_len] for j in [i])
        col = letters[i::key_len]
        best_shift, best_chi = 0, float("inf")
        for shift in range(26):
            shifted = "".join(chr((ord(c) - ord("a") - shift) % 26 + ord("a")) for c in col)
            chi = _chi_squared(_letter_freq(shifted), _EN_FREQ)
            if chi < best_chi:
                best_chi, best_shift = chi, shift
        key.append(chr(best_shift + ord("a")))
    return "".join(key)


def _analyse_vigenere(text: str) -> CipherCandidate:
    """
    Try all key lengths up to min(20, n/20); for each, recover the key by column
    frequency analysis and score the decrypted text by bigram quality. Pick the
    key length that yields the highest bigram score. This works correctly even
    when the plaintext IC is above the English IC target (high-IC prose).
    """
    if _ascii_alpha_ratio(text) < 0.20:
        return CipherCandidate(cipher="Vigenère", confidence=0.05, key="a", plaintext=text)

    letters = _letters_only(text)
    n = len(letters)
    if n < 20:
        return CipherCandidate(cipher="Vigenère", confidence=0.05, key="a", plaintext=text)

    max_kl = min(20, n // 20)
    best_kl, best_score, best_key, best_plain = 1, -1.0, "a", text

    for kl in range(1, max_kl + 1):
        key_str = _recover_key_for_length(letters, kl)
        plaintext = solve_vigenere(text, key_str)
        score = _bigram_score(plaintext)
        if score > best_score:
            best_score, best_kl, best_key, best_plain = score, kl, key_str, plaintext

    confidence = best_score
    # Penalise degenerate cases that are just Caesar in disguise
    if best_kl == 1:
        confidence *= 0.30
    elif len(set(best_key)) == 1:
        # All key chars identical → single-shift cipher (Caesar)
        confidence *= 0.20

    # Secondary check: high ciphertext IC means monoalphabetic (Caesar)
    ct_ic = _index_of_coincidence(text)
    if ct_ic >= 0.062:
        confidence *= 0.10

    return CipherCandidate(
        cipher="Vigenère",
        confidence=round(confidence, 4),
        key=best_key,
        plaintext=best_plain,
    )


# ── XOR ───────────────────────────────────────────────────────────────────────

def solve_xor(text: str, key_hex: str) -> str:
    """
    XOR-decrypt text with a repeating key given as hex string.
    text is treated as raw bytes (latin-1 encoded).
    """
    key_bytes = bytes.fromhex(key_hex)
    if not key_bytes:
        return text
    raw = text.encode("latin-1", errors="replace")
    decrypted = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(raw))
    return decrypted.decode("latin-1", errors="replace")


def _analyse_xor(text: str) -> CipherCandidate:
    """
    Single-byte XOR: try all 256 byte values; select by chi-squared of letter
    frequencies on output that passes the printable-ASCII filter.
    """
    raw = text.encode("latin-1", errors="replace")
    best_byte, best_chi, best_pr = 0, float("inf"), -1.0

    for b in range(256):
        decrypted = bytes(x ^ b for x in raw)
        decoded = decrypted.decode("latin-1")
        # Must be at least 70% printable ASCII
        pr = _ascii_printable_ratio(decoded)
        if pr < 0.70:
            continue
        chi = _chi_squared(_letter_freq(decoded), _EN_FREQ)
        if chi < best_chi or (chi == best_chi and pr > best_pr):
            best_chi, best_byte, best_pr = chi, b, pr

    key_hex = f"{best_byte:02x}"
    plaintext = solve_xor(text, key_hex)
    alpha = _ascii_alpha_ratio(plaintext)
    if best_chi == float("inf") or alpha < 0.25:
        confidence = 0.10
    else:
        confidence = round(
            max(0.0, min(0.92, _bigram_score(plaintext))), 4
        )
    return CipherCandidate(cipher="XOR", confidence=confidence, key=key_hex, plaintext=plaintext)


# ── Rail Fence ────────────────────────────────────────────────────────────────

def solve_railfence(text: str, rails: int) -> str:
    """Decrypt a Rail Fence cipher with the given number of rails."""
    n = len(text)
    if rails < 2 or n == 0:
        return text
    pattern = []
    rail, direction = 0, 1
    for _ in range(n):
        pattern.append(rail)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction
    rail_lengths = [0] * rails
    for r in pattern:
        rail_lengths[r] += 1
    rail_segments, idx = [], 0
    for length in rail_lengths:
        rail_segments.append(list(text[idx: idx + length]))
        idx += length
    rail_pos = [0] * rails
    result = []
    for r in pattern:
        result.append(rail_segments[r][rail_pos[r]])
        rail_pos[r] += 1
    return "".join(result)


def _analyse_railfence(text: str) -> CipherCandidate:
    """
    Try rails 2–10; score by English bigram frequency of decrypted text.
    Bigram score is the right metric for transposition ciphers because letter
    frequencies are identical for all rail counts — only adjacency changes.
    """
    if _ascii_alpha_ratio(text) < 0.20:
        return CipherCandidate(cipher="Rail Fence", confidence=0.05, key="2", plaintext=text)

    best_rails, best_score, best_plain = 2, -1.0, text
    for r in range(2, min(11, len(text))):
        candidate = solve_railfence(text, r)
        score = _bigram_score(candidate)
        if score > best_score:
            best_score, best_rails, best_plain = score, r, candidate

    confidence = round(min(1.0, best_score * 1.15), 4)
    return CipherCandidate(
        cipher="Rail Fence", confidence=confidence, key=str(best_rails), plaintext=best_plain
    )


# ── Top-level identify ────────────────────────────────────────────────────────

def identify(ciphertext: str) -> list[CipherCandidate]:
    """
    Run all four analysers on ciphertext and return candidates ranked by confidence.
    Always returns a non-empty list; never raises.
    """
    if not ciphertext or not ciphertext.strip():
        return [CipherCandidate(cipher="Caesar", confidence=0.0, key="0", plaintext="")]

    candidates: list[CipherCandidate] = []
    for analyser in [_analyse_caesar, _analyse_vigenere, _analyse_xor, _analyse_railfence]:
        try:
            candidates.append(analyser(ciphertext))
        except Exception:
            pass

    if not candidates:
        return [CipherCandidate(cipher="Caesar", confidence=0.0, key="0", plaintext=ciphertext)]

    # Low ASCII-letter ratio → ciphertext cannot be Caesar or Vigenère
    # (both always produce 100% letter output). This is the primary XOR signal.
    alpha = _ascii_alpha_ratio(ciphertext)
    if alpha < 0.25:
        scale = alpha / 0.25          # 0 → 1 as alpha goes from 0 → 0.25
        for c in candidates:
            if c.cipher in ("Caesar", "Vigenère", "Rail Fence"):
                c.confidence = round(c.confidence * scale * 0.3, 4)

    candidates.sort(key=lambda c: c.confidence, reverse=True)
    return candidates
