"""
CyberKit — Hash Verifier engine

Computes MD5, SHA-1, SHA-256, and SHA-512 digests for a file in 1 MB chunks,
then compares against an expected hash string.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

_CHUNK = 1024 * 1024  # 1 MB


@dataclass
class HashResult:
    file_path: str
    md5:       str
    sha1:      str
    sha256:    str
    sha512:    str
    error:     str = ""


@dataclass
class VerifyResult:
    matched_algorithm: str   # "MD5" | "SHA-1" | "SHA-256" | "SHA-512" | ""
    match:             bool


def compute(path: str, stop_event=None, on_progress=None) -> HashResult:
    """Hash a file with all four algorithms. Never raises."""
    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()

    try:
        total = os.path.getsize(path)
        done  = 0
        with open(path, "rb") as fh:
            while True:
                if stop_event and stop_event.is_set():
                    break
                chunk = fh.read(_CHUNK)
                if not chunk:
                    break
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
                sha512.update(chunk)
                done += len(chunk)
                if on_progress:
                    on_progress(done, total)
    except OSError as exc:
        return HashResult(path, "", "", "", "", error=str(exc))

    return HashResult(
        file_path=path,
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
        sha512=sha512.hexdigest(),
    )


def verify(result: HashResult, expected: str) -> VerifyResult:
    """Compare *expected* against each digest; case-insensitive."""
    norm = expected.strip().lower()
    candidates = [
        ("MD5",     result.md5),
        ("SHA-1",   result.sha1),
        ("SHA-256", result.sha256),
        ("SHA-512", result.sha512),
    ]
    for algo, digest in candidates:
        if digest and digest.lower() == norm:
            return VerifyResult(matched_algorithm=algo, match=True)
    return VerifyResult(matched_algorithm="", match=False)
