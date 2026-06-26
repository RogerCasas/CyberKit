"""
CyberKit — Hash type identifier (pattern-based).
"""

import re
from dataclasses import dataclass


@dataclass
class HashMatch:
    name:  str
    notes: str


_PATTERNS: list[tuple] = [
    ("bcrypt",
     re.compile(r"^\$2[ayb]\$\d{2}\$.{53}$"),
     "Blowfish — 60-char prefixed hash. Cannot be cracked by this tool."),
    ("MySQL5 / SHA1*",
     re.compile(r"^\*[0-9A-Fa-f]{40}$"),
     "MySQL5/MariaDB password hash — '*' followed by 40 hex chars."),
    ("SHA-512",
     re.compile(r"^[0-9a-fA-F]{128}$"),
     "128 hex chars — SHA-512 (most likely)."),
    ("SHA-256",
     re.compile(r"^[0-9a-fA-F]{64}$"),
     "64 hex chars — SHA-256 (most likely)."),
    ("SHA-1 / MySQL4",
     re.compile(r"^[0-9a-fA-F]{40}$"),
     "40 hex chars — SHA-1 or MySQL4 Old Password."),
    ("MD5 / NTLM / LM",
     re.compile(r"^[0-9a-fA-F]{32}$"),
     "32 hex chars — MD5, NTLM, or LM hash."),
]


def identify(hash_str: str) -> list:
    """Return all HashMatch patterns that fit hash_str, ordered by specificity."""
    s = hash_str.strip()
    if not s:
        return []
    return [
        HashMatch(name=name, notes=notes)
        for name, pattern, notes in _PATTERNS
        if pattern.match(s)
    ]
