"""
CyberKit — Encoding / Decoding pure functions (no UI dependency).
"""

import base64
import binascii
import codecs
import html
import json
import urllib.parse


def url_encode(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def url_decode(s: str) -> str:
    return urllib.parse.unquote(s)


def base64_encode(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def base64_decode(s: str) -> str:
    s = s.strip()
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    try:
        return base64.b64decode(s).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as e:
        raise ValueError(f"Invalid Base64 input: {e}") from e


def base64url_encode(s: str) -> str:
    return base64.urlsafe_b64encode(s.encode("utf-8")).decode("ascii").rstrip("=")


def base64url_decode(s: str) -> str:
    s = s.strip()
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    try:
        return base64.urlsafe_b64decode(s).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as e:
        raise ValueError(f"Invalid Base64URL input: {e}") from e


def html_encode(s: str) -> str:
    return html.escape(s, quote=True)


def html_decode(s: str) -> str:
    return html.unescape(s)


def hex_encode(s: str) -> str:
    return s.encode("utf-8").hex()


def hex_decode(s: str) -> str:
    s = s.strip().replace(" ", "")
    try:
        return bytes.fromhex(s).decode("utf-8")
    except ValueError as e:
        raise ValueError(f"Invalid hex input: {e}") from e


def rot13(s: str) -> str:
    return codecs.encode(s, "rot_13")


def jwt_inspect(token: str) -> tuple:
    """Decode JWT header and payload without verification.

    Returns (header_dict, payload_dict). Raises ValueError on malformed input.
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError(
            f"Expected 3 JWT parts separated by '.', got {len(parts)}"
        )

    def _decode_part(part: str, name: str) -> dict:
        padding = 4 - len(part) % 4
        if padding != 4:
            part += "=" * padding
        try:
            decoded = base64.urlsafe_b64decode(part).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError) as e:
            raise ValueError(f"Cannot base64url-decode JWT {name}: {e}") from e
        try:
            return json.loads(decoded)
        except json.JSONDecodeError as e:
            raise ValueError(f"JWT {name} is not valid JSON: {e}") from e

    header  = _decode_part(parts[0], "header")
    payload = _decode_part(parts[1], "payload")
    return header, payload
