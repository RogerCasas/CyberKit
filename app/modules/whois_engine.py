"""
CyberKit — WHOIS lookup engine
"""

from dataclasses import dataclass, field
from datetime import datetime

import whois


@dataclass
class WhoisInfo:
    domain: str
    registrar: str
    creation_date: str
    expiry_date: str
    updated_date: str
    registrant_org: str
    name_servers: list


def lookup(domain: str) -> WhoisInfo:
    w = whois.whois(domain)
    if not w or not w.domain_name:
        raise ValueError(f"No WHOIS data returned for {domain!r}")

    return WhoisInfo(
        domain=domain,
        registrar=_str(w.registrar),
        creation_date=_fmt_date(w.creation_date),
        expiry_date=_fmt_date(getattr(w, "expiration_date", None)),
        updated_date=_fmt_date(w.updated_date),
        registrant_org=_str(getattr(w, "org", None)),
        name_servers=_ns_list(w.name_servers),
    )


# ── Helpers (exported for unit tests) ────────────────────────────────────────

def _str(val) -> str:
    if val is None:
        return ""
    if isinstance(val, list):
        return str(val[0]) if val else ""
    return str(val)


def _fmt_date(val) -> str:
    if val is None:
        return ""
    if isinstance(val, list):
        val = val[0] if val else None
    if val is None:
        return ""
    if isinstance(val, datetime):
        return val.strftime("%Y-%m-%d")
    return str(val)


def _ns_list(val) -> list:
    if val is None:
        return []
    if isinstance(val, list):
        return sorted({str(ns).lower().rstrip(".") for ns in val if ns})
    return [str(val).lower().rstrip(".")]
