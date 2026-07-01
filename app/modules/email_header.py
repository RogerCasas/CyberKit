"""
CyberKit — Email Header Analyser Engine

Parses raw email headers to reconstruct the relay chain, evaluate
SPF/DKIM/DMARC results, and surface suspicious patterns.
Stdlib only — no external dependencies.
"""

import email.parser
import email.utils
import re
from dataclasses import dataclass, field


@dataclass
class HopEntry:
    index:     int
    by:        str        # receiving MTA
    from_:     str        # sending host
    timestamp: str        # raw timestamp string
    ip:        str        # extracted sender IP (empty if not found)
    delta_s:   int | None # seconds since previous hop (None for first)


@dataclass
class AuthResult:
    spf:   str   # "pass" / "fail" / "softfail" / "neutral" / "none" / "unknown"
    dkim:  str
    dmarc: str


@dataclass
class HeaderSummary:
    from_:      str
    to:         str
    subject:    str
    date:       str
    message_id: str
    mailer:     str
    hops:       list[HopEntry]
    auth:       AuthResult
    flags:      list[str]   # human-readable warning strings


# ── Regex helpers ─────────────────────────────────────────────────────────────

_IP_RE = re.compile(
    r'\[(\d{1,3}(?:\.\d{1,3}){3})\]'          # IPv4 in brackets
    r'|\((\d{1,3}(?:\.\d{1,3}){3})\)'          # IPv4 in parens
    r'|(?<!\w)(\d{1,3}(?:\.\d{1,3}){3})(?!\w)' # bare IPv4
)

_AUTH_FIELD_RE = re.compile(r'(spf|dkim|dmarc)\s*=\s*([A-Za-z]+)', re.IGNORECASE)

_KNOWN_FAILURES = {"fail", "softfail", "permerror", "temperror"}
_SUSPICIOUS     = {"none", "neutral"}


def _extract_ip(text: str) -> str:
    """Return the first IPv4 address found in text, or empty string."""
    m = _IP_RE.search(text)
    if not m:
        return ""
    return m.group(1) or m.group(2) or m.group(3) or ""


def _parse_received(value: str) -> tuple[str, str, str, str]:
    """
    Return (from_, by, timestamp, ip) from a Received: header value.
    All fields are best-effort; missing ones return empty string.
    """
    from_m = re.search(r'\bfrom\s+(\S+)', value, re.IGNORECASE)
    from_  = from_m.group(1).rstrip(";,") if from_m else ""

    by_m = re.search(r'\bby\s+(\S+)', value, re.IGNORECASE)
    by   = by_m.group(1).rstrip(";,") if by_m else ""

    # Timestamp is usually after the last semicolon
    ts_m = re.search(r';\s*(.+)$', value, re.DOTALL | re.IGNORECASE)
    timestamp = re.sub(r'\s+', ' ', ts_m.group(1)).strip() if ts_m else ""

    ip = _extract_ip(value)
    return from_, by, timestamp, ip


def _parse_datetime(timestamp: str):
    """
    Try to parse a timestamp string into a datetime; return None on failure.
    Strips any trailing comment in parentheses first.
    """
    cleaned = re.sub(r'\([^)]*\)', '', timestamp).strip()
    try:
        return email.utils.parsedate_to_datetime(cleaned)
    except Exception:
        return None


# ── Public API ────────────────────────────────────────────────────────────────

def parse(raw_header: str) -> HeaderSummary:
    """
    Parse a raw email header block and return a HeaderSummary.
    Never raises — missing fields are returned as empty strings.
    """
    _empty_auth = AuthResult(spf="unknown", dkim="unknown", dmarc="unknown")

    if not raw_header or not raw_header.strip():
        return HeaderSummary(
            from_="", to="", subject="", date="",
            message_id="", mailer="",
            hops=[], auth=_empty_auth, flags=[],
        )

    msg = email.parser.HeaderParser().parsestr(raw_header)

    # ── Key metadata ──────────────────────────────────────────────────────────
    from_      = msg.get("From",       "")
    to         = msg.get("To",         "")
    subject    = msg.get("Subject",    "")
    date       = msg.get("Date",       "")
    message_id = msg.get("Message-ID", "")
    mailer     = msg.get("X-Mailer",   "") or msg.get("User-Agent", "")

    # ── Relay hops ────────────────────────────────────────────────────────────
    # Received headers are listed newest-first; reverse for oldest-first display.
    received_headers = list(reversed(msg.get_all("Received") or []))

    hops: list[HopEntry] = []
    prev_dt = None
    for i, rv in enumerate(received_headers):
        hop_from, hop_by, hop_ts, hop_ip = _parse_received(rv)
        delta_s: int | None = None
        dt = _parse_datetime(hop_ts)
        if dt is not None and prev_dt is not None:
            delta_s = int((dt - prev_dt).total_seconds())
        if dt is not None:
            prev_dt = dt
        hops.append(HopEntry(
            index=i + 1,
            by=hop_by,
            from_=hop_from,
            timestamp=hop_ts,
            ip=hop_ip,
            delta_s=delta_s,
        ))

    # ── Authentication-Results ────────────────────────────────────────────────
    auth_headers = msg.get_all("Authentication-Results") or []
    auth_text    = " ".join(auth_headers)

    spf = dkim = dmarc = "unknown"
    for m in _AUTH_FIELD_RE.finditer(auth_text):
        name  = m.group(1).lower()
        value = m.group(2).lower()
        if name == "spf"   and spf   == "unknown": spf   = value
        if name == "dkim"  and dkim  == "unknown": dkim  = value
        if name == "dmarc" and dmarc == "unknown": dmarc = value

    auth = AuthResult(spf=spf, dkim=dkim, dmarc=dmarc)

    # ── Flags ─────────────────────────────────────────────────────────────────
    flags: list[str] = []

    if not auth_headers:
        flags.append(
            "No Authentication-Results header found — "
            "SPF/DKIM/DMARC status cannot be evaluated"
        )
    for label, val in [("SPF", spf), ("DKIM", dkim), ("DMARC", dmarc)]:
        if val in _KNOWN_FAILURES:
            flags.append(f"{label} result is '{val}' — potential email spoofing or forgery")
        elif val in _SUSPICIOUS:
            flags.append(f"{label} result is '{val}' — sender domain has no policy configured")

    # Time gap check on hops that have parseable timestamps
    parsed_times = []
    for rv in received_headers:
        _, _, hop_ts, _ = _parse_received(rv)
        dt = _parse_datetime(hop_ts)
        if dt is not None:
            parsed_times.append(dt)

    for j in range(1, len(parsed_times)):
        gap_s = int((parsed_times[j] - parsed_times[j - 1]).total_seconds())
        if gap_s > 3600:
            h   = gap_s // 3600
            m_  = (gap_s % 3600) // 60
            flags.append(
                f"Large time gap between hops {j} and {j+1}: "
                f"{h}h {m_}min — could indicate greylisting, spam filtering, or clock skew"
            )

    return HeaderSummary(
        from_=from_, to=to, subject=subject, date=date,
        message_id=message_id, mailer=mailer,
        hops=hops, auth=auth, flags=flags,
    )
