"""
CyberKit — Log Analyser engine

Detects Apache/Nginx combined access log or SSH auth.log format,
then parses top IPs, status codes, error spikes, and failed-auth stats.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field


# ── Dataclass ─────────────────────────────────────────────────────────────────

@dataclass
class LogSummary:
    format:          str                      # "apache" | "auth" | "unknown"
    total_lines:     int
    parsed_lines:    int
    top_ips:         list[tuple[str, int]]    # (ip, count), up to 20
    status_counts:   dict[str, int]           # {"2xx": N, ...}
    error_by_hour:   list[tuple[str, int]]    # (hour "YYYY-MM-DD HH", count)
    failed_auth:     list[tuple[str, int]]    # (username, count)
    failed_auth_ips: list[tuple[str, int]]    # (ip, count)


# ── Regexes ───────────────────────────────────────────────────────────────────

# Apache/Nginx combined log: 127.0.0.1 - - [01/Jan/2024:12:00:00 +0000] "GET / HTTP/1.1" 200 1234
_APACHE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<day>\d+)/(?P<mon>\w+)/(?P<year>\d+):'
    r'(?P<hour>\d+):\d+:\d+\s[^\]]+\]\s+"[^"]*"\s+(?P<status>\d{3})\s+'
)

# SSH auth.log: Jul  1 12:00:00 host sshd[123]: Failed password for user from 1.2.3.4 port 22 ssh2
_AUTH_FAILED_RE = re.compile(
    r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
)
_AUTH_INVALID_RE = re.compile(
    r'Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)'
)

_MON_MAP = {
    "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04",
    "May": "05", "Jun": "06", "Jul": "07", "Aug": "08",
    "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12",
}


# ── Format detection ──────────────────────────────────────────────────────────

def _detect_format(lines: list[str]) -> str:
    sample = [l for l in lines if l.strip()][:20]
    apache_hits = sum(1 for l in sample if _APACHE_RE.match(l))
    auth_hits = sum(
        1 for l in sample
        if "sshd" in l or "Failed password" in l or "Invalid user" in l or "Accepted " in l
    )
    if apache_hits >= max(1, len(sample) // 3):
        return "apache"
    if auth_hits >= max(1, len(sample) // 3):
        return "auth"
    return "unknown"


# ── Apache/Nginx parser ───────────────────────────────────────────────────────

def _parse_apache(lines: list[str]) -> LogSummary:
    ip_counter: Counter[str] = Counter()
    status_counter: Counter[str] = Counter()
    error_by_hour: Counter[str] = Counter()
    parsed = 0

    for line in lines:
        m = _APACHE_RE.match(line)
        if not m:
            continue
        parsed += 1
        ip = m.group("ip")
        status = m.group("status")
        ip_counter[ip] += 1

        group = f"{status[0]}xx"
        status_counter[group] += 1

        if status.startswith(("4", "5")):
            mon = _MON_MAP.get(m.group("mon"), "00")
            hour_str = f"{m.group('year')}-{mon}-{m.group('day').zfill(2)} {m.group('hour')}"
            error_by_hour[hour_str] += 1

    total_requests = sum(ip_counter.values())
    top_ips = ip_counter.most_common(20)
    # Pad percentage info into count (caller can compute %)
    error_hours = sorted(error_by_hour.items(), key=lambda x: x[1], reverse=True)[:10]

    return LogSummary(
        format="apache",
        total_lines=len(lines),
        parsed_lines=parsed,
        top_ips=top_ips,
        status_counts=dict(status_counter),
        error_by_hour=error_hours,
        failed_auth=[],
        failed_auth_ips=[],
    )


# ── SSH auth.log parser ───────────────────────────────────────────────────────

def _parse_auth(lines: list[str]) -> LogSummary:
    user_counter: Counter[str] = Counter()
    ip_counter: Counter[str] = Counter()
    parsed = 0

    for line in lines:
        m = _AUTH_FAILED_RE.search(line)
        if not m:
            m = _AUTH_INVALID_RE.search(line)
        if m:
            parsed += 1
            user_counter[m.group("user")] += 1
            ip_counter[m.group("ip")] += 1

    return LogSummary(
        format="auth",
        total_lines=len(lines),
        parsed_lines=parsed,
        top_ips=[],
        status_counts={},
        error_by_hour=[],
        failed_auth=user_counter.most_common(20),
        failed_auth_ips=ip_counter.most_common(20),
    )


# ── Public API ────────────────────────────────────────────────────────────────

def analyse(path: str, stop_event=None) -> LogSummary:
    """Read a log file and return a LogSummary. Never raises."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines: list[str] = []
            for i, line in enumerate(fh):
                if stop_event and stop_event.is_set():
                    break
                lines.append(line.rstrip("\n"))
                if i > 0 and i % 10_000 == 0 and stop_event and stop_event.is_set():
                    break
    except OSError as exc:
        _empty = LogSummary("unknown", 0, 0, [], {}, [], [], [])
        return _empty

    fmt = _detect_format(lines)
    if fmt == "apache":
        return _parse_apache(lines)
    if fmt == "auth":
        return _parse_auth(lines)
    return LogSummary("unknown", len(lines), 0, [], {}, [], [], [])
