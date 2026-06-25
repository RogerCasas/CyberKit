# Plan — v1.1: Network & Header Visibility

Each group is independently testable before the next begins.

---

## Group 1 — Port data (`app/data/port_lists.py`)

**1.1** Create `app/data/port_lists.py` containing:
- `TOP_1000_PORTS: list[int]` — the 1000 most commonly open ports, frequency-ranked (mirrors nmap's default scan list).
- `WELL_KNOWN_SERVICES: dict[int, str]` — port → service name for the ~250 most recognisable ports (HTTP, HTTPS, SSH, FTP, SMTP, DNS, RDP, etc.).

**1.2** Verify: `from app.data.port_lists import TOP_1000_PORTS, WELL_KNOWN_SERVICES` imports cleanly; `len(TOP_1000_PORTS) == 1000`; `WELL_KNOWN_SERVICES[80] == "HTTP"`.

---

## Group 2 — Port Scanner engine (`app/modules/port_scanner.py`)

**2.1** Define dataclasses:
```
@dataclass
class PortResult:
    port: int
    status: str          # OPEN | CLOSED | FILTERED
    service: str         # from WELL_KNOWN_SERVICES or ""
    banner: str          # first 256 bytes decoded, or ""
    response_ms: int

@dataclass
class ScanSummary:
    host: str
    total: int
    open: int
    filtered: int
    closed: int
    errors: int
    results: list[PortResult]
```

**2.2** Implement `PortScanEngine.__init__(host, ports, threads, timeout_s, grab_banner)`.
- Normalise `host`: strip scheme, trailing slashes, and path — extract hostname/IP only.
- Store `stop_event = threading.Event()`.

**2.3** Implement `_probe(port) -> PortResult`:
- `socket.setdefaulttimeout(timeout_s)`; `socket.connect_ex((host, port))`.
- Return code 0 → OPEN; `errno.ECONNREFUSED` → CLOSED; everything else / timeout → FILTERED.
- If OPEN and `grab_banner`: wrap socket in a 1-second receive; decode first 256 bytes as UTF-8 (errors='replace'), strip control characters.
- Populate `service` from `WELL_KNOWN_SERVICES.get(port, "")`.
- Record elapsed ms.

**2.4** Implement `start(on_result, on_done)`:
- Background `threading.Thread` wrapping a `ThreadPoolExecutor`.
- `as_completed()` loop; check `stop_event` between futures; call `on_result(PortResult)` for each.
- Call `on_done(ScanSummary)` when loop exits.

**2.5** Implement `stop()` → set `stop_event`.

**2.6** Verify standalone: instantiate engine against `127.0.0.1` with a 5-port list; confirm OPEN detected for any locally listening port (e.g. 135 on Windows).

---

## Group 3 — Port Scanner UI (`app/ui/pages/port_scanner.py`)

**3.1** Build controls card:
- Host entry (placeholder `192.168.1.1 or hostname`)
- Scan mode: `CTkSegmentedButton` → "Top 1000" / "Custom Range"
- Custom range row (hidden by default, revealed when "Custom Range" selected): two `CTkEntry` widgets for `from` and `to` port, validated to int 1–65535
- Banner grab `CTkCheckBox`
- Threads slider (10–200, default 100)
- Timeout slider (0.5–3.0 s, default 1.0, step 0.5)
- Start / Stop button

**3.2** Build summary cards: Open (green) · Filtered (amber) · Closed (grey) · Errors (red). Same 5-card row pattern as `FuzzerPage`.

**3.3** Build Treeview results table: Port | Service | Status | Banner | Response (ms).
- Tags: `open` (green), `filtered` (amber), `closed` (grey), `error` (red); alternating row backgrounds.
- Default display filter: show Open + Filtered; Closed rows inserted but hidden via treeview `detach()` and a toggle checkbox "Show closed ports".

**3.4** Wire polling (80 ms, batch 60):
- No-filter fast path: incremental `tree.insert()` as results arrive.
- Filter change: full `tree.delete(*children)` + re-insert.

**3.5** Add filter bar: text search on port/service/banner + category dropdown (All / Open / Filtered / Closed / Error).

**3.6** Add export (CSV + TXT). CSV columns: Port, Service, Status, Banner, Response (ms).

**3.7** Add inline disclaimer label below the host entry: "Only scan hosts you own or have explicit permission to test."

---

## Group 4 — Header Analyser engine (`app/modules/header_analyser.py`)

**4.1** Define dataclasses:
```
@dataclass
class HeaderRule:
    name: str            # HTTP header name, lowercase
    severity: str        # critical | high | medium | info
    weight: int          # grade points
    https_only: bool     # skip gracefully on HTTP
    check_fn: Callable[[str | None], tuple[str, str]]
    # returns (status: "ok"|"warn"|"missing", tip: str)

@dataclass
class HeaderFinding:
    rule: HeaderRule
    raw_value: str | None   # None = header absent
    status: str             # ok | warn | missing | skipped
    tip: str
    score: int              # actual points awarded (0 = missing/warn, weight = ok)
```

**4.2** Define `HEADER_RULES: list[HeaderRule]` for the 6 scored headers + 3 info-leak headers.
- CSP check: present → ok (25 pts); present but contains `unsafe-inline`/`unsafe-eval` → warn (12 pts); absent → missing (0 pts).
- HSTS check: `max-age` ≥ 31536000 → ok (25 pts); present but low max-age → warn (12 pts); absent → missing (0 pts).
- X-Frame-Options: DENY/SAMEORIGIN → ok; ALLOW-FROM → warn; absent → missing.
- X-Content-Type-Options: `nosniff` → ok; other value → warn; absent → missing.
- Referrer-Policy: present and not `unsafe-url` → ok; absent → missing.
- Permissions-Policy: present → ok; absent → missing.
- Server / X-Powered-By / X-AspNet-Version: present → info finding (not scored, flag as leaking).

**4.3** Implement `analyse(url: str) -> list[HeaderFinding]`:
- `requests.get(url, timeout=10, allow_redirects=True)` with browser UA; access `resp.headers`.
- Detect scheme from final URL (after redirects) to handle HSTS skip correctly.
- Run each rule's `check_fn` against the header value or `None`.

**4.4** Implement `compute_grade(findings: list[HeaderFinding]) -> tuple[str, int, int]` → (letter, score, max_score):
- Sum `f.score` for non-skipped findings; sum `f.rule.weight` for applicable rules.
- Apply grade thresholds from requirements.

**4.5** Verify standalone: call `analyse("https://example.com")` and print findings; confirm grade is computed; confirm HSTS-skipped gracefully on `http://` URL.

---

## Group 5 — Header Analyser UI (`app/ui/pages/header_analyser.py`)

**5.1** Build controls: URL entry + "Analyse" button (single-shot, no streaming). Show spinner/status label while request in flight (run `analyse()` in a `threading.Thread`; return result via `queue.Queue`; poll with `after()`).

**5.2** Build grade display widget: large letter grade (e.g. "B"), colour-coded (A+/A=green, B=cyan, C=amber, D/F=red), score subtitle ("65 / 85 pts").

**5.3** Build findings Treeview: Header | Value | Status | Severity | Tip.
- Status icons: ✓ (ok, green), ⚠ (warn, amber), ✕ (missing, red), — (skipped, grey), ℹ (info, cyan).
- Row click: show full tip text in a read-only text box below the table.

**5.4** Build info-leak section: a compact card listing detected information-leaking headers (Server, X-Powered-By, etc.) with their values and a single remediation note: "Remove or mask these headers in your server config."

**5.5** Add TXT export: grade + all findings with values and tips.

---

## Group 6 — Integration

**6.1** Register `PortScannerPage` and `HeaderAnalyserPage` in `app/ui/app_window.py` (`_register_pages`).

**6.2** Add `("Port Scanner", "🔍", "port_scanner")` and `("Header Analyser", "🛡", "header_analyser")` to `NAV_ITEMS` in `sidebar.py`.

**6.3** Update `MODULE_CARDS` in `home.py`: change both cards' `tag` from `"Coming Soon"` to `"Active"`, set `tag_color` to `"#22c55e"`, and wire `page` keys.

**6.4** Update `implementation_plan.md` spec index: mark specs 02 and 03 as `✅ v1.1`.

**6.5** Update `roadmap.md`: add ✅ to both v1.1 module rows.
