# Validation — v1.1: Network & Header Visibility

Pass/fail is unambiguous for every item. Both automated and manual testing required.

---

## Group 1 — Port data

- [x] `from app.data.port_lists import TOP_1000_PORTS, WELL_KNOWN_SERVICES` imports with no errors
- [x] `len(TOP_1000_PORTS) == 1000`
- [x] `len(set(TOP_1000_PORTS)) == 1000` (no duplicates)
- [x] `all(1 <= p <= 65535 for p in TOP_1000_PORTS)` is True
- [x] `WELL_KNOWN_SERVICES[80] == "HTTP"` and `WELL_KNOWN_SERVICES[443] == "HTTPS"` and `WELL_KNOWN_SERVICES[22] == "SSH"`

---

## Group 2 — Port Scanner engine (automated)

Run `python tests/test_port_scanner.py` (create this file as part of the implementation):

- [x] A temporary `socket.socket` server bound to a random free port on `127.0.0.1` is detected as **OPEN** within 2 seconds
- [x] A port that is not listening on `127.0.0.1` is detected as **CLOSED** or **FILTERED** (not OPEN)
- [x] `stop()` called mid-scan halts within 2 seconds and `on_done` is still called
- [x] With `grab_banner=True` and a server that sends a greeting, `result.banner` is non-empty
- [x] Host normalisation: `PortScanEngine("https://example.com/path", [80], ...)` stores host as `"example.com"` (scheme and path stripped)
- [x] Engine raises no exception when given an unreachable host (all ports return FILTERED or ERROR)

---

## Group 3 — Port Scanner UI (manual)

Test against `127.0.0.1` and one external authorised host.

- [x] App launches without errors after integration (Group 6)
- [x] "Port Scanner" appears in sidebar and clicking it navigates to the page
- [x] "Top 1000" mode: custom range inputs are hidden; scan runs over 1000 ports
- [x] "Custom Range" mode: from/to inputs appear; entering `20`–`25` scans exactly 6 ports
- [x] Invalid range (e.g. from > to, or non-integer) shows an inline error, does not start scan
- [x] Scan of `127.0.0.1` port 1–1024 completes and shows at least one OPEN port (e.g. 135 on Windows)
- [x] Stop button halts scan; partial results are visible and summary counts are correct
- [x] "Show closed ports" checkbox: unchecked hides closed rows; checked shows them
- [x] Text search filters table in real time (e.g. typing "http" shows ports whose service contains "http")
- [x] Category dropdown "Open" shows only OPEN rows
- [x] With `grab_banner=True` and a target running SSH, the banner column shows something like `SSH-2.0-…`
- [x] CSV export produces a file with correct headers and one row per result
- [x] TXT export produces a readable report with all findings
- [x] Disclaimer text is visible below the host entry

---

## Group 4 — Header Analyser engine (automated)

Run `python tests/test_header_analyser.py`:

- [x] `compute_grade` returns `"A+"` when all 6 headers are present and correctly configured (mock response)
- [x] `compute_grade` returns `"F"` when all headers are absent
- [x] HSTS finding is `status == "skipped"` when URL scheme is `http://`
- [x] CSP with `unsafe-inline` in value produces `status == "warn"` (not "ok")
- [x] X-Content-Type-Options with value `"nosniff"` produces `status == "ok"`
- [x] Score for a warning finding is between 0 and `rule.weight` (partial credit awarded)
- [x] Info-leak findings for `Server` and `X-Powered-By` headers are included but do not affect the grade score

---

## Group 5 — Header Analyser UI (manual)

Test against `https://example.com`, `http://enriqueite.com/demoGPT/`, and one well-secured site (e.g. `https://github.com`).

- [x] "Header Analyser" appears in sidebar; navigation works
- [x] Analysing `https://example.com` completes in < 5 seconds and shows results
- [x] Grade letter is displayed large and colour-coded (green for A/A+, amber for B/C, red for D/F)
- [x] Each header row shows: name, value or "MISSING", status icon (✓ / ⚠ / ✕ / — / ℹ)
- [x] Clicking a finding row shows the full tip text in the detail area below the table
- [x] HSTS row shows "Skipped (HTTP)" for `http://` target; no false penalty in grade
- [x] Info-leak section appears when `Server` or `X-Powered-By` is detected
- [x] TXT export produces a readable report with grade, score, and all findings
- [x] Empty URL shows inline error; does not attempt request
- [x] Analysing an unreachable URL shows a clear error message (not a crash)

---

## Group 6 — Integration

- [x] Both new pages load without errors in the full app
- [x] Sidebar shows all four nav items: Home, Dir Fuzzer, Port Scanner, Header Analyser — in that order
- [x] Home page: Port Scanner and Header Analyser cards show "Active" tag (green), not "Coming Soon"
- [x] Clicking either card on home page navigates to the correct module
- [x] `implementation_plan.md` spec index rows 02 and 03 marked `✅ v1.1`
- [x] `roadmap.md` v1.1 module rows marked `✅ Done`

---

## Documentation

- [x] `specs/2026-06-25-v1.1-network-header/requirements.md` committed
- [x] `specs/2026-06-25-v1.1-network-header/plan.md` committed
- [x] `specs/2026-06-25-v1.1-network-header/validation.md` committed
- [x] `specs/02-port-scanner.md` created (or this folder serves as spec 02+03)
- [x] `CHANGELOG.md` updated with v1.1 entry after implementation completes (via `/changelog`)
