# v3.1 — Web Attack Utilities: Requirements

---

## Problem Statement

CyberKit currently covers recon and enumeration, but stops before the "interact with the target" phase of manual web testing. Learners need two capabilities that bridge recon and exploitation:

1. **Crafting raw HTTP requests** — understanding exactly what gets sent (method, headers, body) and reading the full raw response is a prerequisite for manual testing and a natural follow-on to the Header Analyser.
2. **Detecting SQL injection** — knowing that a parameter is injectable (without extracting data) is the first step in web exploitation and a key CTF skill. Detection-only keeps the tool scoped to reconnaissance per the mission.

---

## In Scope

### HTTP Request Builder / Replay
- HTTP methods: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS
- Arbitrary request headers: an editable key/value list with Add / Remove row buttons
- Request body: raw text input (useful for JSON, form data, XML)
- Full response display: status code + reason, response headers, response body
- Follow-redirects toggle (on by default)
- Elapsed time shown alongside status
- Inline error display for connection failures, timeouts, and invalid URLs
- Background thread + queue pattern (hard architectural constraint — no Tk calls from worker thread)

### SQL Injection Tester (detection only)
- URL + HTTP method (GET / POST) as inputs
- Parameter list: auto-parsed from the URL query string; also manually editable
- **Error-based detection**: inject a common error payload (`'`) and scan the response body for known DB error strings (MySQL, MSSQL, Oracle, PostgreSQL, SQLite)
- **Boolean-based detection**: send a baseline request, then compare response content/length for `' AND 1=1--` (should match baseline) vs `' AND 1=2--` (should differ)
- Results table: one row per (parameter, payload) combination showing detection type, evidence snippet, and verdict
- Background thread + queue; live progress label
- Disclaimer: "Only test systems you own or have explicit permission to test."
- Reuses the HTTP request engine from the HTTP Builder module

---

## Out of Scope

- UNION-based or time-based blind SQLi (extraction / exfiltration)
- XSS, command injection, or any other injection type
- Authentication in the HTTP Builder (Credential Tester already covers that)
- Multipart / file upload in the HTTP Builder
- Response body diffing beyond content-length comparison for boolean detection
- Saving / replaying request history
- Proxy support or intercepting traffic

---

## Key Decisions & Constraints

- **`requests` library** is already in `requirements.txt` — use it for both modules. No new network dependency needed.
- **Shared engine**: `app/modules/http_builder.py` exposes a `send()` function; `app/modules/sqli_tester.py` imports it for its probe requests, keeping networking logic in one place.
- **No new dependencies** for v3.1 (no Scapy, no BeautifulSoup — response parsing is plain string search).
- **Thread safety**: same `threading.Thread` + `queue.Queue` + `widget.after()` pattern as all other modules.
- **Detection only**: the SQLi tester must not attempt data extraction. Scope matches `mission.md` ("reconnaissance, enumeration, and analysis").
- **Windows-first**: UI must render correctly on Windows 11 / CustomTkinter 5.2+.

---

## Open Questions

None — all answered during spec interview.
