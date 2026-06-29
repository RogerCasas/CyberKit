# v4.1 — Web Attack Expansion — Requirements

## Problem statement and motivation

CyberKit's web-testing surface currently covers enumeration (Dir Fuzzer),
passive audit (Header Analyser), raw request crafting (HTTP Builder), and
injection detection (SQLi Tester). Three of the most common web vulnerability
classes that learners encounter — **reflected XSS**, **CSRF weaknesses**, and
**open redirects** — have no dedicated module.

v4.1 adds three detection-only modules under the existing **Web / Active
Testing** category so learners can see *how* each class is probed and *why* a
response signature indicates a finding, consistent with the "educational first,
honest tooling" values in `mission.md`.

## In scope

- **XSS Tester** — Inject a set of reflected XSS payloads into each GET/POST
  parameter and detect whether the payload is reflected **unescaped** in the
  response body. Distinguishes raw reflection (vulnerable) from
  HTML-entity-encoded reflection (safe) and reports the reflection context
  (HTML body / tag attribute / script block) heuristically. Detection only —
  **no browser execution, no headless rendering.**
- **CSRF Analyser** — Fetch a target URL and inspect its CSRF posture:
  `Set-Cookie` headers for `SameSite` / `Secure` / `HttpOnly` flags, form HTML
  for hidden anti-CSRF token fields, and a best-effort Origin/Referer
  validation probe (resend with a spoofed/missing `Origin` and compare). Output
  is a findings list with severity, mirroring the Header Analyser style.
- **Open Redirect Detector** — Inject external-host redirect payloads
  (`//evil`, `https://evil`, `/\evil`, scheme-relative and backslash variants)
  into each GET/POST parameter, send with redirects **disabled**, and flag any
  `3xx` whose `Location` header resolves to the external sentinel host.
- **Shared injection helper** (`app/modules/web_injection.py`) — Extract the
  GET/POST parameter-injection and query-parsing logic (currently private in
  `sqli_tester.py`) into a reusable module used by XSS, Open Redirect, and
  (refactored) SQLi.
- Three new UI pages following the SQLi Tester page pattern (URL + method +
  optional params, disclaimer banner, live `ttk.Treeview` results, CSV/TXT
  export, background-thread + `queue` polling).
- Wiring: `categories.py` (three entries under `web_active`), `home.py` cards
  (three new **Active** cards), `app_window.py` page registration, sidebar
  version label → `v4.1.0`.
- Automated engine unit tests for all three engines + the shared helper.

## Out of scope

- Any payload that *executes* in a browser. All three modules are pure
  request/response signature detectors. No Selenium/Playwright/CEF.
- Stored/DOM-based XSS (requires JS execution and stateful crawling) — reflected
  only.
- CSRF *exploitation* (auto-generating a working PoC HTML form). The analyser
  reports posture and findings; it does not weaponise them.
- Following redirect chains or multi-hop redirect analysis — single-response
  `Location` inspection only.
- Authentication/session handling, crawling, or automatic form discovery beyond
  the single submitted URL.
- A local bundled vulnerable test server (validation uses mocked-HTTP unit tests
  plus manual checks against public practice targets — see `validation.md`).

## Key decisions and constraints

- **Per-module engine + shared helper** (chosen approach). Each module gets its
  own `app/modules/<name>.py` engine and `app/ui/pages/<name>.py` page, but the
  parameter-injection/parsing plumbing lives once in
  `app/modules/web_injection.py`. SQLi Tester is refactored to consume it so
  there is a single implementation (regression-guarded by its existing 15 tests).
- **Reuse `http_builder.send()`** for all network I/O (`tech-stack.md`: requests
  is the one HTTP path). Open Redirect calls it with `follow_redirects=False` to
  capture the `3xx` + `Location`; that parameter already exists.
- **Unique reflection marker** — XSS payloads embed a random sentinel token so
  reflection detection is unambiguous and resistant to incidental page text.
- **External sentinel host** — Open Redirect uses a fixed, non-resolving
  sentinel (e.g. `cyberkit-redirect-test.example`) so a positive match cannot
  accidentally point at a real third party.
- **No admin/root, no C extensions** (`tech-stack.md` constraints) — all three
  are plain HTTP over `requests`.
- **Thread-safety** — engines run in a background `threading.Thread`; results
  reach the UI via `queue.Queue` drained by `widget.after(...)`. No Tk widget is
  touched off the main thread (hard architectural constraint).
- **Responsible-use disclaimer** — every page carries the same permission
  banner already used by the SQLi Tester.
- Detection-only scope keeps v4.1 inside the project's stated non-goal of "not a
  replacement for Burp Suite / Metasploit."

## Open questions

- None blocking. CSRF Origin/Referer probing is inherently heuristic; the spec
  treats a reflected/accepted spoofed Origin as an *informational* finding, not
  a hard "vulnerable" verdict, to avoid false confidence.
