# Changelog

All notable changes to CyberKit are recorded here, grouped by release date.

---

## 2026-06-29 — v4.0 UI Category Grouping & Scroll Fixes

- Implemented the v4.0 **collapsible sidebar category accordion**: the flat "MODULES" list is now grouped into seven named, collapsible categories (Web / Active Testing, Network / Recon, Auth & Exploitation, DNS & OSINT, Cryptanalysis & Encoding, Tech Analysis, Wordlist & Utilities). Each header expands/collapses its tools; expanded state persists while the app runs.
- Implemented the v4.0 **home page category sections**: the module card grid is reorganised into labelled sections matching the sidebar categories, each with a heading and separator, preserving the existing Active / Coming Soon tags.
- Added `app/data/categories.py` as the single source of truth (`CATEGORIES`, `ToolEntry`, `Category`, `PAGE_TO_CATEGORY`) shared by the sidebar and home page.
- Navigating to a tool auto-expands its category without collapsing the others; clicking **Home** collapses every category.
- Added tooltips on the collapsed (icon-only) sidebar: hovering a tool icon now shows its name.
- Fixed the sidebar navigation scrollbar never appearing when the category list overflows — `AutoHideScrollFrame` now lays out its canvas and scrollbar with `grid` (scrollbar in a reserved column toggled via `grid()`/`grid_remove()`) instead of `pack`, which starved a later-added scrollbar to 1 px. Gave the sidebar scrollbar visible thumb colours.
- Fixed the spurious scrollbar that appeared mid-page on ARP Scanner, WHOIS & Geo, Hash Tool, Encoder/Decoder, Tech Fingerprinter, and SSL Analyser. `AutoHideScrollFrame._sync` now defers layout until the canvas has a real size and compares the content's natural height against the viewport, so the scrollbar shows only on genuine overflow.
- Set `height=1` on all ten `ttk.Treeview` result tables so their inflated 10-row (~320 px) minimum no longer pushes pages past the viewport; they still expand to fill via `weight=1` at runtime.
- Replaced redundant `CTkScrollableFrame` wrappers with `CTkFrame` in the Hash Tool and SSL Analyser detail panels, and switched Treeview scrollbars to the auto-hiding `autohide_vsb` helper.
- Marked v4.0 ✅ Complete in `roadmap.md`.

---

## 2026-06-28 — Replanning: v4.0–v4.5 Milestones & Scope Expansion

- Expanded roadmap with six new milestones (v4.0–v4.5) covering 13 new modules across UI reorganisation, web attack expansion, network recon, cryptanalysis & CTF utilities, OSINT, and blue-team forensics.
- v4.0 introduces collapsible sidebar category groups and home page category sections, applying seven category labels retroactively to all existing tools.
- v4.1 adds XSS Tester, CSRF Analyser, and Open Redirect Detector.
- v4.2 adds Traceroute, Banner Grabber, and Packet Sniffer.
- v4.3 adds JWT Forge & Verify and Cipher Identifier & Solver.
- v4.4 adds Email Header Analyser, Robots.txt & Sitemap Parser, and CVE / Vulnerability Lookup.
- v4.5 adds Log Analyser, File Metadata Extractor, and Hash Verifier.
- Updated `tech-stack.md` with metadata extraction dependencies for v4.5 (`Pillow`, `pypdf`, `python-docx`, `openpyxl`), ADR-005 (collapsible sidebar accordion via `grid_remove` toggle), and ADR-006 (NVD unauthenticated rate-limit policy and 6-second query sleep).
- Updated `mission.md` scope to explicitly include blue-team investigation alongside reconnaissance, enumeration, and analysis. Clarified that the v4.2 Packet Sniffer is an educational protocol visualiser, not a replacement for Wireshark.

---

## 2026-06-27 — v3.2 Polish: Scrolling, UI Fixes & Privacy

- Replaced the page-level scroll implementation (`AutoHideScrollFrame`) with a `CTkScrollbar`-based design: the scrollbar now matches the rounded, minimalist style used by `CTkScrollableFrame` throughout the app.
- Fixed mousewheel scrolling: replaced the broken canvas `<Enter>`/`<Leave>` approach with a single toplevel binding that checks cursor position — now works correctly over all child widgets including nav items and cards.
- Fixed initial scrollbar visibility: `_sync` now defers via `after_idle` and manually triggers the yscrollcommand after setting the scroll region, so the scrollbar appears correctly on first render.
- Fixed teardown crash (`TclError: invalid command name`) by overriding `_update_dimensions_event` in `AutoHideScrollFrame` to catch errors during window close.
- Fixed home page module card hover/click not working when the cursor was over the title or tag badge — bindings are now applied recursively to all descendants.
- Removed redundant `CTkScrollableFrame` wrappers from the home page card container and the SQL Injection Tester page — these conflicted with the outer `AutoHideScrollFrame` and produced a spurious scrollbar in the middle of the page.
- Switched `theme_use("clam")` to apply once at startup so custom ttk colours (Treeview scrollbars in ARP, Port Scanner, SQLi, etc.) are honoured on Windows — the default Vista theme ignores colour overrides.
- Wordlist Generator live preview upgraded from a fixed 20-entry grid to a scrollable `CTkScrollableFrame` containing up to 200 entries; the preview panel fills its column and the user scrolls within it rather than enlarging the window.
- Removed the 1 000 000-entry generation cap from the wordlist generator engine.
- Performed a privacy audit of the repository: no personal paths, IPs, or secrets found in tracked files. Git commit email changed to a GitHub noreply alias for future commits.

---

## 2026-06-26 — v3.2 Password & Network Tools

- Added **Password / Wordlist Generator** module: two-tab interface for charset brute-force (itertools.product, lowercase/uppercase/digits/symbols, min/max length) and seed-phrase mutation (leet-speak, case variants, numeric suffixes 1–99, custom prefix/suffix). Both tabs show a live 20-entry preview updating in real time. Generation capped at 1,000,000 entries with warning. Export to `.txt` via background thread with progress label. "Send to Credential Tester" buttons wire the exported list directly into the Credential Tester (username or password list) without navigating away.
- Added **ARP Scanner** module: broadcasts ARP requests on a user-supplied subnet (or auto-detected CIDR), resolves vendor from a bundled OUI table, performs best-effort reverse-DNS hostname lookup. Live Treeview (IP, MAC, Vendor, Hostname), auto-scroll, CSV/TXT export. Privilege check on scan start — shows a clear error if not running as administrator instead of crashing. Admin warning banner always visible above the controls.
- Added `app/modules/wordlist_generator.py` — `BruteforceGenerator`, `MutationGenerator`, `generate_to_file`.
- Added `app/modules/arp_scanner.py` — `ARPScanner`, `check_privileges`, `auto_detect_subnet`.
- Added `app/data/oui_table.py` — bundled OUI vendor lookup table with `lookup_vendor()`.
- Added `scapy>=2.5.0` to `requirements.txt` (requires administrator/root at runtime).
- Updated sidebar with Wordlist Gen and ARP Scanner nav items; bumped version label to v3.2.0.
- Promoted Wordlist Generator and ARP Scanner home-page cards to Active.
- Marked v3.2 ✅ Complete in roadmap.md.

---

## 2026-06-26 — v3.1 Web Attack Utilities

- Added **HTTP Request Builder / Replay** module: craft custom HTTP requests (method, headers, body) and inspect the full raw response — status code with colour-coded badge, response headers, and response body. Supports GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, follow-redirects toggle, and arbitrary request headers via a dynamic add/remove editor.
- Added **SQL Injection Tester** module: inject payloads into GET and POST parameters to detect SQL injection via error-based signatures (MySQL, MSSQL, Oracle, PostgreSQL, SQLite) and boolean-based content-length divergence. Detection only — no data extraction. Includes a mandatory disclaimer banner reminding users to only test systems they own or have explicit permission to test.
- Added `app/modules/http_builder.py`: shared HTTP engine backed by `requests`; returns a `RequestResult` dataclass, never raises exceptions — errors are surfaced in the `error` field.
- Added `app/modules/sqli_tester.py`: SQLi detection engine with 4 error payloads (single quote, double quote, backslash, quote+paren) and 5 boolean probe sets (AND string, AND numeric, OR string, AND bracket, OR numeric); each probe iterates with early exit on first detection.
- Added 18 automated engine tests: 3 for the HTTP engine and 15 for the SQLi engine — covering all supported DB error patterns, all boolean probe strategies, `_inject` GET/POST mechanics, `_parse_params`, and `scan()` integration.
- Updated sidebar navigation (HTTP Builder, SQLi Tester items), home-page module cards (two new Active cards), `app_window.py` page registration, and version label to `v3.1.0`.
- Marked v3.1 complete in `roadmap.md`.

---

## 2026-06-26 — v3.0 Passive Recon Expansion

- Added **SSL/TLS Certificate Analyser** module: connects to any host over TLS, retrieves the certificate, and displays CN, issuer, subject alternative names, serial number, signature algorithm, and validity dates. Status badges flag expired (red), near-expiry < 30 days (amber), and self-signed (amber) certificates; valid certs from a trusted CA show green. Scrollable cert-details panel handles long SAN lists.
- Added **WHOIS & Geolocation** module: two-tab page combining domain WHOIS lookup (registrar, creation/expiry dates, registrant org, name servers via `python-whois`) and IP geolocation (country, region, city, ISP, org, ASN via ip-api.com). Domain names are resolved to IP automatically for the geo tab. URL normalisation strips `https://` and trailing paths.
- Added `app/modules/ssl_analyser.py`: SSL engine using `ssl.CERT_NONE` context + `cryptography` library for DER certificate parsing; exports `_compute_status` and `_extract_sans` helpers for unit testing.
- Added `app/modules/whois_engine.py`: WHOIS engine with type-safe normalisation helpers that handle `None`, `str`, and `list[datetime]` field variants returned by `python-whois`.
- Added `app/modules/geo_engine.py`: geolocation engine backed by the ip-api.com free-tier JSON API; resolves domain names to IP before querying.
- Added 13 automated engine tests: 8 for SSL (`_compute_status` flags, SAN extraction, self-signed detection) and 5 for WHOIS/geo (mocked field parsing, error handling).
- Fixed SAN extraction bug: `get_values_for_type(x509.DNSName)` returns plain strings, not `DNSName` objects — removed erroneous `.value` attribute access.
- Added `cryptography>=3.3` and `python-whois>=0.9.0` to `requirements.txt`.
- Updated sidebar navigation (SSL Analyser, WHOIS & Geo items), home-page module cards (two new Active cards), `app_window.py` page registration, and version label to `v3.0.0`.
- Marked v3.0 complete in `roadmap.md`; committed spec files and fully-checked validation checklist.

---

## 2026-06-26 — Roadmap Replanning

- Restructured `roadmap.md`: promoted all six v2.x future candidates into three scheduled milestones — v3.0 (SSL/TLS Certificate Analyser + WHOIS & IP Geolocation), v3.1 (HTTP Request Builder + SQL Injection Tester), and v3.2 (Password/Wordlist Generator + ARP Scanner). Each milestone now has a full description table and module summaries.
- Updated `tech-stack.md`: added `python-whois` (v3.0) and `scapy` (v3.2) to the networking dependency table; updated the dependency file block with version pins and per-milestone comments; updated the admin/root constraint note to reference v3.2 instead of "future candidate".

---

## 2026-06-26 — v2.0 Analysis & CTF Utilities

- Added **Encoder / Decoder** module: bidirectional transforms for URL encoding, Base64, Base64 URL-safe, HTML entities, hex, and ROT-13; JWT Inspect mode decodes the header and payload of a JWT without verifying the signature. All operations use stdlib only (`urllib.parse`, `base64`, `html`, `codecs`, `hashlib`). 14 automated engine tests.
- Added **Hash Tool** module: Identify tab pattern-matches a hash against MD5/NTLM/LM, SHA-1/MySQL4, SHA-256, SHA-512, MySQL5, and bcrypt by length and charset; Crack tab runs a dictionary attack via `hashlib` against MD5, SHA-1, SHA-256, or SHA-512 using the bundled wordlist (top-200 rockyou subset) or a custom file, with live progress bar and Stop support. 11 automated engine tests.
- Added **Tech Fingerprinter** module: issues a single HTTP GET and matches response headers, HTML body, cookie names, and `<meta>` tags against 37 signatures across 7 categories (CMS, Server, Language/Runtime, Framework, Frontend Library, CDN/Security, Cloud Storage). Results shown in a live Treeview; TXT export supported.
- Added `app/data/wordlists.py` `CRACK_WORDLIST` (236-entry rockyou top-200 subset) for the Hash Tool cracker.
- Added spec files for v2.0 (`specs/2026-06-26-v2.0-analysis-ctf/`).
- Fixed tab-button flickering on the Hash Tool page: replaced `grid_remove()`/`grid()` with `tkraise()` (same pattern as Credential Tester and DNS Enumerator).
- Wrapped the home-page module grid in a `CTkScrollableFrame` so all module cards remain accessible at any window size.
- Updated sidebar navigation, home-page module cards, and `roadmap.md` for v2.0; bumped version label to v2.0.0.

---

## 2026-06-26

- Expanded `SUBDOMAIN_WORDLIST` from 289 to 524 entries (521 unique) to satisfy the ≥ 500 spec requirement; new entries cover infrastructure, mail/DNS servers, CDN/media, observability tools, auth/identity, databases, CI/CD tooling, analytics, and miscellaneous common subdomains.
- Completed the v1.2 validation pass: marked all confirmed items in `specs/2026-06-25-v1.2-auth-dns/validation.md`; HTTP credential tester and DNS enumerator fully verified against a local test server; SSH tab flagged as pending until an OpenSSH server is available for testing.

---

## 2026-06-25 — v1.2 Auth & DNS Recon

- Added **Credential Tester** module: two-tab interface for HTTP (Basic auth + POST form) and SSH credential testing. Dictionary attack using bundled or custom username/password lists. Mandatory configurable rate-limiting delay (0–5 s). Live Treeview results with Success/Failed/Error colour coding. CSV and TXT export. Rate-limited thread-safe engine backed by `requests` (HTTP) and `paramiko` (SSH).
- Added **DNS & Subdomain Enumerator** module: Record Lookup tab resolves A, AAAA, MX, NS, TXT records with colour-coded Treeview; Subdomain Brute-Force tab uses a 150+ entry bundled wordlist or a custom .txt file, thread-pool scanner (5–100 threads), live progress bar, and CSV/TXT export. Backed by `dnspython`.
- Added `app/utils/file_helpers.py` — shared Browse-button / wordlist file import helper used by both new modules.
- Extended `app/data/wordlists.py` with `SUBDOMAIN_WORDLIST` (150+ entries), `DEFAULT_USERNAMES`, and `DEFAULT_PASSWORDS`.
- Added `dnspython>=2.4.0` and `paramiko>=3.4.0` to `requirements.txt`.
- Updated sidebar with Cred Tester and DNS Enumerator nav items; bumped version label to v1.2.0.
- Promoted Credential Tester and DNS Enumerator home-page cards from "Coming Soon" to "Active".
- Marked v1.2 complete in roadmap.md.

---

## 2026-06-25 (roadmap update)

- Extended v1.2 Credential Tester scope to include an SSH tab (Paramiko) alongside the existing HTTP module, following review of a reference implementation using Paramiko.
- Added ARP Scanner as a v2.x future candidate (Scapy, requires admin/root); noted the privilege constraint in both roadmap and tech-stack.
- Added Paramiko to the tech-stack dependency table and requirements list (ships with v1.2).

---

## 2026-06-25

- Added Port Scanner module: TCP connect scan over Top-1000 ports or a custom range, with optional banner grabbing, live results table, category/text filtering, and CSV/TXT export. Includes cross-platform socket error handling (Unix + Windows) and a 1000-port list assembled from a curated 700-port core plus well-known ports 1–1024.
- Added Header Analyser module: inspects HTTP response headers against the OWASP security baseline, computes a weighted grade (A+ through F) for CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy, detects info-leak headers (Server, X-Powered-By), and exports a full report. HSTS check is automatically skipped for plain-HTTP targets.
- Disabled sidebar hover auto-expand/collapse; the sidebar now only toggles when the arrow button is clicked.
- Promoted Port Scanner and Header Analyser home-page cards from "Coming Soon" to "Active".
- Added 15 automated engine tests (6 for Port Scanner, 9 for Header Analyser).

---

## 2026-06-24

- Initial release: CyberKit v1.0 with Directory Fuzzer module, collapsible sidebar, page-switching architecture, SDD constitution (mission, roadmap, tech-stack, implementation plan), and v1.1 spec.
