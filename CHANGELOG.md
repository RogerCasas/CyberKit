# Changelog

All notable changes to CyberKit are recorded here, grouped by release date.

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
