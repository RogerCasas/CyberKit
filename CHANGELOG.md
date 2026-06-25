# Changelog

All notable changes to CyberKit are recorded here, grouped by release date.

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
