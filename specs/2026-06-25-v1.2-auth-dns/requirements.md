# v1.2 — Auth & DNS Recon: Requirements

## Problem Statement

CyberKit v1.1 covers passive web inspection and network recon (port scanning, header analysis, directory fuzzing). v1.2 adds two active recon modules that teach the next layer of pen-testing fundamentals: how credential-based attacks work and how DNS infrastructure is mapped. These are core skills for HackTheBox, CTF, and OSCP-style labs.

## In Scope

### Credential Tester
- **HTTP tab** — supply a login URL, a username list, and a password list; try combinations via HTTP POST (form-based) and HTTP Basic auth; report successes live in a results table.
- **SSH tab** — supply a host + port, a username list, and a password list; use Paramiko to test SSH login; report successes live.
- **Configurable delay** between attempts (default 0.5 s, user-adjustable) — mandatory rate-limiting to prevent accidental DoS and teach responsible use.
- **Custom wordlist file import** — Browse button lets the user load a .txt wordlist from disk for both username and password lists (one entry per line).
- **Bundled default wordlist** — a small default credential list in `app/data/wordlists.py` for quick demos.
- Start/Stop control, live results table (Treeview), export to CSV/TXT, disclaimer banner.

### DNS & Subdomain Enumerator
- **Record lookup** — resolve A, AAAA, MX, NS, TXT records for a given domain.
- **Subdomain brute-force** — thread-pool wordlist scan; each candidate tested via DNS A/AAAA resolution.
- **Bundled subdomain wordlist** in `app/data/wordlists.py` (≈500 common subdomains).
- **Custom wordlist file import** — Browse button for user-supplied .txt subdomain lists.
- Start/Stop control, live results table (Treeview), export to CSV/TXT, disclaimer banner.

## Out of Scope

- HTTPS/TLS certificate validation during credential testing (not required for lab targets).
- CSRF token handling for HTTP form login (complex; documented as a known limitation).
- Async DNS (dnspython sync API is sufficient; async adds complexity with no learner benefit here).
- GUI settings persistence (v2.x candidate per roadmap).
- Any exploitation capability beyond credential verification.

## Key Decisions & Constraints

- **Architecture** — same scan engine / queue / poll pattern as existing modules (thread pool → `queue.Queue` → `widget.after` poll). No Tk widgets touched from worker threads (hard constraint from `tech-stack.md`).
- **No admin/root required** — SSH via Paramiko (pure Python), DNS via dnspython; no raw sockets.
- **No C extensions** — Paramiko and dnspython are both pure-Python-compatible.
- **New dependencies** — `dnspython>=2.4.0` and `paramiko>=3.4.0` added to `requirements.txt` (already documented in `tech-stack.md` as v1.2 additions).
- **Responsible use** — mandatory delay slider in Credential Tester; disclaimer banner on both modules; modules scoped to targets the user owns or has explicit permission to test (per `mission.md`).
- **Windows-first** — Paramiko and dnspython both work on Windows without additional system packages.

## Open Questions

None — all scope and approach decisions resolved in planning interview.
