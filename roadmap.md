# CyberKit — Roadmap

Each milestone is a releasable version. Modules within a milestone are roughly ordered by implementation complexity.

---

## v1.0 — Foundation ✅ Complete

| Module | Category | Status |
|---|---|---|
| **Directory Fuzzer** | Web / Enumeration | ✅ Done |

Key infrastructure shipped in v1.0:
- Collapsible sidebar navigation
- Page-switching architecture (stackable frames)
- Thread-pool scan engine with live queue polling
- Wordlist system (616 paths)
- Treeview results table with filter + search + export

---

## v1.1 — Network & Header Visibility

| Module | Category | Core technique |
|---|---|---|
| **Port Scanner** | Network / Recon | TCP connect scan + optional banner grab |
| **Header Analyser** | Web / Security audit | HTTP response header inspection vs. OWASP baseline |

**Port Scanner** — nmap-inspired. Enter a host + port range, get a live table of open/closed/filtered ports with service guesses. Teaches the TCP handshake and common port numbers.

**Header Analyser** — Enter a URL, receive a grade and colour-coded breakdown of security headers: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`. Missing or misconfigured headers flagged as findings.

---

## v1.2 — Auth & DNS Recon

| Module | Category | Core technique |
|---|---|---|
| **Credential Tester** | Auth / Brute-force | HTTP form-based + Basic auth dictionary attack |
| **DNS & Subdomain Enumerator** | Recon / OSINT | DNS record lookup + wordlist-based subdomain brute-force |

**Credential Tester** — hydra-inspired (HTTP only). Supply a login URL, username list, and password list; the engine tries combinations and reports successes. Teaches HTTP auth flows without enabling mass attacks (rate-limiting built in).

**DNS & Subdomain Enumerator** — theHarvester/Sublist3r-inspired. Resolve A, AAAA, MX, TXT, NS records; brute-force subdomains from a wordlist; display a live table of discovered hosts.

---

## v2.0 — Analysis & CTF Utilities

| Module | Category | Core technique |
|---|---|---|
| **Tech Fingerprinter** | Web / Recon | HTTP headers, HTML meta, cookie names → CMS / framework / server detection |
| **Hash Identifier & Cracker** | Cryptanalysis | Pattern-match hash type; dictionary attack via hashlib |
| **Encoder / Decoder** | Utility / CTF | URL, Base64, HTML entity, hex, rot13 — bidirectional |

**Tech Fingerprinter** — WhatWeb-inspired. Detects CMS (WordPress, Drupal, Joomla), server software (Apache, Nginx, IIS), frameworks (Laravel, Django, Rails, Express), and security products from response signatures.

**Hash Identifier & Cracker** — Identify hash algorithm from format (MD5, SHA-1, SHA-256, bcrypt, NTLM, etc.) then optionally run a dictionary attack against the hash. Teaches hashing concepts without requiring GPU cracking tools.

**Encoder / Decoder** — Multi-tab utility for URL encoding/decoding, Base64, HTML entities, hex, ROT-13, and JWT inspection. Essential for CTF participants and manual web testing.

---

## v2.x — Future Candidates

These are not scheduled; they become candidates when a milestone is complete.

| Idea | Inspired by |
|---|---|
| SSL/TLS Certificate Analyser | SSLyze, testssl.sh |
| WHOIS & IP Geolocation | whois, ipinfo.io |
| HTTP Request Builder / Replay | curl, Postman |
| SQL Injection Tester (basic) | sqlmap (GET/POST detection only) |
| Password / Wordlist Generator | crunch, CeWL |

---

## SDD Process

Each milestone follows this cycle:

1. **Spec** — `/sdd-next-spec` generates `specs/NN-module-name.md` with requirements, design, and acceptance criteria.
2. **Implement** — code written against the spec; spec updated if design changes.
3. **Changelog** — `/changelog` records what shipped.
4. **Promote** — module card on home page changes from `Coming Soon` to `Active`.
