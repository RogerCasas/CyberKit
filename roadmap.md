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

## v1.1 — Network & Header Visibility ✅ Complete

| Module | Category | Core technique |
|---|---|---|
| **Port Scanner** | Network / Recon | TCP connect scan + optional banner grab | ✅ Done |
| **Header Analyser** | Web / Security audit | HTTP response header inspection vs. OWASP baseline | ✅ Done |

**Port Scanner** — nmap-inspired. Enter a host + port range, get a live table of open/closed/filtered ports with service guesses. Teaches the TCP handshake and common port numbers.

**Header Analyser** — Enter a URL, receive a grade and colour-coded breakdown of security headers: `Content-Security-Policy`, `Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`. Missing or misconfigured headers flagged as findings.

---

## v1.2 — Auth & DNS Recon ✅ Complete

| Module | Category | Core technique |
|---|---|---|
| **Credential Tester** | Auth / Brute-force | HTTP form-based + Basic auth dictionary attack | ✅ Done |
| **DNS & Subdomain Enumerator** | Recon / OSINT | DNS record lookup + wordlist-based subdomain brute-force | ✅ Done |

**Credential Tester** — hydra-inspired. Two tabs: (1) HTTP — supply a login URL, username list, and password list; tries combinations and reports successes; (2) SSH — supply a host, username list, and password list; uses Paramiko to test SSH login. Teaches HTTP auth flows and the SSH protocol without enabling mass attacks (rate-limiting built in).

**DNS & Subdomain Enumerator** — theHarvester/Sublist3r-inspired. Resolve A, AAAA, MX, TXT, NS records; brute-force subdomains from a wordlist; display a live table of discovered hosts.

---

## v2.0 — Analysis & CTF Utilities ✅ Complete

| Module | Category | Core technique |
|---|---|---|
| **Tech Fingerprinter** | Web / Recon | HTTP headers, HTML meta, cookie names → CMS / framework / server detection | ✅ Done |
| **Hash Identifier & Cracker** | Cryptanalysis | Pattern-match hash type; dictionary attack via hashlib | ✅ Done |
| **Encoder / Decoder** | Utility / CTF | URL, Base64, HTML entity, hex, rot13 — bidirectional | ✅ Done |

**Tech Fingerprinter** — WhatWeb-inspired. Detects CMS (WordPress, Drupal, Joomla), server software (Apache, Nginx, IIS), frameworks (Laravel, Django, Rails, Express), and security products from response signatures.

**Hash Identifier & Cracker** — Identify hash algorithm from format (MD5, SHA-1, SHA-256, bcrypt, NTLM, etc.) then optionally run a dictionary attack against the hash. Teaches hashing concepts without requiring GPU cracking tools.

**Encoder / Decoder** — Multi-tab utility for URL encoding/decoding, Base64, HTML entities, hex, ROT-13, and JWT inspection. Essential for CTF participants and manual web testing.

---

## v3.0 — Passive Recon Expansion ✅ Complete

| Module | Category | Core technique |
|---|---|---|
| **SSL/TLS Certificate Analyser** | Web / Recon | TLS handshake → certificate chain inspection, expiry, SANs, cipher suites | ✅ Done |
| **WHOIS & IP Geolocation** | Recon / OSINT | Domain WHOIS registration data + IP geolocation via public APIs | ✅ Done |

**SSL/TLS Certificate Analyser** — SSLyze-inspired. Connect to a host over TLS, retrieve the certificate chain, and display expiry date, issuer, subject alternative names, and supported cipher suites. Flags expired, near-expiry (< 30 days), and self-signed certificates.

**WHOIS & IP Geolocation** — whois + ipinfo.io-inspired. Enter a domain or IP; retrieve WHOIS registration data (registrar, creation/expiry dates, registrant org) and geographic IP context (country, city, ASN). Two-tab layout.

---

## v3.1 — Web Attack Utilities

| Module | Category | Core technique |
|---|---|---|
| **HTTP Request Builder / Replay** | Web / Testing | Custom method, headers, and body; full response inspection |
| **SQL Injection Tester (basic)** | Web / Exploitation | Error-based + boolean SQLi payload injection into GET/POST parameters |

**HTTP Request Builder / Replay** — curl/Postman-inspired. Choose method (GET/POST/PUT/DELETE/…), set arbitrary headers, supply a request body, and send. View the full response (status, headers, body). Teaches raw HTTP semantics and is a natural prerequisite to manual injection testing.

**SQL Injection Tester (basic)** — sqlmap-inspired (detection only, no extraction). Inject common SQL error payloads into GET/POST parameters; detect error-based and boolean-based signatures in the response. Covers detection, not exploitation.

---

## v3.2 — Password & Network Tools

| Module | Category | Core technique |
|---|---|---|
| **Password / Wordlist Generator** | Utility / Offensive | Character-set brute-force + seed-phrase mutation (leet, caps, suffixes) |
| **ARP Scanner** | Network / Recon | Layer-2 ARP broadcast → MAC/IP/vendor table |

**Password / Wordlist Generator** — crunch/CeWL-inspired. Generate wordlists from a character set + min/max length (brute-force mode) or from a seed phrase with common mutations (leet-speak, capitalisation, number suffixes). Export to `.txt` for direct use in the Credential Tester or Hash Cracker.

**ARP Scanner** — Scapy-inspired. Broadcast an ARP request on the local subnet and collect replies: IP, MAC address, and vendor name via OUI lookup. Teaches layer-2 topology. ⚠ Requires administrator/root privileges and the `scapy` dependency (C extension).

---

## SDD Process

Each milestone follows this cycle:

1. **Spec** — `/sdd-next-spec` generates `specs/NN-module-name.md` with requirements, design, and acceptance criteria.
2. **Implement** — code written against the spec; spec updated if design changes.
3. **Changelog** — `/changelog` records what shipped.
4. **Promote** — module card on home page changes from `Coming Soon` to `Active`.
