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

## v3.1 — Web Attack Utilities ✅ Complete

| Module | Category | Core technique |
|---|---|---|
| **HTTP Request Builder / Replay** | Web / Testing | Custom method, headers, and body; full response inspection | ✅ Done |
| **SQL Injection Tester (basic)** | Web / Exploitation | Error-based + boolean SQLi payload injection into GET/POST parameters | ✅ Done |

**HTTP Request Builder / Replay** — curl/Postman-inspired. Choose method (GET/POST/PUT/DELETE/…), set arbitrary headers, supply a request body, and send. View the full response (status, headers, body). Teaches raw HTTP semantics and is a natural prerequisite to manual injection testing.

**SQL Injection Tester (basic)** — sqlmap-inspired (detection only, no extraction). Inject common SQL error payloads into GET/POST parameters; detect error-based and boolean-based signatures in the response. Covers detection, not exploitation.

---

## v3.2 — Password & Network Tools ✅ Complete

| Module | Category | Core technique |
|---|---|---|
| **Password / Wordlist Generator** | Utility / Offensive | Character-set brute-force + seed-phrase mutation (leet, caps, suffixes) | ✅ Done |
| **ARP Scanner** | Network / Recon | Layer-2 ARP broadcast → MAC/IP/vendor table | ✅ Done |

**Password / Wordlist Generator** — crunch/CeWL-inspired. Generate wordlists from a character set + min/max length (brute-force mode) or from a seed phrase with common mutations (leet-speak, capitalisation, number suffixes). Export to `.txt` for direct use in the Credential Tester or Hash Cracker.

**ARP Scanner** — Scapy-inspired. Broadcast an ARP request on the local subnet and collect replies: IP, MAC address, and vendor name via OUI lookup. Teaches layer-2 topology. ⚠ Requires administrator/root privileges and the `scapy` dependency (C extension).

---

---

## v4.0 — UI Reorganisation: Category Grouping ✅ Complete

| Change | Area | Status |
|---|---|---|
| **Collapsible sidebar categories** | UI / Navigation | ✅ Done |
| **Home page category sections** | UI / Home | ✅ Done |

**Collapsible sidebar categories** — Replace the single flat "MODULES" list with named, collapsible category groups. Each group header (e.g. "Web / Active Testing") can be clicked to expand or collapse all tools within it. Expanded state persists while the app is running. Collapses all groups except the one containing the active page on navigation.

**Home page category sections** — The home page card grid is reorganised into labelled sections matching the sidebar categories. A section heading (styled like the existing "AVAILABLE MODULES" label) appears above each group of cards. Existing Active/Coming Soon tags are preserved.

Categories introduced in v4.0 (applied retroactively to all existing tools):

| Category | Existing tools |
|---|---|
| Web / Active Testing | Dir Fuzzer, Header Analyser, HTTP Builder, SQLi Tester |
| Network / Recon | Port Scanner, ARP Scanner |
| Auth & Exploitation | Credential Tester |
| DNS & OSINT | DNS Enumerator, WHOIS & Geo |
| Cryptanalysis & Encoding | Hash Tool, Encoder / Decoder |
| Tech Analysis | Tech Fingerprinter, SSL Analyser |
| Wordlist & Utilities | Wordlist Generator |

---

## v4.1 — Web Attack Expansion ✅ Complete

| Module | Category | Core technique | Status |
|---|---|---|---|
| **XSS Tester** | Web / Active Testing | Reflected XSS payload injection into GET/POST parameters; unescaped-payload detection in response | ✅ Done |
| **CSRF Analyser** | Web / Active Testing | SameSite cookie flags, anti-CSRF token presence, Origin/Referer validation check | ✅ Done |
| **Open Redirect Detector** | Web / Active Testing | URL parameter injection with external-host payloads; 3xx Location header inspection | ✅ Done |

**XSS Tester** — Inject common reflected XSS payloads (`<script>`, `"><img onerror=...>`, SVG vectors) into GET/POST parameters and detect whether they appear unescaped in the response body. Detection only — no browser execution. Teaches output-encoding failures.

**CSRF Analyser** — Submit a request to a target endpoint and inspect: `Set-Cookie` headers for `SameSite` attribute, form HTML for hidden CSRF token fields, and server response to missing/spoofed `Origin`/`Referer` headers.

**Open Redirect Detector** — Inject redirect payloads (`//evil.com`, `https://evil.com`, `\evil.com`) into URL parameters and POST body values; flag any 3xx response whose `Location` header resolves to an external domain.

---

## v4.2 — Network Recon Expansion ✅ Complete

| Module | Category | Core technique | Status |
|---|---|---|---|
| **Traceroute** | Network / Recon | ICMP/UDP TTL-escalation probes; hop-by-hop latency + reverse-DNS | ✅ Done |
| **Banner Grabber** | Network / Recon | Raw TCP connect; service banner capture (SSH, FTP, SMTP, HTTP) | ✅ Done |
| **Packet Sniffer** | Network / Recon | Scapy passive capture; live table of src/dst/protocol/port ⚠ admin required | ✅ Done |

**Traceroute** — Send probes with incrementing TTL and display a live table of hop index, IP, reverse-DNS hostname, and RTT for each hop. Teaches routing, BGP handoff points, and geographic topology.

**Banner Grabber** — Connect to a user-supplied host:port over raw TCP, send a minimal probe, and capture the service banner. Complements the Port Scanner: scanner finds what's open, Banner Grabber identifies the exact version string.

**Packet Sniffer** — Passive Scapy capture on a selected network interface. Live Treeview of src IP, dst IP, protocol, src port, dst port, and payload preview. Filter by protocol (TCP/UDP/ICMP/ARP). Read-only — no packet injection. ⚠ Requires admin/root (extends existing Scapy dependency).

---

## v4.3 — Cryptanalysis & CTF Utilities ✅ Complete

| Module | Category | Core technique | Status |
|---|---|---|---|
| **JWT Forge & Verify** | Cryptanalysis & Encoding | `alg:none` bypass attempt; HS256 secret brute-force via wordlist; decoded header/payload view | ✅ Done |
| **Cipher Identifier & Solver** | Cryptanalysis & Encoding | Index-of-coincidence + frequency analysis → Caesar/Vigenère/XOR/Rail Fence identification + one-click decrypt | ✅ Done |

**JWT Forge & Verify** — Extends the existing JWT inspection in Encoder/Decoder. Dedicated module: paste a JWT, attempt the `alg: none` bypass, brute-force a weak HS256 secret against a wordlist, and display the structured decoded token. Teaches JWT attack classes that appear in almost every CTF.

**Cipher Identifier & Solver** — Paste ciphertext; the engine runs index-of-coincidence, letter frequency, and bigram analysis to identify the most likely classical cipher; offers a one-click solve with adjustable key. Covers Caesar, Vigenère, XOR, and Rail Fence.

---

## v4.4 — OSINT & Information Gathering ✅ Complete

| Module | Category | Core technique | Status |
|---|---|---|---|
| **Email Header Analyser** | DNS & OSINT | Raw email header parse; relay hops, SPF/DKIM/DMARC evaluation, timestamp deltas | ✅ Done |
| **Robots.txt & Sitemap Parser** | DNS & OSINT | Fetch/parse `robots.txt` and `sitemap.xml`; disallowed paths + sitemap URL tree | ✅ Done |
| **CVE / Vulnerability Lookup** | DNS & OSINT | NVD public API query by product+version; CVE ID, CVSS score, summary | ✅ Done |

**Email Header Analyser** — Paste a raw email header (from "View Source" in any mail client) and extract: every relay hop with timestamp and IP, SPF/DKIM/DMARC pass/fail status, and any suspicious timestamp gaps. Teaches phishing investigation and mail-server forensics.

**Robots.txt & Sitemap Parser** — Enter a domain; fetch and parse `robots.txt` (disallowed paths, crawl-delay, sitemaps referenced) and `sitemap.xml` (all listed URLs in a collapsible tree). Teaches how sites inadvertently expose their directory structure.

**CVE / Vulnerability Lookup** — Query the NIST NVD REST API (no auth required) by product name and version; display matching CVEs sorted by CVSS score with a link to the full advisory. Teaches students to map discovered service versions to known public exploits.

---

## v4.5 — Forensics & Blue Team

| Module | Category | Core technique |
|---|---|---|
| **Log Analyser** | Forensics / Blue Team | Apache/Nginx access log + auth.log parsing; top IPs, error spikes, failed-auth patterns |
| **File Metadata Extractor** | Forensics / Blue Team | EXIF (images), PDF/Office metadata; GPS, author, creation tool extraction |
| **Hash Verifier** | Forensics / Blue Team | Compute MD5/SHA-1/SHA-256/SHA-512 for a file; compare against expected hash string |

**Log Analyser** — Open a local log file (Apache/Nginx access log, SSH `auth.log`, or Windows Event Log exported as CSV) and surface: top IPs by request count, 4xx/5xx error rate over time, failed SSH login attempts, and potential directory-traversal patterns. Teaches log-based threat hunting.

**File Metadata Extractor** — Drag-and-drop a file and extract embedded metadata: EXIF data from images (GPS coordinates, camera model, capture timestamp), PDF author/creation-tool/modification history, and Office document last-modified-by. Teaches why metadata stripping matters before publishing files publicly.

**Hash Verifier** — Select a file and enter an expected hash string; the tool computes MD5/SHA-1/SHA-256/SHA-512 and displays a clear pass/fail comparison. Simpler and more focused than the Hash Tool (which cracks hashes) — this is purely for download integrity and chain-of-custody verification.

---

## SDD Process

Each milestone follows this cycle:

1. **Spec** — `/sdd-next-spec` generates `specs/NN-module-name.md` with requirements, design, and acceptance criteria.
2. **Implement** — code written against the spec; spec updated if design changes.
3. **Changelog** — `/sdd-changelog` records what shipped.
4. **Promote** — module card on home page changes from `Coming Soon` to `Active`.
