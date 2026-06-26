# v3.0 — Passive Recon Expansion: Requirements

---

## Problem Statement

CyberKit's recon suite covers active scanning (ports, directories, credentials, DNS) and passive fingerprinting (tech stack). v3.0 adds two techniques used at the very start of a pen-test engagement: certificate inspection and domain/IP registration lookup. Both are fully passive — they retrieve public data without sending any attack traffic — and teach a learner what information is exposed before any tool even touches the target.

---

## In Scope

### SSL/TLS Certificate Analyser

- Connect to a user-supplied host and port (default 443) over TLS
- Extract from the leaf certificate:
  - Subject Common Name (CN)
  - Issuer CN and Organisation
  - Validity window: `Not Before` and `Not After` dates
  - Subject Alternative Names (SANs) — DNS names only
  - Serial number (hex)
  - Signature algorithm (e.g. `sha256WithRSAEncryption`)
- Compute and display three status flags:
  - **Expired** — `Not After` is in the past
  - **Near-expiry** — fewer than 30 days remain
  - **Self-signed** — issuer DN equals subject DN
- 10-second connection timeout; clear inline error for unreachable hosts, TLS errors, and hostname mismatches
- Uses stdlib `ssl` + `socket` for the TLS handshake; `cryptography` library for cert parsing (already a transitive dep of `paramiko` — added as an explicit dep in this phase)

### WHOIS & IP Geolocation

- Two-tab layout: **WHOIS** tab and **Geolocation** tab
- **WHOIS tab**: enter a domain name; retrieve via `python-whois`; display:
  - Registrar
  - Creation date, expiry date, last-updated date
  - Registrant organisation
  - Name servers (list)
- **Geolocation tab**: enter an IP address or domain (resolved to IP before query); query `http://ip-api.com/json/{ip}` (free tier, no API key); display:
  - Country, region, city
  - ISP and organisation
  - AS number
- `python-whois` added to `requirements.txt` in this phase (first explicit use)
- `requests` already present — used for the ip-api.com call

---

## Out of Scope

- Cipher suite enumeration or TLS version grading
- Full certificate chain inspection (intermediate and root CAs)
- Certificate revocation checking (OCSP / CRL)
- Paid API keys or authenticated geolocation endpoints
- RDAP protocol (WHOIS successor)
- Reverse DNS lookups
- WHOIS for IP ranges (ARIN/RIPE lookups)
- Rate-limit retry logic (graceful error message is sufficient)

---

## Key Decisions & Constraints

| Decision | Rationale |
|---|---|
| `cryptography` for cert parsing | `ssl.SSLSocket.getpeercert()` returns an empty dict when `verify_mode=CERT_NONE`; binary DER form requires a parser. `cryptography` is already installed transitively via `paramiko` and gives clean access to all cert fields including for expired/self-signed certs. |
| `ip-api.com` for geolocation | Free, no API key, 45 req/min, HTTP-only on free tier. Sufficient for a learning tool. |
| `python-whois` for WHOIS | Pure-Python WHOIS client; cross-platform; already listed in tech-stack.md for v3.0. |
| Leaf cert only | Inspecting the full chain requires presenting intermediate and root CAs, adding significant complexity for marginal educational value at this phase. |
| Results displayed as label-value rows | The SSL result is a single certificate (not a list), so a Treeview is overkill. A structured card with field/value rows (matching the Header Analyser's findings style) is more readable. |

---

## Open Questions

None — all decisions resolved during spec interview.
