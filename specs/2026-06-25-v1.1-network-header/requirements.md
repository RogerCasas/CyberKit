# Requirements — v1.1: Network & Header Visibility

**Phase:** v1.1
**Branch:** `phase-2-v1.1-network-header`
**Modules:** Port Scanner · Header Analyser
**Inspired by:** nmap · securityheaders.com

---

## Problem Statement

CyberKit v1.0 only covers web directory enumeration. A learner who wants to understand the *network layer* — which ports are open, what services are running — or audit a site's *HTTP security posture* has no GUI tool available without installing nmap or visiting external sites. v1.1 closes this gap with two self-contained modules that teach complementary skills: network reconnaissance and HTTP security hygiene.

---

## Module A — Port Scanner

### In Scope

| Feature | Detail |
|---|---|
| **Default scan mode** | Top-1000 most common ports (predefined list in `app/data/port_lists.py`) |
| **Custom range mode** | User enters `from` and `to` port (1–65535); replaces the top-1000 list |
| **TCP connect scan** | `socket.connect_ex()` — no raw sockets, no admin privileges needed |
| **Port states** | OPEN (connect succeeded), FILTERED (timeout), CLOSED (connection refused) |
| **Display filter** | Show Open + Filtered by default; Closed ports hidden (too numerous) |
| **Optional banner grab** | Toggle checkbox; on open ports, reads first 256 bytes after connect |
| **Service name lookup** | Static dict of well-known port → service name (HTTP, SSH, FTP, …) |
| **Live results table** | Treeview: Port \| Service \| Status \| Banner \| Response (ms) |
| **Summary cards** | Open · Filtered · Closed · Errors |
| **Thread count** | Slider 10–200, default 100 (ports are fast I/O) |
| **Timeout slider** | 0.5 s – 3.0 s per port, default 1.0 s |
| **Stop mid-scan** | Same stop-event pattern as FuzzerEngine |
| **Export** | CSV and TXT |
| **Disclaimer** | Inline warning reminding user to only scan authorised hosts |

### Out of Scope (v1.1)

- UDP scanning (requires raw sockets / admin on Windows)
- SYN (half-open) scanning — requires raw sockets
- OS detection, version detection depth beyond banner
- IP range / CIDR input (single host only)
- Traceroute or latency hops
- NSE-style scripted probes

### Constraints (from tech-stack.md)

- No admin/root required — TCP connect only (ADR constraint)
- No C extensions
- ThreadPoolExecutor for concurrency (consistent with FuzzerEngine pattern)
- Treeview for results (ADR-002)
- Queue + `after()` polling; never touch Tk from worker thread

---

## Module B — Header Analyser

### In Scope

| Feature | Detail |
|---|---|
| **Target input** | Single URL; scheme normalised (http/https preserved) |
| **Fetch method** | `requests.get()` with browser UA; reads only response headers, content discarded |
| **Headers checked** | Six OWASP-recommended security headers (see below) |
| **Per-header result** | Name \| Value (or "MISSING") \| Status (✓/⚠/✕) \| Severity \| Tip |
| **Letter grade** | A+ through F computed from weighted score (see below) |
| **Info-leak flags** | Flag Server, X-Powered-By, X-AspNet-Version as informational findings (not in grade) |
| **HTTPS awareness** | HSTS check skipped gracefully on HTTP targets with a note |
| **Single-shot** | Not a streaming scan; result appears once the request completes |
| **Export** | TXT report with all findings and grade |

#### Headers Checked and Weights

| Header | Severity | Points |
|---|---|---|
| `Content-Security-Policy` | Critical | 25 |
| `Strict-Transport-Security` | Critical (HTTPS only) | 25 |
| `X-Frame-Options` | High | 15 |
| `X-Content-Type-Options` | High | 15 |
| `Referrer-Policy` | Medium | 10 |
| `Permissions-Policy` | Medium | 10 |

**Grade thresholds** (% of applicable max score):

| Grade | % |
|---|---|
| A+ | 95–100 |
| A  | 85–94  |
| B  | 70–84  |
| C  | 50–69  |
| D  | 30–49  |
| F  | < 30   |

#### Value Validation (basic)

- **HSTS**: warn if `max-age` < 31536000 (1 year)
- **X-Content-Type-Options**: must be `nosniff`
- **X-Frame-Options**: must be `DENY` or `SAMEORIGIN` (flag `ALLOW-FROM` as deprecated)
- **CSP**: flag presence of `unsafe-inline` or `unsafe-eval` as a warning (present but weakened)

### Out of Scope (v1.1)

- Full CSP directive-level parsing
- Cookie attribute analysis (Secure, HttpOnly, SameSite)
- CORS policy analysis
- Certificate / TLS validation (v2.x candidate)
- Batch URL scanning

---

## Key Decisions

- Both engines follow the **same architectural pattern** as `FuzzerEngine`: background `threading.Thread` → `queue.Queue` → `after()` poll. No new patterns introduced.
- Both pages follow the **same layout pattern** as `FuzzerPage`: header, controls card, summary cards, Treeview table.
- Port lists stored in `app/data/port_lists.py` (same approach as `wordlists.py`).
- Header rules stored inline in `app/modules/header_analyser.py` as a list of dataclasses (no external file needed at this scale).

---

## Open Questions

None — all resolved during the spec interview.
