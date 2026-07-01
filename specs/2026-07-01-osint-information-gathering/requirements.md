# v4.4 — OSINT & Information Gathering: Requirements

## Problem Statement & Motivation

CyberKit's OSINT surface currently covers DNS enumeration and WHOIS/Geolocation.
Three important passive-recon and analysis techniques are missing:

1. **Email Header Analysis** — Phishing investigation and mail-server forensics require
   parsing raw email headers to reconstruct the relay chain, evaluate SPF/DKIM/DMARC
   results, and surface suspicious timestamp gaps. No interactive GUI tool makes this
   immediately accessible to learners.

2. **Robots.txt & Sitemap Parsing** — Reconnaissance often starts by reading what a site
   deliberately exposes in `robots.txt` (disallowed paths, referenced sitemaps) and
   `sitemap.xml` (the full URL tree). This is a standard first step that students
   frequently overlook.

3. **CVE / Vulnerability Lookup** — Once a service version is identified (e.g. by the
   Banner Grabber), learners need a fast path to known CVEs. The NIST NVD REST API
   (v2) provides this without requiring an account.

---

## In Scope

### Email Header Analyser (`email_header`)
- Paste-box accepts a raw email header block (multi-line text).
- Parse all `Received:` headers to reconstruct the relay hop chain (sender, receiver,
  timestamp, IP where available).
- Display hops in a `ttk.Treeview` ordered oldest-first (bottom of paste → top).
- Compute and display inter-hop time deltas (e.g. "3 min 12 s").
- Extract and display SPF, DKIM, and DMARC result strings from
  `Authentication-Results:` headers (text extraction only — no cryptographic
  re-validation of DKIM signatures).
- Extract key metadata fields: `From`, `To`, `Subject`, `Date`, `Message-ID`,
  `X-Mailer` / `User-Agent`.
- Flag suspicious patterns: large time gaps (> 1 hour between hops), missing
  `Authentication-Results`, SPF/DKIM/DMARC `fail` or `none` results.
- All parsing uses `email.parser` from the Python stdlib.

### Robots.txt & Sitemap Parser (`robots_sitemap`)
- URL input field; fetches `https://{domain}/robots.txt` and parses it.
- Display all `Disallow:` entries in a list (grouped by `User-agent:` directive).
- Extract all `Sitemap:` directives from `robots.txt` and fetch each referenced
  sitemap XML.
- Parse `<url><loc>` entries from sitemap XML and display in a scrollable list.
  If a sitemap index is found, follow one level of `<sitemap><loc>` references.
- HTTP fetching via `requests` (already a dependency); XML parsing via `xml.etree`
  (stdlib).
- Display fetch errors (connection refused, 404, timeout) inline — never raise.

### CVE / Vulnerability Lookup (`cve_lookup`)
- Two text fields: product name and version string.
- Queries the NIST NVD REST API v2:
  `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={product}&resultsPerPage=20`
- Display results in a `ttk.Treeview`: CVE ID | CVSS Score | Severity | Summary.
- Sort by CVSS score descending.
- Enforce a 6-second inter-query sleep (per ADR-006) with a visible countdown label.
- Show a clear note in the UI: "Rate limited to 1 request per 6 s without an API key."
- All HTTP via `requests`.

---

## Out of Scope

- Cryptographic DKIM signature re-verification (requires fetching DNS TXT records and
  verifying RSA/Ed25519 — too complex; text extraction of the result string is
  sufficient for a learning tool).
- Multi-level sitemap recursion beyond one index → child sitemaps.
- NVD API key management / settings screen (deferred to a future Settings module).
- Exporting CVE results to CSV (consistent with other modules — export is a global
  future enhancement).
- Any form of automated scanning or mass-querying of external services.

---

## Key Decisions & Constraints

| Decision | Rationale |
|---|---|
| `email.parser` (stdlib) for header parsing | No extra dependency; handles folded headers and encoded words correctly |
| `requests` for HTTP (robots.txt, sitemap, NVD) | Already a project dependency; consistent with all other network modules |
| `xml.etree.ElementTree` (stdlib) for sitemap XML | No extra dependency; sufficient for well-formed sitemap files |
| No DKIM crypto | Matches mission.md constraint: educational focus, not a full mail forensics suite |
| NVD unauthenticated + 6 s sleep | Per ADR-006: no API key required from the user |
| One engine module + one UI page per tool | Consistent with every module since v1.0 (mission.md: "One file = one tool") |
| Thread + queue pattern for network calls | Per tech-stack.md: no Tk widgets ever touched from worker threads |
| Category: DNS & OSINT | All three modules join the existing "DNS & OSINT" sidebar category |

---

## Open Questions

None — all scope and approach questions resolved in the spec interview.
