# v4.4 — OSINT & Information Gathering: Implementation Plan

---

## Group 1 — Email Header Analyser Engine

### 1.1 — Create `app/modules/email_header.py`
Define a `HopEntry` dataclass:
```python
@dataclass
class HopEntry:
    index:     int
    by:        str   # receiving server
    from_:     str   # sending server / IP
    timestamp: str   # raw date string
    ip:        str   # extracted IP if present
    delta_s:   int | None   # seconds since previous hop (None for first)
```
Define an `AuthResult` dataclass:
```python
@dataclass
class AuthResult:
    spf:   str   # "pass" / "fail" / "softfail" / "neutral" / "none" / "unknown"
    dkim:  str
    dmarc: str
```
Define a `HeaderSummary` dataclass:
```python
@dataclass
class HeaderSummary:
    from_:      str
    to:         str
    subject:    str
    date:       str
    message_id: str
    mailer:     str
    hops:       list[HopEntry]
    auth:       AuthResult
    flags:      list[str]   # human-readable warning strings
```

### 1.2 — Implement `parse(raw_header: str) -> HeaderSummary`
- Use `email.parser.HeaderParser().parsestr(raw_header)` to get a `Message` object.
- Extract `From`, `To`, `Subject`, `Date`, `Message-ID`, `X-Mailer`/`User-Agent`.
- Collect all `Received:` headers (preserving order); parse each for `from`, `by`,
  timestamp, and IP (regex on bracketed IPv4/IPv6).
- Parse timestamps with `email.utils.parsedate_to_datetime`; compute deltas between
  consecutive hops; assign `delta_s`.
- Parse `Authentication-Results:` header(s) for `spf=`, `dkim=`, `dmarc=` results
  using regex; default to `"unknown"` if absent.
- Generate `flags`: time gap > 3600 s, missing `Authentication-Results`, any
  spf/dkim/dmarc result in `{"fail","softfail","none","permerror","temperror"}`.

### 1.3 — Write `tests/test_email_header.py`
- `test_parse_hops`: fixture with a 3-hop raw header; assert correct hop count,
  `by`/`from_` fields, non-None deltas for hops 2 and 3.
- `test_auth_results_extracted`: fixture with `Authentication-Results` containing
  `spf=pass`, `dkim=fail`, `dmarc=none`; assert `AuthResult` fields match.
- `test_flags_gap`: fixture with two hops > 1 hour apart; assert a gap flag is present.
- `test_flags_spf_fail`: fixture with `spf=fail`; assert a fail flag is present.
- `test_empty_input`: `parse("")` returns a `HeaderSummary` without raising.

---

## Group 2 — Robots.txt & Sitemap Parser Engine

### 2.1 — Create `app/modules/robots_sitemap.py`
Define `RobotsResult`:
```python
@dataclass
class RobotsResult:
    url:         str
    raw_text:    str
    directives:  list[tuple[str, str]]   # (user_agent, disallow_path)
    sitemap_urls: list[str]
    error:       str   # empty string if fetch succeeded
```
Define `SitemapResult`:
```python
@dataclass
class SitemapResult:
    source_url: str
    urls:       list[str]
    error:      str
```

### 2.2 — Implement `fetch_robots(domain: str) -> RobotsResult`
- Normalise input: strip scheme if user typed one; construct
  `https://{domain}/robots.txt`; fall back to `http://` on SSL error.
- Fetch with `requests.get(..., timeout=10)`.
- Parse lines: track current `User-agent:` group; collect `Disallow:` into
  `directives`; collect `Sitemap:` into `sitemap_urls`.
- Store raw text and return `RobotsResult`.

### 2.3 — Implement `fetch_sitemap(url: str) -> SitemapResult`
- Fetch XML with `requests.get(..., timeout=10)`.
- Parse with `xml.etree.ElementTree`; handle both sitemap index
  (`<sitemapindex>/<sitemap>/<loc>`) and URL set (`<urlset>/<url>/<loc>`).
- For a sitemap index: fetch each child sitemap and collect `<loc>` entries
  (one level deep only).
- Namespace-aware parsing: strip `{...}` prefix from tag names.
- Return `SitemapResult`; catch all exceptions and store in `error` field.

### 2.4 — Write `tests/test_robots_sitemap.py`
- `test_parse_directives`: call a `_parse_robots_text(text)` helper with a
  known multi-agent robots.txt string; assert directives and sitemap URLs
  are extracted correctly.
- `test_parse_sitemap_urlset`: parse a minimal XML string with 3 `<loc>` entries;
  assert all 3 are in the result.
- `test_parse_sitemap_index`: parse a sitemapindex XML with 2 child sitemap entries;
  assert 2 URLs are returned.
- `test_empty_robots`: empty string produces zero directives and zero sitemaps
  without raising.

---

## Group 3 — CVE / Vulnerability Lookup Engine

### 3.1 — Create `app/modules/cve_lookup.py`
Define `CveEntry`:
```python
@dataclass
class CveEntry:
    cve_id:      str
    cvss_score:  float   # v3.1 base score, or v2 if v3 absent, or 0.0
    severity:    str     # "CRITICAL" / "HIGH" / "MEDIUM" / "LOW" / "NONE"
    description: str
    published:   str
```
Define `CveResult`:
```python
@dataclass
class CveResult:
    product:     str
    version:     str
    total_results: int
    entries:     list[CveEntry]   # sorted by cvss_score descending
    error:       str
```

### 3.2 — Implement `search(product: str, version: str, stop_event) -> CveResult`
- Build query: `keyword = f"{product} {version}".strip()`; call NVD API v2
  `cves/2.0?keywordSearch={keyword}&resultsPerPage=20`.
- Parse JSON response: for each vulnerability extract `cve.id`,
  `cve.descriptions[lang=="en"].value`, `cve.published`.
- Extract CVSS score: prefer `metrics.cvssMetricV31[0].cvssData.baseScore`;
  fall back to `cvssMetricV2`; default to `0.0`.
- Derive severity from score: ≥9.0 CRITICAL, ≥7.0 HIGH, ≥4.0 MEDIUM,
  >0 LOW, 0 NONE.
- Sort by `cvss_score` descending; return `CveResult`.
- Check `stop_event` before the request; set `error` on any exception.

### 3.3 — Write `tests/test_cve_lookup.py`
- `test_parse_response`: call a `_parse_response(json_dict)` helper with a
  minimal NVD-shaped fixture; assert CVE ID, CVSS score, severity, description
  are extracted correctly.
- `test_severity_bands`: assert all five severity bands resolve correctly from
  scores 9.5, 8.0, 5.5, 2.0, 0.0.
- `test_sorted_descending`: fixture with 3 entries at different scores; assert
  result list is sorted highest-first.
- `test_empty_vulnerabilities`: `_parse_response` with empty `vulnerabilities`
  list returns zero entries without raising.

---

## Group 4 — UI Pages

### 4.1 — Create `app/ui/pages/email_header.py`
- `EmailHeaderPage(CTkFrame)` with a tall paste box (CTkTextbox, ~10 rows).
- **Analyse** button → calls `email_header.parse()` synchronously (no network,
  fast enough for the UI thread) → populates result widgets.
- Summary panel: key–value labels for From/To/Subject/Date/Message-ID/Mailer.
- Authentication panel: three coloured labels (green=pass, red=fail/none,
  grey=unknown) for SPF, DKIM, DMARC.
- Hops Treeview: columns Hop # | From | By | Timestamp | Delta | IP.
- Flags panel: coloured warning labels below the Treeview (amber background for
  warnings, red for failures).
- Clear button resets all widgets.

### 4.2 — Create `app/ui/pages/robots_sitemap.py`
- `RobotsSitemapPage(CTkFrame)` with a URL input field.
- **Fetch** button → starts a background thread; shows a spinner label.
- Results split into two sections:
  - **robots.txt**: raw text panel (CTkTextbox, read-only) + Treeview of
    directives (User-Agent | Disallow Path).
  - **Sitemaps**: list of referenced sitemap URLs (as clickable labels that
    populate a second fetch); Treeview of all resolved page URLs.
- Error label shown if fetch fails.

### 4.3 — Create `app/ui/pages/cve_lookup.py`
- `CveLookupPage(CTkFrame)` with Product and Version input fields.
- **Search** button → starts a background thread; shows rate-limit countdown
  label ("Querying NVD… rate limit: 1 req / 6 s").
- Results Treeview: CVE ID | CVSS | Severity | Published | Description (truncated).
- Row tag colouring by severity: CRITICAL red, HIGH orange, MEDIUM yellow,
  LOW grey, NONE dim.
- Total results label ("Showing 20 of N results").
- Stop button cancels in-flight query via `stop_event`.
- Rate-limit info note rendered as a muted label beneath the input row.

---

## Group 5 — Wiring & Documentation

### 5.1 — Register new pages in `app/data/categories.py`
Add three `ToolEntry` objects to the `dns_osint` category:
```python
ToolEntry("Email Header Analyser", "📧", "email_header"),
ToolEntry("Robots & Sitemap",      "🤖", "robots_sitemap"),
ToolEntry("CVE Lookup",            "🔎", "cve_lookup"),
```

### 5.2 — Wire pages into `app/ui/app_window.py`
Import the three page classes and call `_add_page()` for each.

### 5.3 — Add home-page cards to `app/ui/pages/home.py`
Add three entries to `CARD_DATA` with `tag: "Active"` and `tag_color: "#22c55e"`.

### 5.4 — Bump sidebar version to `v4.4.0` in `app/ui/sidebar.py`
Update both occurrences of the version string.

### 5.5 — Update `docs/roadmap.md`
Change the v4.4 heading to `## v4.4 — OSINT & Information Gathering ✅ Complete`
and add a Status column to the module table.

### 5.6 — Commit the spec files on the feature branch
Ensure `specs/2026-07-01-osint-information-gathering/` is committed so the spec
travels with the implementation history.
