# v4.4 — OSINT & Information Gathering: Validation Checklist

---

## Group 1 — Email Header Analyser Engine

- [ ] `test_parse_hops` passes: 3-hop fixture produces 3 `HopEntry` objects with
      correct `by`/`from_` values; hops 2 and 3 have non-None `delta_s`.
- [ ] `test_auth_results_extracted` passes: fixture with `spf=pass dkim=fail dmarc=none`
      produces an `AuthResult` with exactly those values.
- [ ] `test_flags_gap` passes: two hops more than 3600 s apart produce a flag containing
      "gap" or "delay" in the description string.
- [ ] `test_flags_spf_fail` passes: fixture with `spf=fail` produces at least one flag.
- [ ] `test_empty_input` passes: `parse("")` returns a `HeaderSummary` without raising.
- [ ] All 5 email header engine tests pass with `python tests/test_email_header.py`.

---

## Group 2 — Robots.txt & Sitemap Parser Engine

- [ ] `test_parse_directives` passes: multi-agent robots.txt string yields the correct
      list of `(user_agent, disallow_path)` tuples and sitemap URLs.
- [ ] `test_parse_sitemap_urlset` passes: minimal `<urlset>` XML with 3 `<loc>` entries
      produces a `SitemapResult` with exactly 3 URLs.
- [ ] `test_parse_sitemap_index` passes: a `<sitemapindex>` with 2 `<sitemap>` entries
      (parsed from the XML string, no HTTP call) produces 2 child sitemap URLs.
- [ ] `test_empty_robots` passes: empty string input produces zero directives and zero
      sitemap URLs without raising.
- [ ] All 4 robots/sitemap engine tests pass with `python tests/test_robots_sitemap.py`.

---

## Group 3 — CVE / Vulnerability Lookup Engine

- [ ] `test_parse_response` passes: a minimal NVD-shaped fixture JSON produces a
      `CveEntry` with correct `cve_id`, `cvss_score`, `severity`, and `description`.
- [ ] `test_severity_bands` passes: scores 9.5→CRITICAL, 8.0→HIGH, 5.5→MEDIUM,
      2.0→LOW, 0.0→NONE.
- [ ] `test_sorted_descending` passes: 3 entries at different scores are ordered
      highest-first.
- [ ] `test_empty_vulnerabilities` passes: `_parse_response` with empty list returns
      zero entries without raising.
- [ ] All 4 CVE engine tests pass with `python tests/test_cve_lookup.py`.

---

## Group 4 — UI Pages (Manual)

### Email Header Analyser page
- [ ] Page opens without errors when selected from the sidebar.
- [ ] Pasting a sample raw email header (with 2+ `Received:` hops) and clicking
      **Analyse** populates the Hops Treeview with the correct number of rows.
- [ ] SPF/DKIM/DMARC labels show the correct colours (green/red/grey) for a fixture
      header with known auth results.
- [ ] A header with a large inter-hop gap displays a visible warning flag.
- [ ] **Clear** resets all panels to their empty state.

### Robots.txt & Sitemap Parser page
- [ ] Entering a domain (e.g. `example.com`) and clicking **Fetch** shows a loading
      state and then populates the robots.txt raw text panel.
- [ ] Disallow directives appear in the Treeview with correct User-Agent grouping.
- [ ] At least one referenced sitemap URL is listed if `robots.txt` contains a
      `Sitemap:` directive.
- [ ] Fetching sitemap URLs populates the URL list Treeview.
- [ ] An invalid domain shows a clear error message, not an unhandled exception.

### CVE Lookup page
- [ ] Entering a product name and version and clicking **Search** starts a visible
      loading/countdown state.
- [ ] Results Treeview is populated with CVE rows sorted by CVSS score descending.
- [ ] Row colours match severity: CRITICAL rows are red-tinted, HIGH orange, etc.
- [ ] **Stop** button cancels an in-flight query cleanly (no crash, status label
      updates to "Stopped").
- [ ] Rate-limit note is visible beneath the input fields before any query is run.

---

## Group 5 — Wiring & Integration (Manual)

- [ ] All three tools appear in the **DNS & OSINT** sidebar category in the correct
      order (Email Header Analyser, Robots & Sitemap, CVE Lookup).
- [ ] Clicking each sidebar entry navigates to the correct page.
- [ ] All three tools appear as **Active** cards in the correct home-page category
      section.
- [ ] Sidebar version label reads `v4.4.0` in both expanded and icon-only modes.
- [ ] No existing tools are broken: navigate to at least DNS Enumerator and WHOIS &
      Geo after adding the new pages and confirm they still work.

---

## Documentation

- [ ] `docs/roadmap.md` v4.4 heading reads `✅ Complete` and all three modules show
      a Status column entry.
- [ ] `CHANGELOG.md` contains a `## 2026-07-01` (or current date) section describing
      all three modules shipped in v4.4.
- [ ] Spec files committed on `phase-12-v4.4-osint-information-gathering` branch:
      - `specs/2026-07-01-osint-information-gathering/requirements.md`
      - `specs/2026-07-01-osint-information-gathering/plan.md`
      - `specs/2026-07-01-osint-information-gathering/validation.md`
- [ ] Feature branch merged to `main` and deleted after all checks pass.
