# v4.5 — Forensics & Blue Team: Validation Checklist

---

## Group 1 — Log Analyser Engine

- [ ] `test_detect_apache` passes: two Apache combined-log lines → `format == "apache"`.
- [ ] `test_detect_auth` passes: two SSH auth.log lines → `format == "auth"`.
- [ ] `test_parse_apache_top_ips` passes: 5-line fixture with 3 unique IPs returns them
      in descending frequency order.
- [ ] `test_parse_apache_status_counts` passes: fixture with 200/404/404/500 lines →
      `2xx=1, 4xx=2, 5xx=1`.
- [ ] `test_parse_auth_failed` passes: fixture with two "Failed password" lines produces
      correct `failed_auth` and `failed_auth_ips` counts.
- [ ] `test_unknown_format` passes: random text → `format == "unknown"`, `parsed_lines == 0`.
- [ ] All 6 log analyser tests pass with `python tests/test_log_analyser.py`.

---

## Group 2 — File Metadata Extractor Engine

- [ ] `test_unknown_extension` passes: `extract("file.xyz")` → `file_type == "unknown"`,
      `error == ""`, no exception raised.
- [ ] `test_pdf_error_handling` passes: `extract("nonexistent.pdf")` → `error` field
      non-empty, no exception raised.
- [ ] `test_meta_field_sensitive_flag` passes: `MetaField(key="GPS", value="...",
      sensitive=True)` is constructable and `sensitive` attribute is `True`.
- [ ] `test_gps_decimal_conversion` passes: known rational GPS input produces correct
      decimal-degree float output (within 0.001° tolerance).
- [ ] All 4 file metadata tests pass with `python tests/test_file_metadata.py`.

---

## Group 3 — Hash Verifier Engine

- [ ] `test_compute_known_hash` passes: SHA-256 of a small known byte sequence matches
      `hashlib.sha256(data).hexdigest()` exactly.
- [ ] `test_verify_match` passes: `verify(result, correct_sha256)` → `match=True`,
      `matched_algorithm == "SHA-256"`.
- [ ] `test_verify_no_match` passes: `verify(result, wrong_hash)` → `match=False`.
- [ ] `test_verify_case_insensitive` passes: uppercase expected hash still matches.
- [ ] `test_compute_error` passes: non-existent file path → `error` field non-empty,
      no exception raised.
- [ ] All 5 hash verifier tests pass with `python tests/test_hash_verifier.py`.

---

## Group 4 — UI Pages (Manual)

### Log Analyser page
- [ ] Page opens without errors from the sidebar.
- [ ] File picker opens a dialog; selecting an Apache access log file populates the
      selected path label.
- [ ] Clicking **Analyse** shows a loading state, then populates all four result panels.
- [ ] Top IPs treeview is sorted by request count descending.
- [ ] Status code panel shows correct colour coding (green 2xx, amber 4xx, red 5xx).
- [ ] Opening an SSH auth.log file populates the Failed Auth treeview with usernames
      and source IPs.
- [ ] **Stop** button cancels an in-flight analysis cleanly.
- [ ] **Copy Top IPs** button puts tab-separated data on the clipboard.

### File Metadata Extractor page
- [ ] File picker opens and accepts image, PDF, and Office file types.
- [ ] Selecting a JPEG with EXIF data and clicking **Extract** populates the results
      treeview with at least Make, Model, or DateTime fields.
- [ ] GPS fields are highlighted in amber when present.
- [ ] Selecting an unsupported file type shows "No metadata extractable for this file type."
- [ ] **Clear** resets all widgets to their initial state.
- [ ] Selecting a .docx file shows Author and last-modified-by (amber) and Created/Modified dates.

### Hash Verifier page
- [ ] File picker opens and accepts any file type.
- [ ] Clicking **Compute** shows a progress label and then populates all four hash fields.
- [ ] All four hash strings are the correct length (MD5=32, SHA-1=40, SHA-256=64,
      SHA-512=128 hex characters).
- [ ] Pasting the displayed SHA-256 into the expected field and clicking **Verify** shows
      a green "✓ MATCH (SHA-256)" result.
- [ ] Pasting a wrong hash shows a red "✗ NO MATCH" result.
- [ ] **Stop** button cancels in-flight hashing cleanly.

---

## Group 5 — Wiring & Integration (Manual)

- [ ] All three tools appear in a new **Forensics / Blue Team** sidebar category in the
      correct order (Log Analyser, File Metadata, Hash Verifier).
- [ ] Clicking each sidebar entry navigates to the correct page.
- [ ] All three tools appear as **Active** cards in the Forensics / Blue Team home-page
      section.
- [ ] Sidebar version label reads `v4.5.0` in both expanded and icon-only modes.
- [ ] Existing tools are not broken: spot-check DNS Enumerator, CVE Lookup, and
      Cipher Identifier after wiring.
- [ ] `pip install Pillow pypdf python-docx openpyxl` succeeds cleanly on a fresh
      environment (or confirms already satisfied).

---

## Documentation

- [ ] `docs/roadmap.md` v4.5 heading reads `✅ Complete` and all three modules show
      a Status column entry.
- [ ] `CHANGELOG.md` contains a `## 2026-07-01` (or current date) section describing
      all three v4.5 modules.
- [ ] `requirements.txt` updated with all four new dependencies under a `# v4.5` comment.
- [ ] Spec files committed on `phase-13-v4.5-forensics-blue-team`:
      - `specs/2026-07-01-forensics-blue-team/requirements.md`
      - `specs/2026-07-01-forensics-blue-team/plan.md`
      - `specs/2026-07-01-forensics-blue-team/validation.md`
- [ ] Feature branch merged to `main` and deleted after all checks pass.
