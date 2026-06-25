# Spec 01 — Directory Fuzzer

**Status:** ✅ Complete (v1.0)
**Module key:** `fuzzer`
**Files:** `app/modules/dir_fuzzer.py`, `app/ui/pages/fuzzer.py`, `app/data/wordlists.py`

---

## Goal

Detect exposed directories and paths on a target web server by systematically probing a curated wordlist. Teaches the concept of content discovery / directory enumeration as used by real tools like gobuster and dirb.

---

## User Stories

- As a student, I want to enter a URL and see which paths respond, so I can understand how a directory fuzzer works.
- As a CTF player, I want to quickly find hidden directories without opening a terminal, so I can focus on the challenge.
- As a tester, I want to filter results by status category and export them, so I can share findings.

---

## Functional Requirements

- [x] Accept a target URL (with sub-path support, e.g. `https://example.com/app/`)
- [x] Probe each path in the wordlist using HTTP HEAD, falling back to GET on 405/501
- [x] Categorise results: FOUND (200), INTERESTING (301/302/303/307/308/401/403), NOT_FOUND, ERROR
- [x] Display results live in a scrollable table as they arrive (incremental insert, no full rebuild)
- [x] Show live summary counters (total, found, interesting, not found, errors)
- [x] Filter table by category (dropdown) and free-text search on path
- [x] Stop scan mid-way; drain remaining queue on stop
- [x] Export results to CSV and TXT
- [x] Progress bar + status label during scan

## Non-Functional Requirements

- [x] UI must remain responsive during scan (results via `queue.Queue` + `after()` polling)
- [x] Table must handle 500+ results without perceptible lag (ttk.Treeview)
- [x] Browser-like User-Agent + Accept headers to avoid WAF false negatives

---

## Design Notes

- `FuzzerEngine` runs in a `threading.Thread`; communicates via `queue.Queue[ScanResult]`
- `FuzzerPage._poll_results()` drains queue every 80 ms; appends rows to Treeview incrementally when no filter is active
- `_apply_filter()` does a full `tree.delete(*children)` + re-insert only on filter change (user-triggered, not on every poll)
- `_normalise_url` preserves `parsed.path` so sub-directory targets work correctly

---

## Acceptance Criteria

- [x] Scanning `https://target.com/subdir/` probes `https://target.com/subdir/web`, not `https://target.com/web`
- [x] A 200-returning path shows as green "200 OK" in the table
- [x] Stopping the scan mid-way shows accurate partial counts
- [x] Exporting CSV produces correct headers and all rows
- [x] Search filter updates table on every keystroke without flicker
