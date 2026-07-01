# v4.5 — Forensics & Blue Team: Requirements

## Problem Statement & Motivation

CyberKit's toolset so far is predominantly offensive and OSINT-facing.
v4.5 adds the defensive / investigation side of the security picture:

1. **Log Analyser** — Security analysts and students regularly need to triage web server
   and auth logs without a SIEM. A GUI-first tool that surfaces top IPs, error spikes,
   and failed-login patterns from a local log file removes the need to know awk/grep and
   teaches the concepts behind log-based threat hunting.

2. **File Metadata Extractor** — Files published online often carry embedded metadata
   (GPS coordinates, author names, software versions, modification history) that
   organisations intend to strip before release. A tool that extracts and presents this
   metadata visually teaches why pre-publication scrubbing matters.

3. **Hash Verifier** — Download integrity and chain-of-custody verification require
   computing a cryptographic digest for a file and comparing it against an expected value.
   This is distinct from the existing Hash Tool (which *cracks* hashes); Hash Verifier
   purely *computes and compares*.

---

## In Scope

### Log Analyser (`log_analyser`)
- File picker opens a local text log file.
- Supported formats detected automatically by line pattern:
  - **Apache / Nginx combined access log** (`127.0.0.1 - - [date] "GET / HTTP/1.1" 200 1234`)
  - **SSH auth.log** (`Jul  1 12:00:00 host sshd[pid]: Failed password for user from IP`)
- Parsed results presented in four panels:
  - **Top IPs** — frequency table (IP, request count, % of total); top 20.
  - **Status code breakdown** — count per HTTP status group (2xx/3xx/4xx/5xx); bar-style display.
  - **Error spike** — 4xx/5xx counts grouped by hour; identifies busiest error hour.
  - **Failed auth** — for auth.log: top usernames attempted, top source IPs, total count.
- Line count and detected format shown in a summary bar.
- All parsing runs in a background thread (large log files can be 100 MB+).
- Export: copy Top IPs table to clipboard as TSV.

### File Metadata Extractor (`file_metadata`)
- File picker accepts any file; format detected by extension and magic bytes.
- **Images** (JPEG, PNG, TIFF, WEBP) — extract EXIF via `Pillow`:
  GPS latitude/longitude (converted to decimal degrees), camera make/model,
  capture datetime, software tag, orientation.
- **PDF** — extract document info via `pypdf`:
  Title, Author, Creator (tool), Producer, CreationDate, ModDate.
- **Office documents** — extract core properties via `python-docx` (.docx) /
  `openpyxl` (.xlsx):
  Author, last-modified-by, created, modified, revision, company.
- Unsupported formats: show a clear "No metadata extractable for this file type" message.
- Results shown as a key→value table (`ttk.Treeview`).
- Highlight fields that are privacy-sensitive (GPS, Author, last-modified-by) in amber.

### Hash Verifier (`hash_verifier`)
- File picker selects any file.
- Computes MD5, SHA-1, SHA-256, and SHA-512 digests (all four always, using `hashlib`).
- Displays each digest as a hex string in a read-only text field.
- Optional: paste an expected hash string into a comparison field; the tool identifies
  which algorithm it matches (by length/format) and shows a clear PASS ✓ / FAIL ✗ result.
- Hashing runs in a background thread (large files); progress label shown while running.

---

## Out of Scope

- Windows Event Log (`.evtx`) parsing — requires `python-evtx` or WMI, too heavy for v4.5.
- Live log tailing / real-time monitoring — file is read once on open.
- EXIF writing / stripping — read-only tool.
- Recursive directory hashing — single file only.
- Chain-of-custody report generation (PDF export) — display only.
- Merging Hash Verifier into the existing Hash Tool page — stays as a separate sidebar
  entry for discoverability (Hash Tool = crack; Hash Verifier = verify).

---

## Key Decisions & Constraints

| Decision | Rationale |
|---|---|
| Pillow, pypdf, python-docx, openpyxl as new dependencies | Pre-planned in tech-stack.md for v4.5; all pure Python, no C compilation on Windows |
| Auto-detect log format by line pattern | Users often don't know which format their log is; a radio button adds friction |
| Background thread for log parsing + hashing | Per tech-stack.md hard constraint: no Tk widget calls from worker threads |
| `hashlib` (stdlib) for all hash computation | Already a project dependency; no new imports needed for Hash Verifier |
| `tkinter.filedialog.askopenfilename` for file picking | Already used in JWT brute-force page; consistent UX |
| Privacy-highlight in metadata | Aligns with mission.md "Educational first" — users must understand which fields are sensitive |
| New sidebar category: **Forensics / Blue Team** | Three modules form a coherent group; avoids overloading existing categories |

---

## Open Questions

None — all scope and approach questions resolved in the spec interview.
