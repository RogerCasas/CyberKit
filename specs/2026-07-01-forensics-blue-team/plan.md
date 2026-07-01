# v4.5 — Forensics & Blue Team: Implementation Plan

---

## Group 1 — Log Analyser Engine

### 1.1 — Create `app/modules/log_analyser.py`
Define dataclasses:
```python
@dataclass
class LogSummary:
    format:        str           # "apache" | "auth" | "unknown"
    total_lines:   int
    parsed_lines:  int
    top_ips:       list[tuple[str, int]]    # (ip, count), up to 20
    status_counts: dict[str, int]           # {"2xx": N, "3xx": N, ...}
    error_by_hour: list[tuple[str, int]]    # (hour_str "YYYY-MM-DD HH", count)
    failed_auth:   list[tuple[str, int]]    # (username, count) for auth.log
    failed_auth_ips: list[tuple[str, int]]  # (ip, count) for auth.log
```

### 1.2 — Implement format detection and Apache/Nginx parser
- `_detect_format(lines: list[str]) -> str`: test first 20 non-empty lines against
  Apache combined log regex and SSH auth.log regex; return `"apache"`, `"auth"`, or
  `"unknown"`.
- `_parse_apache(lines) -> LogSummary`: regex per line for IP, status code, and
  timestamp (`[day/Mon/year:HH:MM:SS`); aggregate into counts.
- Extract hour from timestamp (`strptime` with `%d/%b/%Y:%H:%M:%S %z`).

### 1.3 — Implement SSH auth.log parser
- `_parse_auth(lines) -> LogSummary`: match lines containing `"Failed password for"`;
  extract username and source IP with regex.
- Also match `"Invalid user"` lines for attempted non-existent usernames.
- status_counts and error_by_hour left empty (not applicable to auth logs).

### 1.4 — Implement public `analyse(path: str, stop_event) -> LogSummary`
- Open file with `utf-8` encoding, `errors="replace"`.
- Read all lines, detect format, dispatch to the correct parser.
- Check `stop_event` between chunks (every 10 000 lines).
- Return `LogSummary(format="unknown", ...)` with `parsed_lines=0` on any read error.

### 1.5 — Write `tests/test_log_analyser.py`
- `test_detect_apache`: two Apache log lines → format == "apache".
- `test_detect_auth`: two auth.log lines → format == "auth".
- `test_parse_apache_top_ips`: 5-line fixture with 3 unique IPs; assert correct
  frequency ordering.
- `test_parse_apache_status_counts`: fixture with 200, 404, 404, 500 lines; assert
  2xx=1, 4xx=2, 5xx=1.
- `test_parse_auth_failed`: 3-line fixture with two "Failed password" lines;
  assert `failed_auth` and `failed_auth_ips` have correct counts.
- `test_unknown_format`: random text lines → format == "unknown", parsed_lines == 0.

---

## Group 2 — File Metadata Extractor Engine

### 2.1 — Create `app/modules/file_metadata.py`
Define dataclasses:
```python
@dataclass
class MetaField:
    key:       str
    value:     str
    sensitive: bool   # GPS, Author, last-modified-by → True

@dataclass
class MetaResult:
    file_path: str
    file_type: str   # "image" | "pdf" | "docx" | "xlsx" | "unknown"
    fields:    list[MetaField]
    error:     str
```

### 2.2 — Implement image EXIF extraction (`_extract_image`)
- Open with `PIL.Image.open(path)`.
- Call `img._getexif()` (JPEG) or `img.getexif()` (general); map tag IDs to names via
  `PIL.ExifTags.TAGS`.
- Extract: `Make`, `Model`, `DateTime`, `Software`, `Orientation`.
- Extract GPS: tag 34853 (`GPSInfo`); convert `GPSLatitude`/`GPSLongitude` rational
  tuples to decimal degrees; mark `sensitive=True`.
- Return `MetaResult(file_type="image", ...)`.

### 2.3 — Implement PDF metadata extraction (`_extract_pdf`)
- Open with `pypdf.PdfReader(path)`.
- Read `reader.metadata`; extract `/Title`, `/Author`, `/Creator`, `/Producer`,
  `/CreationDate`, `/ModDate`.
- Mark `/Author` as `sensitive=True`.
- Return `MetaResult(file_type="pdf", ...)`.

### 2.4 — Implement Office metadata extraction (`_extract_office`)
- `.docx`: `python_docx.Document(path).core_properties`; extract `author`,
  `last_modified_by`, `created`, `modified`, `revision`, `company`.
- `.xlsx`: `openpyxl.load_workbook(path, read_only=True).properties`; same fields.
- Mark `author` and `last_modified_by` as `sensitive=True`.

### 2.5 — Implement public `extract(path: str) -> MetaResult`
- Detect type by extension (`.jpg`/`.jpeg`/`.png`/`.tiff`/`.tif`/`.webp` → image;
  `.pdf` → pdf; `.docx` → docx; `.xlsx` → xlsx).
- Dispatch to correct extractor; catch all exceptions → return `MetaResult` with
  `error` field set, never raise.
- Unknown extension → `MetaResult(file_type="unknown", fields=[], error="")`.

### 2.6 — Write `tests/test_file_metadata.py`
- `test_unknown_extension`: `extract("file.xyz")` → `file_type == "unknown"`, no error.
- `test_pdf_error_handling`: `extract("nonexistent.pdf")` → `error` field non-empty,
  no exception raised.
- `test_meta_field_sensitive_flag`: construct a `MetaField` with `sensitive=True`;
  assert attribute is accessible.
- `test_gps_decimal_conversion`: call the internal `_gps_to_decimal` helper with
  known rational values; assert correct float output.

---

## Group 3 — Hash Verifier Engine

### 3.1 — Create `app/modules/hash_verifier.py`
Define dataclasses:
```python
@dataclass
class HashResult:
    file_path: str
    md5:       str
    sha1:      str
    sha256:    str
    sha512:    str
    error:     str

@dataclass
class VerifyResult:
    matched_algorithm: str   # "MD5" | "SHA-1" | "SHA-256" | "SHA-512" | ""
    match:             bool
```
```

### 3.2 — Implement `compute(path: str, stop_event, on_progress) -> HashResult`
- Read file in 1 MB chunks; update all four `hashlib` objects per chunk.
- Call `on_progress(bytes_read, total_bytes)` after each chunk.
- Check `stop_event` between chunks.
- Return `HashResult` with hex digests; set `error` on any `OSError`.

### 3.3 — Implement `verify(result: HashResult, expected: str) -> VerifyResult`
- Normalise `expected` to lowercase, strip whitespace.
- Compare against each digest; return `VerifyResult` with the matching algorithm name
  and `match=True`, or `matched_algorithm=""` and `match=False` if none match.

### 3.4 — Write `tests/test_hash_verifier.py`
- `test_compute_known_hash`: write a small known byte string to a temp file; compute
  hashes; assert SHA-256 matches `hashlib.sha256(b"...").hexdigest()`.
- `test_verify_match`: build a `HashResult` with known digests; `verify()` with correct
  SHA-256 → `match=True`, `matched_algorithm=="SHA-256"`.
- `test_verify_no_match`: `verify()` with wrong hash string → `match=False`.
- `test_verify_case_insensitive`: uppercase expected hash → still matches.
- `test_compute_error`: `compute("nonexistent_file.bin", ...)` → `error` field
  non-empty, no exception raised.

---

## Group 4 — UI Pages

### 4.1 — Create `app/ui/pages/log_analyser.py`
- `LogAnalyserPage(CTkFrame)`.
- File picker button (via `tkinter.filedialog.askopenfilename`) + selected path label.
- **Analyse** button → starts background thread → polls queue.
- Summary bar: format detected, total lines, parsed lines.
- Four result panels in a 2×2 grid of cards:
  - **Top IPs** — `ttk.Treeview` (IP | Requests | %).
  - **Status Codes** — coloured labels per group (2xx green, 3xx blue, 4xx amber, 5xx red).
  - **Error Spike** — `ttk.Treeview` (Hour | Error Count); top 10 hours.
  - **Failed Auth** — `ttk.Treeview` (Username | Attempts); only populated for auth.log.
- Copy Top IPs button (clipboard TSV).
- Stop button cancels in-flight analysis.

### 4.2 — Create `app/ui/pages/file_metadata.py`
- `FileMetadataPage(CTkFrame)`.
- File picker button + selected path label + detected type chip.
- **Extract** button → calls `extract()` synchronously (fast, no network).
- Results `ttk.Treeview`: Field | Value columns.
- Sensitive fields highlighted with amber foreground text (`sensitive=True`).
- Clear button resets all widgets.
- "No metadata extractable" label shown for unknown types.

### 4.3 — Create `app/ui/pages/hash_verifier.py`
- `HashVerifierPage(CTkFrame)`.
- File picker button + selected path label.
- **Compute** button → starts background thread; progress label shows
  "Hashing… X MB / Y MB".
- Four read-only entry fields: MD5 / SHA-1 / SHA-256 / SHA-512 (monospaced font).
- Expected hash input field + **Verify** button.
- Result label: large green "✓ MATCH (SHA-256)" or red "✗ NO MATCH".
- Stop button cancels in-flight hashing.

---

## Group 5 — Wiring & Documentation

### 5.1 — Add new sidebar category in `app/data/categories.py`
Append a new `Category` after `wordlist_utils`:
```python
Category("forensics_blue", "Forensics / Blue Team", [
    ToolEntry("Log Analyser",    "📋", "log_analyser"),
    ToolEntry("File Metadata",   "🔍", "file_metadata"),
    ToolEntry("Hash Verifier",   "✅", "hash_verifier"),
]),
```

### 5.2 — Wire pages into `app/ui/app_window.py`
Import the three page classes; add `_add_page()` calls.

### 5.3 — Add home-page cards in `app/ui/pages/home.py`
Three entries in `CARD_DATA` with `tag: "Active"` and `tag_color: "#22c55e"`.

### 5.4 — Bump sidebar version to `v4.5.0` in `app/ui/sidebar.py`
Update both occurrences.

### 5.5 — Add new dependencies to `requirements.txt`
```
# v4.5
Pillow>=10.0.0
pypdf>=4.0.0
python-docx>=1.1.0
openpyxl>=3.1.0
```

### 5.6 — Update `docs/roadmap.md`
Change v4.5 heading to `## v4.5 — Forensics & Blue Team ✅ Complete`
and add a Status column to the module table.

### 5.7 — Commit spec files on the feature branch
Ensure `specs/2026-07-01-forensics-blue-team/` is committed before implementation begins.
