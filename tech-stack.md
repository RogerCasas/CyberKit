# CyberKit — Tech Stack

## Runtime

| Layer | Choice | Rationale |
|---|---|---|
| Language | **Python 3.11+** | Rich stdlib (socket, hashlib, ssl, urllib), huge security ecosystem, no compilation step |
| GUI framework | **CustomTkinter 5.2+** | Dark-mode widgets on top of Tk; no external runtime; single-folder distribution |
| Results table | **tkinter.ttk.Treeview** | Native widget; handles 500+ rows without per-cell widget allocation; styled via `ttk.Style("clam")` |

## Networking & Scanning

| Purpose | Library | Notes |
|---|---|---|
| HTTP requests (all modules) | **requests 2.31+** | Session reuse, `allow_redirects`, stream mode; browser-like headers to avoid UA-filter false negatives |
| Concurrency | **concurrent.futures.ThreadPoolExecutor** | I/O-bound tasks (HTTP, TCP) — threads outperform async here for simplicity |
| TCP port scanning | **socket** (stdlib) | Connect scan only; no raw sockets needed (avoids admin privileges) |
| DNS resolution | **dnspython** | A/AAAA/MX/NS/TXT lookups + subdomain brute-force |

## Cryptanalysis

| Purpose | Library | Notes |
|---|---|---|
| Hash computation | **hashlib** (stdlib) | MD5, SHA-1, SHA-256, SHA-512 |
| Hash identification | Pattern regex (internal) | Identify algorithm from length + charset before cracking |

## Data & Storage

| Purpose | Approach | Notes |
|---|---|---|
| Wordlists | Python list in `app/data/wordlists.py` | No file dependency at runtime; easy to extend |
| Scan results | In-memory `list[ScanResult]` | Exported to CSV/TXT on demand; no persistence needed |
| Configuration | None yet | Settings screen is a v2.x candidate |

## Thread Safety

All scan engines run in a background `threading.Thread`. Results are passed through a `queue.Queue` to the main thread, which drains it via `widget.after(N, poll_fn)`. **No Tk widget is ever touched from a worker thread.** This is a hard architectural constraint.

## Distribution

Single project folder, launched with `python main.py`. All dependencies installable via `pip install -r requirements.txt`. No packaging, installer, or virtual-environment enforcement — keeping it approachable for students.

## Key Constraints

- **No admin/root required** — TCP connect scans only (no raw socket ICMP or SYN scans).
- **No C extensions** — avoids compilation friction on lab machines.
- **Windows-first** — tested on Windows 11; CustomTkinter and ttk render correctly; Bash tool (Git Bash) and PowerShell both supported.

---

## Dependency File

```
customtkinter>=5.2.0
requests>=2.31.0
dnspython>=2.4.0
```

> `dnspython` is added in v1.2 when the DNS Enumerator module ships.

---

## Architecture Decision Records

### ADR-001 — CustomTkinter over Qt/Electron
**Context:** Python GUI framework choice.
**Decision:** CustomTkinter.
**Reason:** Zero external runtime (no Node, no Qt DLLs), dark mode built-in, pure Python — students can read and modify the widget code without a build system. Qt adds significant complexity for a learning tool.

### ADR-002 — ttk.Treeview over CTkScrollableFrame for results tables
**Context:** Initial implementation used a `CTkScrollableFrame` with one `CTkFrame + 4 × CTkLabel` per row, causing ~2500 widget allocations for 500 results and making every layout event (including sidebar toggle) noticeably slow.
**Decision:** Switch to `ttk.Treeview` with `clam` theme.
**Reason:** Treeview renders rows natively inside a single widget; `tree.insert()` is an order of magnitude faster than CTk widget creation. Row tags handle alternating backgrounds + per-category foreground colours cleanly.

### ADR-003 — Browser User-Agent in scan sessions
**Context:** Custom UA (`CyberKit/1.0 (Educational Scanner)`) caused servers with UA-filtering WAFs to return `406 Not Acceptable` for every path, making all results appear as Not Found.
**Decision:** Use a realistic browser UA + standard `Accept`/`Accept-Language` headers.
**Reason:** Real pen-testing tools (gobuster, curl, etc.) all support custom/spoofed UAs. This also serves as a teaching moment: server-side filtering on UA is a common (and easily bypassed) defence.

### ADR-004 — Preserve URL path in base URL normalisation
**Context:** `_normalise_url` originally stripped everything except `scheme://host`, so scanning `https://example.com/demoGPT/` probed `https://example.com/web` instead of `https://example.com/demoGPT/web`.
**Decision:** Preserve `parsed.path` (with trailing slash stripped) in the normalised base URL.
**Reason:** Allows targeting sub-directory deployments, which is the common case in shared hosting and CTF environments.
