# CyberKit — Implementation Plan (SDD Index)

> **SDD workflow:** spec → implement → changelog → promote.
> New feature? Run `/sdd-next-spec`. Feature shipped? Run `/sdd-changelog`.
> Constitution: [`mission.md`](mission.md) · [`roadmap.md`](roadmap.md) · [`tech-stack.md`](tech-stack.md)

## Spec Index

| # | Module | Spec | Status |
|---|---|---|---|
| 01 | Directory Fuzzer | [specs/01-dir-fuzzer.md](../specs/01-dir-fuzzer.md) | ✅ v1.0 |
| 02 | Port Scanner | [specs/2026-06-25-v1.1-network-header/](../specs/2026-06-25-v1.1-network-header/) | ✅ v1.1 |
| 03 | Header Analyser | [specs/2026-06-25-v1.1-network-header/](../specs/2026-06-25-v1.1-network-header/) | ✅ v1.1 |
| 04 | Credential Tester | ../specs/04-credential-tester.md | 📋 Planned |
| 05 | DNS & Subdomain Enumerator | ../specs/05-dns-enumerator.md | 📋 Planned |
| 06 | Tech Fingerprinter | ../specs/06-tech-fingerprinter.md | 📋 Planned |
| 07 | Hash Identifier & Cracker | ../specs/07-hash-cracker.md | 📋 Planned |
| 08 | Encoder / Decoder | ../specs/08-encoder-decoder.md | 📋 Planned |

---

# CyberKit — Unified Cybersecurity Learning Tool (Original Design Doc)

A Python desktop application with a modern GUI, designed as an extensible platform for pen-testing learning tools. The first module is a **Directory Fuzzer**.

---

## Background

Most pen-testing tools are terminal-only and not beginner-friendly. This tool will feature a polished, dark-themed GUI with a collapsible sidebar for navigation between modules. Each module is self-contained, making it trivial to add new features over time.

---

## Proposed Technology Stack

| Layer | Choice | Reason |
|---|---|---|
| GUI Framework | **CustomTkinter** | Modern dark-themed widgets on top of Tkinter; no external runtime, pure Python |
| HTTP Requests | **requests** + **concurrent.futures** | Async directory scanning with thread pool |
| Wordlist storage | Python list in a dedicated module | Easy to grow; no file dependency at runtime |
| Packaging | Single-folder project, run with `python main.py` | Simple for a learning environment |

> [!NOTE]
> CustomTkinter gives us rounded corners, dark mode, and custom color schemes without the complexity of Qt or Electron.

---

## Project Structure

```
M00 - AI Tool/
├── main.py                   # Entry point — launches the app
├── requirements.txt          # pip dependencies
├── app/
│   ├── __init__.py
│   ├── ui/
│   │   ├── __init__.py
│   │   ├── app_window.py     # Root window + sidebar layout
│   │   ├── sidebar.py        # Collapsible sidebar with nav items
│   │   └── pages/
│   │       ├── __init__.py
│   │       ├── home.py       # Welcome / dashboard page
│   │       └── fuzzer.py     # Directory Fuzzer page
│   ├── modules/
│   │   ├── __init__.py
│   │   └── dir_fuzzer.py     # Fuzzing logic (requests, threading)
│   └── data/
│       ├── __init__.py
│       └── wordlists.py      # 100+ common directory names
```

---

## Proposed Changes

### `main.py` [NEW]
Entry point — initialises CustomTkinter and launches `AppWindow`.

---

### `requirements.txt` [NEW]
```
customtkinter>=5.2.0
requests>=2.31.0
```

---

### `app/data/wordlists.py` [NEW]
A curated list of **130+ common web directories** grouped by category:
- Admin panels (`/admin`, `/administrator`, `/wp-admin`, `/phpmyadmin`, …)
- Config & backup files (`.env`, `/config`, `/backup`, …)
- API endpoints (`/api`, `/api/v1`, `/graphql`, …)
- Dev artefacts (`/.git`, `/.svn`, `/debug`, …)
- CMS-specific paths (WordPress, Joomla, Drupal, …)
- Upload & media dirs (`/uploads`, `/images`, `/media`, …)

---

### `app/modules/dir_fuzzer.py` [NEW]
Core fuzzing logic:
- `FuzzerEngine` class
- Accepts a base URL + wordlist
- Uses `ThreadPoolExecutor` (configurable threads, default 10)
- Per-path HTTP HEAD/GET request with timeout
- Emits results via a thread-safe `queue.Queue` so the GUI can poll without blocking
- Result object: `{ path, status_code, found: bool, response_time_ms }`

---

### `app/ui/sidebar.py` [NEW]
Collapsible sidebar component:
- Toggle button (hamburger/arrow icon) to expand/collapse
- When collapsed → shows only icons (40 px wide)
- When expanded → shows icons + labels (200 px wide)
- Smooth width animation (10-step interpolation)
- Navigation items: **Home**, **Dir Fuzzer** (more to be added later)
- Active item highlighted with accent colour

---

### `app/ui/pages/fuzzer.py` [NEW]
Directory Fuzzer UI page:
- **URL input bar** + **Start / Stop** button
- **Thread count** slider (1–20)
- **Progress bar** + live status label (e.g. "Scanning 42 / 130…")
- **Summary cards** — two large stat cards:
  - ✅ Found (green)
  - ❌ Not Found (grey)
- **Results table** (scrollable) with columns: Path | Status Code | Response Time | Found
- **Filter bar** — text search + dropdown filter: All / Found / Not Found
- Results update live as scan progresses (queue polling every 100 ms via `after()`)
- Export results button (saves to `.txt` or `.csv`)

---

### `app/ui/pages/home.py` [NEW]
A welcome dashboard showing:
- Tool name + tagline
- Module cards (clickable, navigates to module)
- A disclaimer banner ("For educational use only")

---

### `app/ui/app_window.py` [NEW]
Root window:
- Sets title, icon, minimum size (900 × 600)
- Manages sidebar + main content area with a grid layout
- `show_page(page_name)` method to swap content frames

---

## Design Aesthetic

- **Theme**: Dark mode, almost-black background (`#0f1117`)
- **Accent**: Electric cyan (`#00d4ff`) for highlights, buttons, active states
- **Secondary accent**: Muted purple (`#7c3aed`) for info/secondary
- **Found items**: Green (`#22c55e`)
- **Not-found items**: Muted grey (`#6b7280`)
- **Font**: Inter (bundled via system, fallback to Segoe UI)
- Rounded corners on all cards and inputs
- Subtle separator lines between sidebar sections

---

## Open Questions

> [!IMPORTANT]
> **Q1 — HTTP Method**: Should the fuzzer use `HEAD` requests first (faster, less bandwidth) and fall back to `GET` if the server doesn't support HEAD? Or always use `GET`?

> [!IMPORTANT]
> **Q2 — "Found" definition**: Should a directory be considered "found" only on `200 OK`, or also on redirects (`301`, `302`) and `403 Forbidden` (which indicates the path exists but is protected)?

> [!NOTE]
> **Q3 — Export format**: The results table will have an export button. Preferred format: `.csv`, `.txt`, or both?

---

## Verification Plan

### Automated
- Run `python main.py` and confirm the window launches without errors.
- Scan `http://localhost` (or a local test server) and verify results appear live.

### Manual
- Confirm sidebar collapse/expand animation works.
- Confirm filter dropdown correctly shows only Found / Not Found items.
- Confirm Stop button halts the scan mid-way.
