# v3.2 — Password & Network Tools: Implementation Plan

---

## Group 1 — Password Generator Engine

**Goal:** A pure-Python engine with no UI dependency, fully unit-testable.

1.1 Create `app/modules/wordlist_generator.py`.
- `BruteforceGenerator(charset, min_len, max_len)` — iterates via `itertools.product`; exposes `__iter__` and `estimated_count() -> int`.
- `MutationGenerator(seeds, rules)` — rules is a dict of booleans: `leet`, `upper`, `lower`, `title`, `suffixes`; exposes `__iter__` and `estimated_count() -> int`.
- Both generators are lazy (yield one entry at a time) so the preview can stop after 20 without computing the full set.
- `LEET_MAP = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$'}` — applied character-by-character.
- `generate_to_file(generator, path, on_progress, stop_event)` — writes to disk in 4 KB batches, calls `on_progress(n)` every 1,000 entries, respects `stop_event`.

1.2 Add unit tests in `tests/test_wordlist_generator.py`:
- Brute-force: `charset='ab', min=1, max=2` → `['a','b','aa','ab','ba','bb']`.
- Mutation leet: `seed='pass'` → contains `'p@$$'`.
- Mutation suffixes: `seed='test'` → contains `'test1'`, `'test99'`.
- Estimated count matches actual iteration length for small inputs.
- `generate_to_file` writes correct entry count and respects 1 M cap.

---

## Group 2 — ARP Scanner Engine + OUI Table

**Goal:** A Scapy-backed scanner and a bundled vendor table, both independent of the UI.

2.1 Create `app/data/oui_table.py`:
- `OUI_TABLE: dict[str, str]` — maps 6-char uppercase hex prefix (e.g. `"001A2B"`) to vendor name.
- Source from trimmed IEEE OUI registry; target ~5,000 most common prefixes.
- `lookup_vendor(mac: str) -> str` — normalises MAC, extracts first 3 octets, returns vendor or `"Unknown"`.

2.2 Create `app/modules/arp_scanner.py`:
- `ARPResult` dataclass: `index, ip, mac, vendor, hostname`.
- `check_privileges() -> bool` — `os.geteuid() == 0` on Unix; `ctypes.windll.shell32.IsUserAnAdmin()` on Windows.
- `auto_detect_subnet() -> str` — uses `scapy.conf.iface` to read the default interface's IP and netmask, returns CIDR string.
- `ARPScanner(subnet, timeout_s)` — `start(on_result, on_done)` / `stop()` / `_run(on_result, on_done)` following the same sentinel-queue pattern as other scanners.
- `_run` sends ARP packets via `scapy.layers.l2.arping`, iterates answered packets, resolves vendor, attempts reverse DNS with `socket.gethostbyaddr` (catches on error), calls `on_result(ARPResult(...))` per host, then `on_done()`.

---

## Group 3 — Password Generator UI

**Goal:** Two-tab page wired to the engine, matching CyberKit's visual design.

3.1 Create `app/ui/pages/wordlist_generator.py` — `WordlistGeneratorPage(CTkFrame)`:
- Header: "🔑  Password / Wordlist Generator", subtitle.
- Tab bar: "Brute-Force" / "Mutation" (same CTkButton pair + `_switch_tab` flicker fix).
- **Brute-Force tab** — ctrl card:
  - Charset checkboxes: Lowercase (a–z), Uppercase (A–Z), Digits (0–9), Symbols (!@#$%^&*).
  - Min length / Max length spinners (1–8, capped to prevent runaway estimates).
  - Estimated count label (updates live).
  - Warning label (red) when estimate > 1 M.
  - Generate button (disabled when > 1 M or no charset selected).
  - Live preview frame: 20-entry label list, updates on any option change.
- **Mutation tab** — ctrl card:
  - Seed phrases text box (multi-line, one per line).
  - Rule checkboxes: Leet-speak, Lowercase, Uppercase, Title Case, Numeric Suffixes (1–99).
  - Custom prefix field (optional), custom suffix field (optional).
  - Estimated count label.
  - Warning label when > 1 M.
  - Generate button.
  - Live preview frame (same 20-entry design).
- Below both tabs: Generate & Export button → `filedialog.asksaveasfilename` → `generate_to_file` in background thread; progress label "Generating… N entries written".
- "Send to Credential Tester ▶ Username list" and "Send to Credential Tester ▶ Password list" buttons — store the exported path in a shared app-level string; Credential Tester's Browse buttons check this on open.

3.2 Wire into `app/ui/app_window.py` and `app/ui/sidebar.py`:
- Register page key `"wordlist_generator"`.
- Sidebar nav item: `("Wordlist Gen", "📝", "wordlist_generator")`.

3.3 Update `app/ui/pages/home.py` — Wordlist Generator card: tag `"Active"`, page `"wordlist_generator"`.

---

## Group 4 — ARP Scanner UI

**Goal:** A single-tab page for the ARP Scanner with privilege awareness.

4.1 Create `app/ui/pages/arp_scanner.py` — `ARPScannerPage(CTkFrame)`:
- Header: "📡  ARP Scanner", subtitle explaining layer-2 and the admin requirement.
- Admin warning banner (amber) shown always: "⚠ This module requires administrator privileges. Re-run CyberKit as administrator if the scan fails."
- Ctrl card:
  - Subnet entry (placeholder: auto-detected CIDR); "Auto-detect" button fills the field.
  - Timeout slider 1–10 s.
  - Start/Stop button.
  - Status label.
- Results Treeview: #, IP, MAC, Vendor, Hostname — styled with `ARP.Treeview` style (same palette).
- On Start: call `check_privileges()`; if False, show error in status label and abort (do not start scan).
- Queue + sentinel pattern (`on_done` puts `None`; poll loop on main thread).
- CSV + TXT export.

4.2 Wire into `app/ui/app_window.py` and `app/ui/sidebar.py`:
- Register page key `"arp_scanner"`.
- Sidebar nav item: `("ARP Scanner", "📡", "arp_scanner")`.

4.3 Update `app/ui/pages/home.py` — ARP Scanner card: tag `"Active"` (or `"Admin required"` in amber if you prefer a visual flag), page `"arp_scanner"`.

---

## Group 5 — Dependency, Docs & Integration

5.1 Add `scapy>=2.5.0` to `requirements.txt` with a comment noting admin requirement.

5.2 Update `tech-stack.md` — confirm scapy entry, add OUI table note.

5.3 Update `roadmap.md` — mark v3.2 ✅ Complete.

5.4 Update `CHANGELOG.md` — document both modules per the existing format.

5.5 End-to-end integration test:
- Generate a small wordlist (brute-force, lowercase only, length 1–2 → 26+676 = 702 entries).
- Use "Send to Credential Tester ▶ Password list"; verify Credential Tester's password label updates to "Custom (702 entries)".
- Verify the Credential Tester can start a scan using that list (it needn't succeed — just confirm the engine reads it).

5.6 Commit spec files; push branch.
