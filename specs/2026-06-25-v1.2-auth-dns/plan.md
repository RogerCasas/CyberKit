# v1.2 — Auth & DNS Recon: Implementation Plan

## Group 1 — Dependencies & Data

1.1 Add `dnspython>=2.4.0` and `paramiko>=3.4.0` to `requirements.txt`.

1.2 Add a bundled subdomain wordlist to `app/data/wordlists.py` (≈500 entries, e.g. `www`, `mail`, `ftp`, `dev`, `staging`, `api`, `admin`, `vpn`, …).

1.3 Add a small bundled credential wordlist to `app/data/wordlists.py` — separate lists for usernames (`admin`, `root`, `user`, `test`, …) and passwords (`password`, `123456`, `admin`, `test`, …).

---

## Group 2 — Credential Tester Module

2.1 Create `app/ui/credential_tester_page.py` following the same `BasePage` / `CTkFrame` structure used by existing modules.

2.2 Implement the **HTTP tab** UI:
  - URL input, HTTP method selector (POST / Basic), username field + Browse button, password field + Browse button.
  - Delay slider (0.0 – 5.0 s, default 0.5 s) with a live label showing the current value.
  - Disclaimer banner (same style as other modules).
  - Treeview results table: columns — `#`, `Username`, `Password`, `Status`, `Response Code`.
  - Start / Stop button pair.

2.3 Implement the **SSH tab** UI:
  - Host input, Port input (default 22), username field + Browse button, password field + Browse button.
  - Delay slider (same as HTTP tab).
  - Disclaimer banner.
  - Treeview results table: columns — `#`, `Username`, `Password`, `Status`.
  - Start / Stop button pair.

2.4 Implement the **HTTP scan engine** (`app/scanners/credential_http_scanner.py`):
  - Accepts a target URL, auth type, username list, password list, and delay.
  - For Basic auth: uses `requests.get(url, auth=(user, password))`.
  - For POST: sends `requests.post(url, data={...})` and detects success by HTTP 200 + absence of a configurable failure string (default: "Invalid" / "incorrect" / "failed").
  - Emits `ScanResult`-compatible tuples into a `queue.Queue`.
  - Respects a `threading.Event` stop signal.

2.5 Implement the **SSH scan engine** (`app/scanners/credential_ssh_scanner.py`):
  - Uses `paramiko.SSHClient` with `AutoAddPolicy`.
  - Emits result tuples into a `queue.Queue`; respects stop signal.
  - Catches `paramiko.AuthenticationException` (fail), `paramiko.SSHException` / `socket.error` (error).

2.6 Wire the scan engines to the UI via `widget.after` polling (same pattern as `port_scanner_page.py`).

2.7 Implement **wordlist file import** (Browse button handler): `filedialog.askopenfilename`, read lines, strip whitespace, filter blanks — reusable helper in `app/utils/file_helpers.py`.

2.8 Implement **CSV/TXT export** (reuse or extend the export helper already present in the codebase).

2.9 Register the page in `app/ui/app_window.py` sidebar and home page card.

---

## Group 3 — DNS & Subdomain Enumerator Module

3.1 Create `app/ui/dns_enumerator_page.py` following the same `BasePage` structure.

3.2 Implement the **Record Lookup tab** UI:
  - Domain input, record type checkboxes (A, AAAA, MX, NS, TXT).
  - "Resolve" button (single-shot, no threading needed for a handful of lookups).
  - Treeview results table: columns — `Type`, `Value`, `TTL`.
  - Disclaimer banner.

3.3 Implement the **Subdomain Brute-Force tab** UI:
  - Domain input, wordlist source toggle (Bundled / Custom file) + Browse button.
  - Thread count selector (default 20).
  - Treeview results table: columns — `#`, `Subdomain`, `IP Address`, `Status`.
  - Start / Stop button pair.
  - Export button (CSV/TXT).

3.4 Implement the **DNS record lookup engine** (`app/scanners/dns_lookup_scanner.py`):
  - Uses `dns.resolver.resolve(domain, record_type)` for each selected type.
  - Returns results synchronously (no queue needed — fast single query).

3.5 Implement the **subdomain brute-force engine** (`app/scanners/subdomain_scanner.py`):
  - Thread pool; each worker resolves `{candidate}.{domain}` via `dns.resolver.resolve`.
  - Emits `(subdomain, ip, status)` tuples into a `queue.Queue`; respects stop signal.
  - Catches `dns.resolver.NXDOMAIN` (not found), `dns.resolver.NoAnswer`, `dns.exception.Timeout`.

3.6 Wire both engines to the UI via `widget.after` polling.

3.7 Reuse the Browse button + file import helper from Group 2 (step 2.7).

3.8 Implement CSV/TXT export for the brute-force tab.

3.9 Register the page in `app/ui/app_window.py` sidebar and home page card.

---

## Group 4 — Final Integration & Cleanup

4.1 Update `requirements.txt` (confirmed in 1.1; verify the file is correct after all wiring is done).

4.2 Update `roadmap.md` — mark v1.2 rows as ✅ Done.

4.3 Update `CHANGELOG.md` with v1.2 entry.

4.4 Commit spec files, then commit implementation on the `phase-3-v1.2-auth-dns` branch.
