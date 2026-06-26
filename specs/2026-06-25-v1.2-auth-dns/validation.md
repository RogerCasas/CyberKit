# v1.2 — Auth & DNS Recon: Validation Checklist

---

## Group 1 — Dependencies & Data

- [x] `requirements.txt` contains `dnspython>=2.4.0` and `paramiko>=3.4.0`.
- [x] `pip install -r requirements.txt` completes without errors on a clean Python 3.11+ environment.
- [x] `app/data/wordlists.py` exposes a subdomain wordlist with ≥ 500 entries. *(524 entries, 521 unique — expanded from 289 during validation pass)*
- [x] `app/data/wordlists.py` exposes a default username list and a default password list.

---

## Group 2 — Credential Tester

### HTTP tab
- [x] Credential Tester page loads from the sidebar without errors.
- [x] HTTP tab is the default active tab on open.
- [x] URL input, method selector (POST / Basic), username field, and password field are all present.
- [x] Browse button for username list opens a file dialog and populates the field with the selected file path.
- [x] Browse button for password list opens a file dialog and populates the field with the selected file path.
- [x] Delay slider ranges from 0.0 to 5.0 s; label updates live as the slider moves.
- [x] Disclaimer banner is visible above the input area.
- [x] Clicking Start begins the scan; results appear live in the Treeview (`#`, `Username`, `Password`, `Status`, `Response Code`).
- [x] Successful HTTP Basic auth attempt against a known target (e.g. DVWA with Basic auth) is reported as `Success`.
- [x] Failed attempts are reported as `Failed`.
- [ ] Clicking Stop halts the scan cleanly with no crash.
- [ ] Export to CSV produces a valid file with correct headers and all result rows.
- [ ] Export to TXT produces a readable plain-text file.
- [x] No Tk widget is accessed from a worker thread (no `RuntimeError: main thread is not in main loop`).

### SSH tab

> **Pending** — OpenSSH Server not available on current device. Re-test against a local SSH server or lab machine.

- [ ] SSH tab is accessible by clicking the tab control.
- [ ] Host, Port (default 22), username field, and password field are all present.
- [ ] Browse buttons work identically to the HTTP tab.
- [ ] Delay slider present with same range.
- [ ] Disclaimer banner visible.
- [ ] Clicking Start tests SSH credentials against a lab target (e.g. local SSH server or HackTheBox machine); successes reported as `Success`.
- [ ] `paramiko.AuthenticationException` is caught and reported as `Failed` (not a crash).
- [ ] Network errors (unreachable host) are caught and reported as `Error` (not a crash).
- [ ] Clicking Stop halts cleanly.
- [ ] Export to CSV and TXT work correctly.

---

## Group 3 — DNS & Subdomain Enumerator

### Record Lookup tab
- [x] DNS Enumerator page loads from the sidebar without errors.
- [x] Record Lookup tab is the default active tab on open.
- [x] Domain input and record type checkboxes (A, AAAA, MX, NS, TXT) are present.
- [x] Disclaimer banner is visible.
- [x] Clicking Resolve populates the Treeview with `Type`, `Value`, `TTL` for each selected record type.
- [ ] Non-existent domain shows a clear "No records found" or error message rather than crashing.
- [x] Results for a real domain (e.g. `example.com`) match those from a reference tool (e.g. `nslookup`).

### Subdomain Brute-Force tab
- [x] Subdomain Brute-Force tab is accessible.
- [x] Domain input, wordlist toggle (Bundled / Custom), Browse button, and thread count selector present.
- [x] Selecting "Bundled" uses the wordlist from `app/data/wordlists.py`.
- [ ] Selecting "Custom" and browsing to a .txt file uses that file's entries.
- [x] Clicking Start spawns threads and results appear live in the Treeview (`#`, `Subdomain`, `IP Address`, `Status`).
- [x] Discovered subdomains of a lab target (e.g. `www.`, `mail.` of a known domain) appear as `Found`.
- [x] `NXDOMAIN` entries are shown as `Not Found` and do not crash.
- [ ] Clicking Stop halts the scan cleanly.
- [ ] Export to CSV and TXT work correctly.
- [x] No Tk widget is accessed from a worker thread.

---

## Group 4 — Integration

- [x] Both modules appear in the sidebar navigation and are reachable by clicking.
- [x] Both module cards on the home page show `Active` (not `Coming Soon`).
- [x] Switching between any two modules does not produce errors or UI corruption.
- [x] App launches cleanly with `python main.py` after `pip install -r requirements.txt`.
- [x] `roadmap.md` v1.2 rows are marked ✅ Done.
- [x] `CHANGELOG.md` contains a v1.2 entry describing both modules.
- [x] Spec files (`requirements.md`, `plan.md`, `validation.md`) are committed on the feature branch.
- [ ] All validation items above pass against at least one real lab target (DVWA, HackTheBox, or local test server). *(Blocked by SSH tab — re-check once OpenSSH is available)*
