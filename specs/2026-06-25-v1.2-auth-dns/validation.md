# v1.2 — Auth & DNS Recon: Validation Checklist

---

## Group 1 — Dependencies & Data

- [ ] `requirements.txt` contains `dnspython>=2.4.0` and `paramiko>=3.4.0`.
- [ ] `pip install -r requirements.txt` completes without errors on a clean Python 3.11+ environment.
- [ ] `app/data/wordlists.py` exposes a subdomain wordlist with ≥ 500 entries.
- [ ] `app/data/wordlists.py` exposes a default username list and a default password list.

---

## Group 2 — Credential Tester

### HTTP tab
- [ ] Credential Tester page loads from the sidebar without errors.
- [ ] HTTP tab is the default active tab on open.
- [ ] URL input, method selector (POST / Basic), username field, and password field are all present.
- [ ] Browse button for username list opens a file dialog and populates the field with the selected file path.
- [ ] Browse button for password list opens a file dialog and populates the field with the selected file path.
- [ ] Delay slider ranges from 0.0 to 5.0 s; label updates live as the slider moves.
- [ ] Disclaimer banner is visible above the input area.
- [ ] Clicking Start begins the scan; results appear live in the Treeview (`#`, `Username`, `Password`, `Status`, `Response Code`).
- [ ] Successful HTTP Basic auth attempt against a known target (e.g. DVWA with Basic auth) is reported as `Success`.
- [ ] Failed attempts are reported as `Failed`.
- [ ] Clicking Stop halts the scan cleanly with no crash.
- [ ] Export to CSV produces a valid file with correct headers and all result rows.
- [ ] Export to TXT produces a readable plain-text file.
- [ ] No Tk widget is accessed from a worker thread (no `RuntimeError: main thread is not in main loop`).

### SSH tab
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
- [ ] DNS Enumerator page loads from the sidebar without errors.
- [ ] Record Lookup tab is the default active tab on open.
- [ ] Domain input and record type checkboxes (A, AAAA, MX, NS, TXT) are present.
- [ ] Disclaimer banner is visible.
- [ ] Clicking Resolve populates the Treeview with `Type`, `Value`, `TTL` for each selected record type.
- [ ] Non-existent domain shows a clear "No records found" or error message rather than crashing.
- [ ] Results for a real domain (e.g. `example.com`) match those from a reference tool (e.g. `nslookup`).

### Subdomain Brute-Force tab
- [ ] Subdomain Brute-Force tab is accessible.
- [ ] Domain input, wordlist toggle (Bundled / Custom), Browse button, and thread count selector present.
- [ ] Selecting "Bundled" uses the wordlist from `app/data/wordlists.py`.
- [ ] Selecting "Custom" and browsing to a .txt file uses that file's entries.
- [ ] Clicking Start spawns threads and results appear live in the Treeview (`#`, `Subdomain`, `IP Address`, `Status`).
- [ ] Discovered subdomains of a lab target (e.g. `www.`, `mail.` of a known domain) appear as `Found`.
- [ ] `NXDOMAIN` entries are shown as `Not Found` and do not crash.
- [ ] Clicking Stop halts the scan cleanly.
- [ ] Export to CSV and TXT work correctly.
- [ ] No Tk widget is accessed from a worker thread.

---

## Group 4 — Integration

- [ ] Both modules appear in the sidebar navigation and are reachable by clicking.
- [ ] Both module cards on the home page show `Active` (not `Coming Soon`).
- [ ] Switching between any two modules does not produce errors or UI corruption.
- [ ] App launches cleanly with `python main.py` after `pip install -r requirements.txt`.
- [ ] `roadmap.md` v1.2 rows are marked ✅ Done.
- [ ] `CHANGELOG.md` contains a v1.2 entry describing both modules.
- [ ] Spec files (`requirements.md`, `plan.md`, `validation.md`) are committed on the feature branch.
- [ ] All validation items above pass against at least one real lab target (DVWA, HackTheBox, or local test server).
