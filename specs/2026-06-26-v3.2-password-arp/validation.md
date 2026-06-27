# v3.2 — Password & Network Tools: Validation Checklist

---

## Group 1 — Password Generator Engine

- [ ] `BruteforceGenerator(charset='ab', min_len=1, max_len=2)` yields exactly `['a','b','aa','ab','ba','bb']` in that order.
- [ ] `BruteforceGenerator.estimated_count()` returns the correct total for several known inputs without iterating.
- [ ] `MutationGenerator` with leet rule enabled produces `'p@$$'` from seed `'pass'`.
- [ ] `MutationGenerator` with numeric suffixes produces `'test1'` through `'test99'` from seed `'test'`.
- [ ] `MutationGenerator.estimated_count()` matches the actual number of items yielded for a small seed set.
- [ ] `generate_to_file` writes exactly the expected number of lines to a temp file.
- [ ] `generate_to_file` stops at 1,000,000 entries when the generator would exceed that cap.
- [ ] All unit tests in `tests/test_wordlist_generator.py` pass with `python -m pytest`.

---

## Group 2 — ARP Scanner Engine + OUI Table

- [ ] `lookup_vendor` returns `"Apple, Inc."` (or equivalent) for MAC prefix `"000A95"`.
- [ ] `lookup_vendor` returns `"Unknown"` for a random/unregistered prefix.
- [ ] `lookup_vendor` handles colons, dashes, and no-separator MAC formats without crashing.
- [ ] `check_privileges()` returns `False` when run without elevation (verify by running as normal user).
- [ ] `auto_detect_subnet()` returns a valid CIDR string (e.g. `"192.168.1.0/24"`) on the dev machine.
- [ ] `ARPScanner` calls `on_done()` after the scan completes (even if zero hosts respond).
- [ ] `ARPScanner.stop()` halts the scan without raising an exception.

---

## Group 3 — Password Generator UI

- [ ] Page loads without error from the sidebar nav.
- [ ] Switching between Brute-Force and Mutation tabs has no hover flicker on the inactive tab button.
- [ ] Live preview updates within ~200 ms of any option change in the Brute-Force tab.
- [ ] Live preview updates within ~200 ms of any seed phrase or rule change in the Mutation tab.
- [ ] Live preview shows at most 20 entries and does not hang for large configurations.
- [ ] Estimated count label updates live and matches the actual exported file entry count (verified on a small config).
- [ ] Warning label appears (red) and Generate button disables when estimated count exceeds 1,000,000.
- [ ] Warning and disable clear when configuration is narrowed back below the cap.
- [ ] Brute-Force Generate button is disabled when no charset checkbox is selected.
- [ ] Generate & Export produces a `.txt` file with one entry per line; file size matches entry count.
- [ ] Progress label updates visibly during generation of a mid-size wordlist (> 10,000 entries).
- [ ] "Send to Credential Tester ▶ Password list" button updates the Credential Tester's password label to `"Custom (N entries)"` without navigating away from the generator page.
- [ ] "Send to Credential Tester ▶ Username list" does the same for the username list.

---

## Group 4 — ARP Scanner UI

- [ ] Page loads without error from the sidebar nav.
- [ ] Admin warning banner is always visible in amber text above the ctrl card.
- [ ] "Auto-detect" button fills the subnet field with a valid CIDR (e.g. `192.168.1.0/24`).
- [ ] Clicking Start without admin privileges shows an error in the status label and does not crash.
- [ ] Clicking Start with admin privileges begins the scan; status label updates to scanning state.
- [ ] Results appear live in the Treeview as ARP replies arrive.
- [ ] Vendor column shows a recognisable name for at least one local device (router, phone, etc.).
- [ ] Stop button halts the scan and finalises the status label.
- [ ] CSV export produces a valid file with headers: #, IP, MAC, Vendor, Hostname.
- [ ] TXT export produces a readable plain-text report.
- [ ] Treeview auto-scrolls as new rows arrive.

---

## Group 5 — Integration & Docs

- [ ] `pip install -r requirements.txt` installs scapy without errors on a clean venv.
- [ ] **End-to-end:** Generate a brute-force wordlist (lowercase a–z, length 1–2, 702 entries), send it to the Credential Tester as Password list, open the Credential Tester — password label reads "Custom (702 entries)".
- [ ] Starting a Credential Tester scan with the sent list does not raise any exception (scan may fail to find credentials — that is expected).
- [ ] `roadmap.md` shows v3.2 ✅ Complete.
- [ ] `CHANGELOG.md` entry for v3.2 documents both modules.
- [ ] `tech-stack.md` reflects scapy and OUI table.
- [ ] Spec files committed and branch pushed to remote.
