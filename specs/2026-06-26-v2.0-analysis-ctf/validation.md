# v2.0 — Analysis & CTF Utilities: Validation Checklist

---

## Group 1 — Encoder / Decoder (automated)

Run `python tests/test_encoder_decoder.py`:

- [ ] URL encode round-trip: `encode("hello world & more?")` → `"hello%20world%20%26%20more%3F"` → original string.
- [ ] URL decode handles `%2B` correctly (decodes to `+`, not space).
- [ ] Base64 encode round-trip: `encode("CyberKit")` → `"Q3liZXJLaXQ="` → original.
- [ ] Base64 decode raises an error (not a crash) on invalid padding such as `"not_valid_b64!!"`.
- [ ] Base64 URL-safe encode/decode round-trip with a string containing `+` and `/` characters.
- [ ] HTML entity encode: `<script>alert("xss")</script>` → `&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;`.
- [ ] HTML entity decode returns the original after encoding.
- [ ] Hex encode: `"hello"` → `"68656c6c6f"`.
- [ ] Hex decode: `"68656c6c6f"` → `"hello"`.
- [ ] Hex decode raises an error on odd-length or non-hex input.
- [ ] ROT-13 applied twice returns the original: `rot13(rot13("CyberKit 2026"))` == `"CyberKit 2026"`.
- [ ] JWT inspect: a known JWT string returns correct header dict (`{"alg": "HS256", "typ": "JWT"}`) and payload dict.
- [ ] JWT inspect raises `ValueError` for a string that is not three `.`-separated parts.
- [ ] JWT inspect raises `ValueError` for a token with invalid base64url padding in the header.

### Encoder / Decoder UI (manual)

- [ ] Encoder / Decoder page loads from the sidebar without errors.
- [ ] All operation modes are selectable (URL, Base64, Base64 URL-safe, HTML Entities, Hex, ROT-13, JWT Inspect).
- [ ] Encoding and decoding produce correct output for at least one test string in each mode.
- [ ] **Swap** button moves the contents of the output panel into the input panel.
- [ ] **Clear** button empties both panels.
- [ ] An invalid input (e.g. bad Base64) shows an inline error message and does not crash.
- [ ] JWT Inspect mode shows the header and payload formatted as readable JSON.

---

## Group 2 — Hash Identifier & Cracker (automated)

Run `python tests/test_hash_tool.py`:

- [ ] `identify("5f4dcc3b5aa765d61d8327deb882cf99")` (MD5 of "password") returns a result list that includes MD5.
- [ ] `identify("da39a3ee5e6b4b0d3255bfef95601890afd80709")` (SHA-1 of empty string) includes SHA-1.
- [ ] `identify("e3b0c44298fc1c149afbf4c8996fb924...")` (SHA-256 of empty string, 64 chars) includes SHA-256.
- [ ] `identify("cf83e135...")` (SHA-512, 128 chars) includes SHA-512.
- [ ] `identify("*0A4A5CAD341293...")` (MySQL5 `*`-prefixed) includes MySQL5.
- [ ] `identify("$2b$12$...")` (bcrypt) includes bcrypt.
- [ ] An empty string returns an empty list (no false matches).
- [ ] Hash cracker finds `"password"` from `"5f4dcc3b5aa765d61d8327deb882cf99"` using the bundled `CRACK_WORDLIST` with algorithm `md5`.
- [ ] Hash cracker returns a "Not found" sentinel when the hash is not in the wordlist.
- [ ] Hash cracker `stop_event.set()` halts the engine within 2 seconds of being called.
- [ ] `HashCrackEngine` raises `ValueError` before starting when given an unsupported algorithm (e.g. `"bcrypt"`).

### Hash Tool UI (manual)

- [ ] Hash Tool page loads from the sidebar without errors.
- [ ] Identify tab is the default active tab.
- [ ] Pasting the MD5 of "password" and clicking Identify shows MD5 as a candidate.
- [ ] Crack tab: pasting the MD5 of "password", selecting MD5 algorithm, using Bundled wordlist, and clicking Start shows `"password"` as the result.
- [ ] Crack tab: clicking Stop during a long crack halts cleanly with no crash.
- [ ] Selecting an unsupported algorithm shows an inline error; scan does not start.

---

## Group 3 — Tech Fingerprinter (manual)

- [ ] Tech Fingerprinter page loads from the sidebar without errors.
- [ ] URL input field and Scan button are present; disclaimer banner is visible.
- [ ] Scanning `https://wordpress.org` returns at least one result with Technology = `WordPress`.
- [ ] Scanning `https://nginx.org` returns at least one result indicating Nginx.
- [ ] Scanning `https://example.com` completes without crashing (may return zero results — that is valid).
- [ ] Scanning an unreachable URL (e.g. `http://192.0.2.1`) shows a clear error message in the status bar; does not crash.
- [ ] Treeview shows three columns: Category, Technology, Evidence.
- [ ] Clicking Stop during a scan (if still running) halts cleanly.
- [ ] TXT export produces a readable file listing all found technologies.
- [ ] `app/data/fingerprints.py` contains ≥ 30 distinct signatures across at least 4 categories.

---

## Group 4 — Integration

- [ ] All three new modules appear in the sidebar navigation and are reachable by clicking.
- [ ] All three new module cards on the home page show `Active` (not `Coming Soon`).
- [ ] Switching between all existing and new modules produces no errors or UI corruption.
- [ ] `roadmap.md` v2.0 module rows are marked ✅ Done.
- [ ] `CHANGELOG.md` contains a v2.0 entry describing all three modules.
- [ ] Spec files (`requirements.md`, `plan.md`, `validation.md`) are committed on the feature branch.
