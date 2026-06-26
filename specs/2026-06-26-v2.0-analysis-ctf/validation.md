# v2.0 — Analysis & CTF Utilities: Validation Checklist

---

## Group 1 — Encoder / Decoder (automated)

Run `python tests/test_encoder_decoder.py`:

- [x] URL encode round-trip: `encode("hello world & more?")` → `"hello%20world%20%26%20more%3F"` → original string.
- [x] URL decode handles `%2B` correctly (decodes to `+`, not space).
- [x] Base64 encode round-trip: `encode("CyberKit")` → `"Q3liZXJLaXQ="` → original.
- [x] Base64 decode raises an error (not a crash) on invalid padding such as `"not_valid_b64!!"`.
- [x] Base64 URL-safe encode/decode round-trip with a string containing `+` and `/` characters.
- [x] HTML entity encode: `<script>alert("xss")</script>` → `&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;`.
- [x] HTML entity decode returns the original after encoding.
- [x] Hex encode: `"hello"` → `"68656c6c6f"`.
- [x] Hex decode: `"68656c6c6f"` → `"hello"`.
- [x] Hex decode raises an error on odd-length or non-hex input.
- [x] ROT-13 applied twice returns the original: `rot13(rot13("CyberKit 2026"))` == `"CyberKit 2026"`.
- [x] JWT inspect: a known JWT string returns correct header dict (`{"alg": "HS256", "typ": "JWT"}`) and payload dict.
- [x] JWT inspect raises `ValueError` for a string that is not three `.`-separated parts.
- [x] JWT inspect raises `ValueError` for a token with invalid base64url padding in the header.

### Encoder / Decoder UI (manual)

- [x] Encoder / Decoder page loads from the sidebar without errors.
- [x] All operation modes are selectable (URL, Base64, Base64 URL-safe, HTML Entities, Hex, ROT-13, JWT Inspect).
- [x] Encoding and decoding produce correct output for at least one test string in each mode.
- [x] **Swap** button moves the contents of the output panel into the input panel.
- [x] **Clear** button empties both panels.
- [x] An invalid input (e.g. bad Base64) shows an inline error message and does not crash.
- [x] JWT Inspect mode shows the header and payload formatted as readable JSON.

---

## Group 2 — Hash Identifier & Cracker (automated)

Run `python tests/test_hash_tool.py`:

- [x] `identify("5f4dcc3b5aa765d61d8327deb882cf99")` (MD5 of "password") returns a result list that includes MD5.
- [x] `identify("da39a3ee5e6b4b0d3255bfef95601890afd80709")` (SHA-1 of empty string) includes SHA-1.
- [x] `identify("e3b0c44298fc1c149afbf4c8996fb924...")` (SHA-256 of empty string, 64 chars) includes SHA-256.
- [x] `identify("cf83e135...")` (SHA-512, 128 chars) includes SHA-512.
- [x] `identify("*0A4A5CAD341293...")` (MySQL5 `*`-prefixed) includes MySQL5.
- [x] `identify("$2b$12$...")` (bcrypt) includes bcrypt.
- [x] An empty string returns an empty list (no false matches).
- [x] Hash cracker finds `"password"` from `"5f4dcc3b5aa765d61d8327deb882cf99"` using the bundled `CRACK_WORDLIST` with algorithm `md5`.
- [x] Hash cracker returns a "Not found" sentinel when the hash is not in the wordlist.
- [x] Hash cracker `stop_event.set()` halts the engine within 2 seconds of being called.
- [x] `HashCrackEngine` raises `ValueError` before starting when given an unsupported algorithm (e.g. `"bcrypt"`).

### Hash Tool UI (manual)

- [x] Hash Tool page loads from the sidebar without errors.
- [x] Identify tab is the default active tab.
- [x] Pasting the MD5 of "password" and clicking Identify shows MD5 as a candidate.
- [x] Crack tab: pasting the MD5 of "password", selecting MD5 algorithm, using Bundled wordlist, and clicking Start shows `"password"` as the result.
- [x] Crack tab: clicking Stop during a long crack halts cleanly with no crash.
- [x] Selecting an unsupported algorithm shows an inline error; scan does not start.

---

## Group 3 — Tech Fingerprinter (manual)

- [x] Tech Fingerprinter page loads from the sidebar without errors.
- [x] URL input field and Scan button are present; disclaimer banner is visible.
- [x] Scanning `https://wordpress.org` returns at least one result with Technology = `WordPress`.
- [x] Scanning `https://nginx.org` returns at least one result indicating Nginx.
- [x] Scanning `https://example.com` completes without crashing (may return zero results — that is valid).
- [x] Scanning an unreachable URL (e.g. `http://192.0.2.1`) shows a clear error message in the status bar; does not crash.
- [x] Treeview shows three columns: Category, Technology, Evidence.
- [x] Clicking Stop during a scan (if still running) halts cleanly.
- [x] TXT export produces a readable file listing all found technologies.
- [x] `app/data/fingerprints.py` contains ≥ 30 distinct signatures across at least 4 categories.

---

## Group 4 — Integration

- [x] All three new modules appear in the sidebar navigation and are reachable by clicking.
- [x] All three new module cards on the home page show `Active` (not `Coming Soon`).
- [x] Switching between all existing and new modules produces no errors or UI corruption.
- [x] `roadmap.md` v2.0 module rows are marked ✅ Done.
- [x] `CHANGELOG.md` contains a v2.0 entry describing all three modules.
- [x] Spec files (`requirements.md`, `plan.md`, `validation.md`) are committed on the feature branch.
