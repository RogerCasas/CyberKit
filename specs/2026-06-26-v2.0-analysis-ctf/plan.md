# v2.0 — Analysis & CTF Utilities: Implementation Plan

Each group is independently testable before the next begins.

---

## Group 1 — Encoder / Decoder

**1.1** Create `app/ui/pages/encoder_decoder.py`.
- Two-panel layout: `CTkTextbox` input (left) and `CTkTextbox` output (right) separated by a centre column of action buttons.
- Operation selector: `CTkSegmentedButton` or `CTkOptionMenu` listing all modes (URL, Base64, Base64 URL-safe, HTML Entities, Hex, ROT-13, JWT Inspect).
- **Encode** and **Decode** buttons (JWT Inspect has only one action button — "Inspect").
- **Swap** button: copies output → input.
- **Clear** button: empties both panels.
- Inline error label below input for malformed input (e.g. invalid Base64 padding, invalid hex).

**1.2** Implement each operation as a pure function in `app/modules/encoder_decoder_ops.py` (no UI dependency — makes unit testing trivial):
- `url_encode(s)` / `url_decode(s)` — `urllib.parse.quote` / `unquote` with `safe=''`
- `base64_encode(s)` / `base64_decode(s)` — standard; raises `binascii.Error` on bad padding
- `base64url_encode(s)` / `base64url_decode(s)` — URL-safe variant
- `html_encode(s)` / `html_decode(s)` — `html.escape` / `html.unescape`
- `hex_encode(s)` / `hex_decode(s)` — UTF-8 encode to bytes, `.hex()` / `bytes.fromhex().decode('utf-8')`
- `rot13(s)` — `codecs.encode(s, 'rot_13')` (same function for encode and decode)
- `jwt_inspect(token)` — split on `.`, base64url-decode header and payload, return `(header_dict, payload_dict)`; raises `ValueError` if not exactly 3 parts or decode fails

**1.3** Wire UI buttons to ops functions; display results in output panel; show inline error on exception.

**1.4** Register page in `app/ui/app_window.py` and `app/ui/sidebar.py`; promote home card to `Active`.

**1.5** Write `tests/test_encoder_decoder.py` covering all operations (see validation.md for exact cases).

**Verify Group 1:** `python tests/test_encoder_decoder.py` passes; page navigates in the running app.

---

## Group 2 — Hash Identifier & Cracker

**2.1** Create `app/modules/hash_identifier.py`.
- Define a list of `HashPattern(name, regex, notes)` dataclass instances.
- Patterns (match by length + charset + optional prefix):
  - MD5: 32 hex chars
  - SHA-1: 40 hex chars
  - SHA-256: 64 hex chars
  - SHA-512: 128 hex chars
  - NTLM: 32 hex chars (differentiated from MD5 by context note)
  - MySQL4 (Old Password): 16 hex chars
  - MySQL5: `*` + 40 hex chars
  - bcrypt: starts with `$2a$`, `$2b$`, or `$2y$`
  - LM: 32 hex, split at pos 16 has equal halves pattern (note only — same length as MD5)
- `identify(hash_str) -> list[HashPattern]` — returns all matching patterns ordered by specificity.

**2.2** Create `app/modules/hash_cracker.py`.
- `HashCrackEngine(hash_str, algorithm, wordlist_iter, result_queue, stop_event)` class
- `run()` method: iterate wordlist, compute `hashlib.new(algorithm, word.encode()).hexdigest()`, put result in queue on match; put sentinel on completion/stop.
- Supported algorithms: `md5`, `sha1`, `sha256`, `sha512`.
- Raises `ValueError` on unsupported algorithm (checked before thread starts).

**2.3** Extend `app/data/wordlists.py` with `CRACK_WORDLIST` — ~200 most common passwords (rockyou top-200 subset).

**2.4** Create `app/ui/pages/hash_tool.py`.
- Two-tab `CTkSegmentedButton` or `CTkTabview`: **Identify** and **Crack**.
- **Identify tab**: `CTkTextbox` for hash input; **Identify** button; results in a `CTkScrollableFrame` or Treeview listing candidate algorithm names and notes.
- **Crack tab**: hash input, algorithm `CTkOptionMenu` (MD5/SHA-1/SHA-256/SHA-512), wordlist toggle (Bundled / Custom with Browse), Start/Stop buttons, live status label, result panel showing cracked value or final "Not found".

**2.5** Register page in `app_window.py` and `sidebar.py`; promote home card to `Active`.

**2.6** Write `tests/test_hash_tool.py` covering identifier and cracker (see validation.md).

**Verify Group 2:** `python tests/test_hash_tool.py` passes; both tabs work in the running app.

---

## Group 3 — Tech Fingerprinter

**3.1** Create `app/data/fingerprints.py`.
- A list of `Fingerprint(name, category, checks)` where `checks` is a dict with optional keys:
  - `headers`: `{header_name: regex_or_substring}`
  - `html`: list of substrings to search in response body
  - `cookies`: list of cookie name substrings
  - `meta`: list of `<meta>` content substrings
- Minimum 30 signatures across these categories:
  - **CMS**: WordPress, Drupal, Joomla, Magento, Shopify, Ghost, Wix, Squarespace
  - **Server**: Apache, Nginx, IIS, LiteSpeed, Caddy
  - **Framework**: Laravel, Django, Flask, Rails, Express, ASP.NET, Spring
  - **Frontend**: React, Angular, Vue, jQuery, Bootstrap
  - **CDN / Security**: Cloudflare, Akamai, Fastly, Imperva
  - **Platform / Language**: PHP, Node.js, Python, Java / Tomcat

**3.2** Create `app/modules/tech_fingerprinter.py`.
- `TechFingerprintEngine(url, result_queue, stop_event)` class.
- `run()`: fetch URL with `requests` + browser UA, iterate fingerprints, emit matches as `FingerprintResult(category, name, evidence)` namedtuple via queue, emit sentinel on completion.
- Single HTTP GET (no crawling); 10 s timeout; catches `requests.RequestException` → error result.

**3.3** Create `app/ui/pages/tech_fingerprinter.py`.
- URL input row (same pattern as Header Analyser).
- Inline error label at row=0, col=1.
- Disclaimer banner.
- Start / Stop buttons.
- `ttk.Treeview` with columns: `#`, `Category`, `Technology`, `Evidence`.
- Status bar (same `_set_status` pattern as other pages).
- TXT export button.

**3.4** Register page in `app_window.py` and `sidebar.py`; promote home card to `Active`.

**Verify Group 3:** manual scan of `https://wordpress.org` returns WordPress in results.

---

## Group 4 — Integration & Documentation

**4.1** Confirm all three modules appear in the sidebar in order: Home, Dir Fuzzer, Port Scanner, Header Analyser, Cred Tester, DNS Enumerator, Encoder/Decoder, Hash Tool, Tech Fingerprinter.

**4.2** Confirm all three new home-page cards show `Active`.

**4.3** Mark v2.0 module rows `✅ Done` in `roadmap.md`.

**4.4** Run `/changelog` to update `CHANGELOG.md`.

**4.5** Commit, merge to main, delete feature branch.
