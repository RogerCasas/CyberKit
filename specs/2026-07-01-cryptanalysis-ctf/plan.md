# v4.3 — Cryptanalysis & CTF Utilities: Implementation Plan

Reference: `docs/roadmap.md`, `docs/tech-stack.md`
Branch: `phase-11-v4.3-cryptanalysis-ctf`

---

## Group 1 — JWT Engine (`app/modules/jwt_tool.py`)

**1.1** Define dataclasses:
- `JwtParts(header_b64, payload_b64, signature_b64, header, payload)` — raw
  segments plus decoded dicts.
- `BruteResult(found, secret, attempts, elapsed_s)` — outcome of a brute-force
  run.

**1.2** Implement `decode(token: str) -> JwtParts`:
- Split on `.`; base64url-decode each segment (pad to 4-byte boundary).
- Return `JwtParts`; raise `ValueError` with a descriptive message on any
  parsing failure (wrong segment count, invalid JSON, etc.).

**1.3** Implement `forge_none_alg(token: str) -> str`:
- Decode the header dict; set `"alg"` to `"none"`; re-encode header with
  base64url (no padding).
- Concatenate `<new_header>.<original_payload>.` (empty signature).
- Return the forged token string.

**1.4** Implement `verify_hs256(token: str, secret: str) -> bool`:
- Re-compute `HMAC-SHA256(header.payload, secret.encode())` and compare to the
  decoded signature bytes with `hmac.compare_digest`.

**1.5** Implement `brute_force(token, wordlist_path, stop_event, on_try)`:
- Open the wordlist file line-by-line (streaming — do not load into memory).
- For each candidate call `verify_hs256`; if it matches, call
  `on_try(BruteResult(found=True, ...))` and return.
- Call `on_try` with incremental attempt counts every 500 tries for live
  progress.
- Respect `stop_event.is_set()` between lines.
- Return `BruteResult(found=False, ...)` if the wordlist is exhausted.

---

## Group 2 — JWT Tests (`tests/test_jwt_tool.py`)

**2.1** `test_decode_valid_hs256` — decode a known HS256 JWT; assert header
`alg == "HS256"` and payload fields match.

**2.2** `test_decode_malformed` — pass a string that is not a valid JWT;
assert `ValueError` is raised.

**2.3** `test_forge_none_alg` — forge a token; assert the resulting token has
three segments, middle segment unchanged, header has `"alg": "none"`, and
third segment is empty.

**2.4** `test_verify_hs256_correct` — sign a token manually with `hmac`; assert
`verify_hs256` returns `True`.

**2.5** `test_verify_hs256_wrong_secret` — assert `verify_hs256` returns `False`
for an incorrect secret.

**2.6** `test_brute_force_finds_secret` — write a tiny temp wordlist containing
the correct secret; assert `BruteResult.found == True` and `secret` matches.

**2.7** `test_brute_force_stop_event` — set `stop_event` before calling;
assert the function returns immediately with `found == False`.

---

## Group 3 — JWT UI Page (`app/ui/pages/jwt_tool.py`)

**3.1** Build `JwtToolPage(ctk.CTkFrame)`:
- Header: "🔑  JWT Forge & Verify", subtitle.
- Token input: multi-line `CTkTextbox` (paste area) + "Decode" button.

**3.2** Decoded view section (appears after Decode):
- Two read-only `CTkTextbox` side-by-side (or stacked): Header JSON, Payload
  JSON — syntax-highlighted with monospace font, non-editable.
- Key fields (alg, exp, iat, sub) surfaced as labelled rows above the raw JSON.

**3.3** Attack section — two sub-panels:

*Panel A — alg:none bypass:*
- "Forge alg:none Token" button.
- Read-only `CTkEntry` or `CTkTextbox` showing the forged token.
- Copy-to-clipboard button.

*Panel B — HS256 brute-force:*
- File-picker button for wordlist (uses `tkinter.filedialog.askopenfilename`).
- Selected file path label.
- Start / Stop buttons.
- Status label showing attempts/s and current candidate.
- Result label: secret found (green) or exhausted (muted).

**3.4** Wire background thread: `threading.Thread(target=brute_force, ...)`;
queue for `BruteResult` updates; `widget.after(100, _poll)` drains the queue.

---

## Group 4 — Cipher Engine (`app/modules/cipher_solver.py`)

**4.1** Define dataclasses:
- `CipherCandidate(cipher, confidence, key, plaintext)` — single ranked result.

**4.2** Implement analysis helpers:
- `_index_of_coincidence(text) -> float` — IC of a string (letters only).
- `_letter_freq(text) -> dict[str, float]` — normalised frequency map.
- `_chi_squared(observed, expected) -> float` — goodness-of-fit vs. English.

**4.3** Implement Caesar analysis & solve:
- `_analyse_caesar(text) -> CipherCandidate` — try all 26 shifts; pick the
  shift with lowest chi-squared vs. English letter frequencies; confidence =
  `1 - normalised_chi`.
- `solve_caesar(text, shift: int) -> str`.

**4.4** Implement Vigenère analysis & solve:
- `_estimate_key_length(text, max_len=20) -> int` — Kasiski examination or
  IC-based key-length search.
- `_analyse_vigenere(text) -> CipherCandidate` — estimate key length, then
  frequency-analyse each column independently.
- `solve_vigenere(text, key: str) -> str`.

**4.5** Implement XOR analysis & solve:
- `_analyse_xor(text) -> CipherCandidate` — single-byte XOR: try all 256
  byte values; pick the one that gives the highest printable-ASCII ratio in the
  decoded output; report key as hex string.
- `solve_xor(text, key_hex: str) -> str` — multi-byte XOR (key repeats).

**4.6** Implement Rail Fence analysis & solve:
- `solve_railfence(text, rails: int) -> str` — reconstruct rail-fence grid.
- `_analyse_railfence(text) -> CipherCandidate` — try rails 2–10; score each
  candidate by printable-ASCII ratio; pick the best.

**4.7** Implement top-level `identify(ciphertext: str) -> list[CipherCandidate]`:
- Strip non-ASCII, normalise whitespace.
- Run all four analysers.
- Sort by `confidence` descending.
- Return ranked list.

---

## Group 5 — Cipher Tests (`tests/test_cipher_solver.py`)

**5.1** `test_caesar_roundtrip` — encrypt with shift 13; solve; assert plaintext
matches original.

**5.2** `test_caesar_identify_top` — `identify()` on a Caesar ciphertext; assert
first candidate is Caesar.

**5.3** `test_vigenere_roundtrip` — encrypt a paragraph with key "KEY"; solve
with correct key; assert match.

**5.4** `test_vigenere_identify_top` — `identify()` on a Vigenère ciphertext;
assert first or second candidate is Vigenère.

**5.5** `test_xor_roundtrip_single_byte` — XOR with `0x42`; solve; assert
plaintext matches.

**5.6** `test_xor_solve_multibyte` — XOR with a 3-byte key; `solve_xor` with
correct hex key; assert match.

**5.7** `test_railfence_roundtrip` — encrypt with 3 rails; solve; assert match.

**5.8** `test_identify_returns_list` — `identify()` always returns a non-empty
list regardless of input; no exception raised on empty input.

---

## Group 6 — Cipher UI Page (`app/ui/pages/cipher_solver.py`)

**6.1** Build `CipherSolverPage(ctk.CTkFrame)`:
- Header: "🔐  Cipher Identifier & Solver", subtitle.
- Input: `CTkTextbox` (multi-line paste) + "Identify" button.

**6.2** Candidates panel (appears after Identify):
- `ttk.Treeview` with columns: Rank, Cipher, Confidence %, Auto-Key.
- Each row is clickable; selecting a row populates the key field and triggers a
  solve.

**6.3** Solve panel:
- Cipher label (read-only, shows selected algorithm).
- Key entry (pre-filled from analysis; user-editable).
- "Solve" button (re-runs solve when user edits key manually).
- Plaintext output: read-only `CTkTextbox`.

**6.4** Identification runs synchronously (fast enough; no thread needed).
Solve also runs synchronously on button click or row selection.

---

## Group 7 — Wiring, Categories & Version

**7.1** `app/data/categories.py` — add `ToolEntry("JWT Forge & Verify", "🔑", "jwt_tool")` and
`ToolEntry("Cipher Identifier", "🔐", "cipher_solver")` to the
`"cryptanalysis"` category.

**7.2** `app/ui/app_window.py` — import `JwtToolPage`, `CipherSolverPage`; add
two `_add_page()` calls.

**7.3** `app/ui/pages/home.py` — add card entries for both tools with
`"tag": "Active", "tag_color": "#22c55e"`.

**7.4** `app/ui/sidebar.py` — bump version label `v4.2.0` → `v4.3.0` (both
occurrences, `replace_all=True`).

**7.5** `docs/roadmap.md` — change `## v4.3 — Cryptanalysis & CTF Utilities`
heading to `## v4.3 — Cryptanalysis & CTF Utilities ✅ Complete`; add Status
column to the module table.
