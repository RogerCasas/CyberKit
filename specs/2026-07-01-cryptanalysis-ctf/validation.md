# v4.3 — Cryptanalysis & CTF Utilities: Validation Checklist

---

## Group 1 & 2 — JWT Engine & Tests

- [ ] `decode()` correctly parses a standard HS256 JWT and returns `header["alg"] == "HS256"` plus the expected payload fields.
- [ ] `decode()` raises `ValueError` (not an unhandled exception) for a malformed token (wrong segment count, invalid base64, non-JSON body).
- [ ] `forge_none_alg()` produces a token with exactly three `.`-separated segments; the middle segment is identical to the original payload segment; the header decodes to `{"alg": "none", ...}`; the third segment is an empty string.
- [ ] `verify_hs256()` returns `True` when the correct secret is supplied.
- [ ] `verify_hs256()` returns `False` when an incorrect secret is supplied.
- [ ] `brute_force()` returns `BruteResult(found=True)` with the correct secret when the secret appears in the wordlist.
- [ ] `brute_force()` returns `BruteResult(found=False)` when the wordlist is exhausted without a match.
- [ ] `brute_force()` terminates promptly (within one iteration) when `stop_event` is set before the call.
- [ ] `python tests/test_jwt_tool.py` exits with code 0 and all tests pass.

---

## Group 3 — JWT UI Page

- [ ] Pasting a valid JWT and clicking "Decode" shows formatted JSON in the Header and Payload panels without error.
- [ ] Key fields (alg, exp, iat) are surfaced clearly above the raw JSON.
- [ ] "Forge alg:none Token" produces a forged token in the output box; the token has an empty signature segment.
- [ ] Copy-to-clipboard copies the full forged token string.
- [ ] The wordlist file-picker opens a file-open dialog and shows the selected path.
- [ ] Clicking "Start" with a valid wordlist begins brute-force in the background; the status label updates with attempt counts while the UI remains responsive.
- [ ] Clicking "Stop" during brute-force halts the background thread within one second.
- [ ] When the secret is found, the result label turns green and shows the discovered secret.
- [ ] When the wordlist is exhausted without a match, the result label shows a clear "not found" message.
- [ ] Pasting an invalid token and clicking "Decode" shows an error message; no crash.

---

## Group 4 & 5 — Cipher Engine & Tests

- [ ] `solve_caesar(text, shift)` correctly decrypts a Caesar-shifted string for all shifts 0–25.
- [ ] `_analyse_caesar()` identifies the correct shift for a standard English-language Caesar ciphertext (≥50 characters).
- [ ] `solve_vigenere(text, key)` correctly decrypts a Vigenère-enciphered paragraph with the right keyword.
- [ ] `_analyse_vigenere()` returns the correct key (or a key that produces readable plaintext) for a typical CTF-length Vigenère ciphertext.
- [ ] `solve_xor(text, key_hex)` correctly decrypts single-byte XOR (`key_hex` = 2 hex chars).
- [ ] `solve_xor(text, key_hex)` correctly decrypts multi-byte XOR (`key_hex` = 4–6 hex chars, key repeats).
- [ ] `solve_railfence(text, rails)` correctly decrypts for rails 2, 3, and 4.
- [ ] `identify(ciphertext)` returns a non-empty list for any non-empty input without raising an exception.
- [ ] `identify()` returns Caesar as the top-ranked candidate for a standard Caesar ciphertext.
- [ ] `identify()` returns Vigenère as first or second candidate for a Vigenère ciphertext.
- [ ] `python tests/test_cipher_solver.py` exits with code 0 and all tests pass.

---

## Group 6 — Cipher UI Page

- [ ] Pasting ciphertext and clicking "Identify" populates the candidates Treeview with at least one row.
- [ ] Each row shows the cipher name, confidence percentage, and auto-derived key.
- [ ] Clicking a row fills the key entry and immediately shows the decrypted plaintext in the output textbox.
- [ ] Editing the key entry and clicking "Solve" re-runs the solve with the user-supplied key and updates the plaintext output.
- [ ] Submitting an empty ciphertext shows an error message; no crash.
- [ ] All four cipher algorithms (Caesar, Vigenère, XOR, Rail Fence) appear as candidates for appropriate inputs.

---

## Group 7 — Wiring & Integration

- [ ] "JWT Forge & Verify" appears in the sidebar under "Cryptanalysis & Encoding" and navigates to the correct page.
- [ ] "Cipher Identifier" appears in the sidebar under "Cryptanalysis & Encoding" and navigates to the correct page.
- [ ] Both tools appear on the Home page with an "Active" green tag.
- [ ] The sidebar version label shows `v4.3.0` (expanded and collapsed states).
- [ ] Navigating between all existing tools and the two new ones produces no errors or blank pages.

---

## Documentation

- [ ] Spec files (`requirements.md`, `plan.md`, `validation.md`) committed on the feature branch under `specs/2026-07-01-cryptanalysis-ctf/`.
- [ ] `docs/roadmap.md` updated: `## v4.3` heading shows `✅ Complete`; module table has Status column.
- [ ] `CHANGELOG.md` updated before merge to `main`.
