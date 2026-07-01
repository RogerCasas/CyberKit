# v4.3 — Cryptanalysis & CTF Utilities: Requirements

## Problem Statement

CTF competitions and real-world security assessments routinely involve two
categories of cryptographic challenge that CyberKit does not yet cover:

1. **JWT attacks** — JSON Web Tokens are used in nearly every modern API.
   The `alg:none` bypass and weak-secret brute-force are among the first
   attacks any security student encounters. The existing Encoder/Decoder
   module can base64-decode a JWT but offers no attack surface.

2. **Classical ciphers** — Caesar, Vigenère, XOR, and Rail Fence appear in
   virtually every beginner and intermediate CTF. Identifying the cipher from
   ciphertext alone (without being told the algorithm) is the core skill;
   current CyberKit has no tool for this.

v4.3 adds dedicated modules for both, keeping everything in the
"Cryptanalysis & Encoding" sidebar category alongside the existing Hash Tool
and Encoder/Decoder.

---

## In Scope

### JWT Forge & Verify
- **Decode**: parse any JWT (header + payload) and display formatted JSON; show
  algorithm, expiry, issued-at, and any custom claims.
- **`alg:none` bypass**: strip the signature and replace `"alg"` with `"none"`;
  produce a forged token the user can copy to clipboard and test on a server.
- **HS256 secret brute-force**: test each line of a user-supplied wordlist as the
  HMAC-SHA256 signing key; run in a background thread with live progress and a
  Stop button; report the secret if found.

### Cipher Identifier & Solver
- **Identify**: run index-of-coincidence, letter-frequency, and bigram analysis
  on the ciphertext to rank candidate algorithms (Caesar, Vigenère, XOR,
  Rail Fence) by confidence score.
- **Solve** each of the four algorithms:
  - **Caesar** — key = shift integer (0–25); frequency analysis for auto-key.
  - **Vigenère** — key = keyword string; Kasiski/IC for key length estimation,
    frequency analysis per column for key recovery.
  - **XOR** — key = one or more hex bytes; single-byte and short multi-byte XOR.
  - **Rail Fence** — key = number of rails (2–10).
- **One-click solve**: clicking a candidate from the ranked list fills the key
  field and shows the decrypted plaintext immediately.
- **Manual override**: the key field is always editable so the user can correct
  the auto-derived key.

---

## Out of Scope

- RS256, ES256, PS256 JWT attacks (require asymmetric key material not available
  to a brute-force attacker; out of scope for a learning tool).
- JWT signature verification against a known public key.
- Polyalphabetic ciphers beyond Vigenère (Beaufort, Playfair, Enigma, etc.).
- Modern symmetric/asymmetric ciphers (AES, RSA, DES, ChaCha20).
- Automated online lookups or rainbow-table APIs.
- Storing or persisting analysed tokens or plaintexts between sessions.

---

## Key Decisions & Constraints

| Decision | Rationale |
|---|---|
| **Stdlib only** (`base64`, `hmac`, `hashlib`, `string`, `collections`, `itertools`) | Avoids adding PyJWT or any crypto library. Consistent with the no-extra-deps policy in `tech-stack.md`. |
| **Background thread + queue + poll** for JWT brute-force | Wordlists can be large; a blocking call would freeze the UI. Matches the pattern used by Hash Cracker, Credential Tester, and every other long-running engine. |
| **No background thread for cipher identification** | Analysis of a paste is fast (<100 ms for any realistic ciphertext); blocking is acceptable and avoids complexity. |
| **Cipher engine is pure Python** | No numpy, no scipy. Index-of-coincidence and frequency analysis are straightforward to implement from first principles. |
| **Engine files in `app/modules/`** | Matches every prior module. One file per tool: `jwt_tool.py`, `cipher_solver.py`. |
| **UI pages in `app/ui/pages/`** | `jwt_tool.py`, `cipher_solver.py`. |
| **Category: Cryptanalysis & Encoding** | Both tools already listed under this category in `docs/roadmap.md` and `app/data/categories.py`. |
| **No admin privileges required** | Pure computation; no network sockets, no raw packets. |

---

## Open Questions

None — all scoping decisions resolved during the spec interview.
