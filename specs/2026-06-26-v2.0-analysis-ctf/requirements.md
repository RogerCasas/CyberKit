# v2.0 — Analysis & CTF Utilities: Requirements

## Problem Statement

v2.0 rounds out CyberKit's utility belt with three modules that CTF players and learners reach for constantly but currently have to scatter across browser tabs and CLI tools:

- **Encoder / Decoder** — CTF challenges routinely involve encoding chains (Base64, URL, hex, ROT-13, HTML entities, JWT). Having all formats in one bidirectional pane removes constant context-switching.
- **Hash Identifier & Cracker** — Recognising a hash type from its format, then attempting a dictionary attack, is a core CTF and real-world credential-analysis skill. Python's `hashlib` stdlib makes this entirely self-contained.
- **Tech Fingerprinter** — Knowing what software a target runs is the entry point for targeted research. A header + HTML signature scan teaches how passive fingerprinting works without touching a single exploit.

---

## In Scope

### Encoder / Decoder
- **URL** — `urllib.parse.quote` / `unquote` (full and component modes)
- **Base64** — standard and URL-safe variants; encode and decode
- **HTML entities** — `html.escape` / `html.unescape`
- **Hex** — `bytes.hex()` / `bytes.fromhex()` (UTF-8 input/output)
- **ROT-13** — `codecs.encode(s, 'rot_13')`
- **JWT inspect** — split on `.`, base64url-decode header and payload, display as formatted JSON; no signature verification, no manipulation

Single two-panel layout (input / output) with an operation selector. A **Swap** button copies output → input for chaining operations. A **Clear** button resets both panels.

### Hash Identifier & Cracker
- **Identification** — pattern-match by length + character set for: MD5 (32 hex), SHA-1 (40 hex), SHA-256 (64 hex), SHA-512 (128 hex), NTLM (32 hex, NT-hash prefix pattern), bcrypt (`$2a$`/`$2b$` prefix), MySQL4 (16 hex), MySQL5 (40 hex with `*` prefix), LM (`$LM$` pattern)
- **Cracking** — dictionary attack via `hashlib`; supported algorithms: MD5, SHA-1, SHA-256, SHA-512; bundled wordlist (common passwords, ~200 entries) or custom `.txt` file; live progress in Treeview; Stop signal; displays cracked value or "Not found"
- Two-tab UI: **Identify** (paste hash → get ranked candidates) and **Crack** (paste hash + select algorithm + wordlist → run attack)

### Tech Fingerprinter
- Single-URL HTTP GET using `requests` with browser UA (ADR-003)
- Signature matching against response headers, HTML `<meta>` tags, cookie names, and body keywords
- Internal signature database (`app/data/fingerprints.py`): ≥ 30 signatures covering CMS, server software, frameworks, CDN/security products
- Results Treeview with columns: **Category**, **Technology**, **Evidence** (which header/tag triggered the match)
- Disclaimer banner (same pattern as other modules)
- TXT export of findings

---

## Out of Scope

- JWT signature verification, JWT forgery, or alg:none attacks
- GPU-accelerated or rainbow-table hash cracking
- Salted/bcrypt cracking (bcrypt is identification-only)
- CMS version detection (presence only, not version number)
- Active port scanning or JavaScript execution within the Fingerprinter
- Settings persistence or cross-session state

---

## Key Decisions & Constraints

| Constraint | Detail |
|---|---|
| **No new dependencies for Encoder/Decoder or Hash** | `urllib.parse`, `base64`, `html`, `codecs`, `hashlib`, `json` — all stdlib. `requirements.txt` unchanged for these two. |
| **Fingerprinter uses `requests`** | Already in `requirements.txt`; no new package needed. |
| **No C extensions, no admin/root** | Consistent with existing ADRs. |
| **Thread-safety rule** | All network/computation engines run in a background thread; results passed via `queue.Queue`; no Tk widget touched from worker thread (hard constraint). |
| **Encoder/Decoder is synchronous** | Operations are instant; no thread needed; direct call on button click. |
| **Hash cracker uses a thread** | Dictionary attack can be slow on large wordlists; same queue-based pattern as other scan engines. |
| **Signature database is internal** | Stored as a Python dict in `app/data/fingerprints.py`; no external file, no network fetch. Easy for students to read and extend. |

---

## Implementation Order

Encoder / Decoder → Hash Identifier & Cracker → Tech Fingerprinter

(Simplest/offline first; each module is independently shippable.)

---

## Open Questions

None — all decisions made during the spec interview.
