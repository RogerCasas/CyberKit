# v3.2 — Password & Network Tools: Requirements

## Problem Statement

Two capability gaps remain after v3.1:

1. **Wordlist supply chain** — the Credential Tester and Hash Cracker both accept external wordlists, but creating quality, targeted lists still requires external tools (crunch, CeWL). Students on lab machines often lack these. A built-in generator lets CyberKit produce its own input without any extra dependency.

2. **Local network visibility** — all existing modules work against explicit IP/hostname targets. There is no way to discover what hosts exist on the local subnet. An ARP Scanner fills this gap and teaches layer-2 concepts (MAC addresses, OUI vendor lookup) that are not covered anywhere else in the tool.

## In Scope

### Password / Wordlist Generator
- **Brute-force tab** — user picks character sets (lowercase, uppercase, digits, symbols), sets min and max length; generator yields every combination in order.
- **Mutation tab** — user enters one or more seed phrases (one per line); generator applies a configurable rule set: leet-speak substitutions (a→@, e→3, i→1, o→0, s→$), capitalisation variants (all-lower, all-upper, title-case), numeric suffixes (1–99 or user-defined), and a custom prefix/suffix field.
- **Live preview panel** — updates in real time as options are adjusted; shows the first 20 generated entries so the user can verify the configuration before committing to a full run.
- **Generate & export** — writes the full wordlist to a `.txt` file via a Save dialog. A progress label shows entry count while generating.
- **Size guard** — generation is capped at 1,000,000 entries; if the computed space exceeds this the UI shows a warning and disables the Generate button until the configuration is narrowed.
- **Integration hook** — a "Send to Credential Tester" button copies the wordlist path into the Credential Tester's username or password browse field (whichever is appropriate based on which tab was last used).

### ARP Scanner
- **Input** — user supplies a subnet in CIDR notation (e.g. `192.168.1.0/24`) or leaves it blank to auto-detect the default interface subnet.
- **Scan** — broadcasts ARP requests via Scapy; collects IP, MAC address, and hostname (reverse DNS best-effort) for each responding host.
- **Vendor OUI lookup** — resolved from a bundled OUI table (not online API) to keep it fast and offline-capable. Table derived from the IEEE public OUI registry, trimmed to the top ~5,000 vendors.
- **Live results** — Treeview updates as replies arrive; columns: #, IP, MAC, Vendor, Hostname.
- **Privilege check** — on launch of a scan, detect whether the process has admin/root; if not, show a clear error message with instructions rather than crashing.
- **Export** — CSV and TXT, consistent with other modules.

## Out of Scope
- Saving generator presets to disk.
- Rule-based wordlist chaining (applying mutation on top of brute-force output).
- Active host enumeration via ICMP ping (ARP Scanner only does ARP).
- Online OUI lookups or automatic OUI database updates.
- Password strength scoring or entropy display.
- Passive network sniffing or packet capture.

## Key Decisions & Constraints

| Decision | Rationale |
|---|---|
| Scapy for ARP | Only library that allows raw layer-2 packet crafting without a system ARP binary; already on the roadmap and in `tech-stack.md`. |
| Bundled OUI table | Keeps the scanner offline-capable; online APIs add latency and rate-limit risk. |
| Cap at 1 M entries | Prevents accidental multi-GB file writes on student machines. |
| Two-tab generator with live preview | Requested in spec interview; preview updates on every widget change using a generator that yields up to 20 items and then stops (no full computation on every keystroke). |
| No admin auto-elevation | The tool never calls UAC / sudo automatically; it instructs the user to re-run with elevated privileges. Consistent with the responsible-use mission value. |
| Brute-force uses `itertools.product` | stdlib, no dependencies, handles character-set cartesian products cleanly. |
| Mutation uses in-memory list | Seed phrases × rules is typically small (< 10,000 entries); no streaming needed until the live-preview cap. |

## Open Questions
- None after the spec interview.
