# v4.0 — UI Category Grouping: Requirements

## Problem Statement

CyberKit currently has 15 tools listed in a flat sidebar and an unsectioned home-page card grid. With 13 more tools planned across v4.1–v4.5, a flat list will become unusable — users will need to scroll through 28+ items to find a tool. Category grouping solves this by organising tools into labelled, collapsible sections so unrelated categories stay out of the way.

## In Scope

- **Collapsible sidebar category groups**: replace the flat nav list with named accordion groups. Each group header is a clickable row that toggles visibility of its child nav items via `grid()` / `grid_remove()`.
- **Home page category sections**: the card grid is reorganised into labelled sections matching the sidebar categories. A section heading appears above each group of cards.
- **Seven categories** applied retroactively to all 15 existing tools (see table below).
- **Session-only state**: expanded/collapsed state lives in a `dict[str, bool]` on `Sidebar`; it resets to default on app restart.
- **Default state**: all groups collapsed except the one containing the active page.
- **Auto-expand on navigation**: when the user navigates to a tool, its category group auto-expands.

### Category → Tool Mapping

| Category | Tools |
|---|---|
| Web / Active Testing | Dir Fuzzer, Header Analyser, HTTP Builder, SQLi Tester |
| Network / Recon | Port Scanner, ARP Scanner |
| Auth & Exploitation | Credential Tester |
| DNS & OSINT | DNS Enumerator, WHOIS & Geo |
| Cryptanalysis & Encoding | Hash Tool, Encoder / Decoder |
| Tech Analysis | Tech Fingerprinter, SSL Analyser |
| Wordlist & Utilities | Wordlist Generator |

## Out of Scope

- Persistent state across app restarts (config file, registry, etc.).
- Drag-to-reorder categories or tools.
- Search/filter within the sidebar.
- Any new tools (v4.1+ modules are not touched).
- Changes to individual tool pages.

## Key Decisions & Constraints

- **`grid_remove()` / `grid()`** toggle (ADR-005): avoids destroying/recreating widgets on collapse, preserving widget state and keeping toggle fast. Nav item widgets are created once at startup.
- **No new dependencies**: implementation uses only existing CTk and tkinter primitives.
- **AutoHideScrollFrame** (`app/ui/scrollable.py`) already wraps the sidebar nav area — category groups are placed inside `self._nav_scroll.inner`, inheriting scroll behaviour for free.
- **Thread safety**: all UI mutations happen on the main thread; no worker threads involved in this phase.
- **Home page** (`app/ui/pages/home.py`): cards are currently laid out in a uniform grid. Category sections replace this with sequential `CTkLabel` headings + per-section sub-grids.
- Existing `Active` / `Coming Soon` card badges are preserved.

## Open Questions

None — all scope decisions made in the interview.
