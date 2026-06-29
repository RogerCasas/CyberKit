# v4.0 — UI Category Grouping: Plan

## Group 1 — Define Category Registry

**Goal:** single source of truth for categories and their tool membership, consumed by both the sidebar and the home page.

- 1.1 Create `app/data/categories.py` with an ordered list of `Category` named-tuples: `(key: str, label: str, tools: list[str])`. The `tools` list holds page-key strings matching the keys used in `app_window.py`'s `_pages` dict.
- 1.2 Verify the mapping covers all 15 existing tool page-keys with no duplicates or omissions.

---

## Group 2 — Collapsible Sidebar Groups

**Goal:** sidebar nav area shows accordion-style category headers with toggleable tool rows.

- 2.1 In `app/ui/sidebar.py`, replace the current flat nav-item loop with a two-level loop: outer loop over categories, inner loop over tools in each category.
- 2.2 For each category, create a header row (`CTkFrame` + `CTkLabel` with arrow indicator `▶` / `▼`) gridded inside `self._nav_scroll.inner`.
- 2.3 For each tool within a category, create the nav item widget as before but grid it immediately after the header. Store a reference in a `dict[str, list[tk.Widget]]` keyed by category key.
- 2.4 Track expanded state in `self._expanded: dict[str, bool]` — all `False` by default.
- 2.5 Implement `_toggle_category(key)`: flip the bool, call `grid_remove()` / `grid()` on each tool widget in the group, update the arrow indicator label.
- 2.6 Implement `expand_category(key)`: expand the named group and collapse all others.
- 2.7 Wire header click (`<Button-1>`) to `_toggle_category`.
- 2.8 On app launch, call `expand_category` for the category containing the default active page (Home or the first tool).

---

## Group 3 — Auto-Expand on Navigation

**Goal:** navigating to any tool automatically expands its category in the sidebar.

- 3.1 Extend `Sidebar.set_active(page_key)` (or equivalent navigation callback) to look up which category `page_key` belongs to (reverse-lookup from `categories.py`) and call `expand_category` for that key.
- 3.2 Verify that navigating via the sidebar, home page cards, or any "Send to X" cross-navigation button all trigger the auto-expand.

---

## Group 4 — Home Page Category Sections

**Goal:** home page card grid is reorganised into labelled sections matching the sidebar categories.

- 4.1 In `app/ui/pages/home.py`, replace the single uniform card grid loop with a loop over `CATEGORIES` from `categories.py`.
- 4.2 For each category, render a section heading (`CTkLabel`, styled like the existing "AVAILABLE MODULES" label but smaller / secondary style) above the cards.
- 4.3 Render the category's cards in a sub-grid (same card widget as before, same hover/click behaviour via `_bind_tree`).
- 4.4 Preserve the `Coming Soon` greyed-out style and disabled click for unimplemented tools.
- 4.5 Ensure the section headings are part of the scrollable area (inside the `AutoHideScrollFrame` inner frame) so they scroll with the cards.

---

## Group 5 — Polish & Regression Check

- 5.1 Style the category header rows to be visually distinct from nav items: slightly lighter background, uppercase label, arrow indicator.
- 5.2 Confirm mousewheel scrolling still works over collapsed and expanded groups.
- 5.3 Confirm the sidebar scrollbar appears/hides correctly when enough categories are expanded to overflow.
- 5.4 Confirm all 15 tools are still reachable and their pages load without error.
- 5.5 Update `roadmap.md` to mark v4.0 ✅ Complete.
