# v4.0 — UI Category Grouping: Validation

## Group 1 — Category Registry

- [ ] `app/data/categories.py` exists and exports an ordered list of categories.
- [ ] All 15 existing tool page-keys are present exactly once across all categories.
- [ ] No tool is assigned to more than one category.

## Group 2 — Collapsible Sidebar Groups

- [ ] Sidebar shows 7 category header rows instead of a flat tool list.
- [ ] Each header displays an arrow indicator (`▶` when collapsed, `▼` when expanded).
- [ ] Clicking a collapsed header expands it and shows its tool nav items.
- [ ] Clicking an expanded header collapses it and hides its tool nav items.
- [ ] Collapsing a group does not destroy the widgets — re-expanding shows them instantly with no flicker.
- [ ] On app launch, all groups are collapsed except the one containing the active page.

## Group 3 — Auto-Expand on Navigation

- [ ] Clicking a tool nav item in any category expands that category and collapses all others.
- [ ] Clicking a home page card navigates to the tool and auto-expands its sidebar category.
- [ ] "Send to Credential Tester" (from Wordlist Generator) navigates correctly and auto-expands Auth & Exploitation.
- [ ] The active nav item highlight still appears correctly inside expanded groups.

## Group 4 — Home Page Category Sections

- [ ] Home page shows 7 labelled section headings, one per category.
- [ ] Each section heading appears above the correct set of tool cards.
- [ ] All 15 tool cards are present under their correct category section.
- [ ] Cards for unimplemented tools (Coming Soon) remain greyed out and non-clickable.
- [ ] Hover highlight and click-to-navigate still work on all active tool cards.
- [ ] Section headings scroll with the card grid inside the AutoHideScrollFrame.

## Group 5 — Polish & Regression

- [ ] Category header rows are visually distinct from tool nav items (different background, uppercase label).
- [ ] Mousewheel scrolling works over the sidebar regardless of which groups are expanded or collapsed.
- [ ] Sidebar scrollbar appears when enough groups are expanded to overflow the nav area, and hides when content fits.
- [ ] All 15 tools open their pages without error after the refactor.
- [ ] No TclError or traceback appears in the terminal during normal use or on app close.
- [ ] `roadmap.md` v4.0 is marked ✅ Complete.

## Documentation

- [ ] `CHANGELOG.md` updated with a v4.0 entry.
- [ ] Spec files committed on the feature branch.
- [ ] Branch merged to `main` via `--no-ff`.
