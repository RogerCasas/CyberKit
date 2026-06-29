# v4.1 — Web Attack Expansion — Validation

Acceptance criteria. Each item is independently pass/fail. Automated items run
via `pytest`; manual items use public practice targets (e.g.
`testphp.vulnweb.com`, PortSwigger Web Security Academy labs) and are
network-dependent.

## Group 1 — Shared injection helper

- [x] `app/modules/web_injection.py` exposes `parse_params` and `inject`.
- [x] `inject` (GET) mutates only the target parameter and preserves all others.
- [x] `inject` (POST) returns the payload in the body with an empty query string.
- [x] `parse_params` returns `[]` for a URL with no query string.
- [x] `sqli_tester.py` imports from `web_injection` and no longer defines its own
      `_inject` / `_parse_params`.
- [x] All existing `tests/test_sqli_tester.py` tests still pass (18/18).
- [x] `tests/test_web_injection.py` passes (6/6).

## Group 2 — XSS Tester engine

- [x] Raw, unescaped reflection of the marker → `is_vulnerable=True`.
- [x] HTML-entity-encoded reflection only → `is_vulnerable=False, encoded=True`.
- [x] Marker absent from response → not reflected, not vulnerable.
- [x] Context detection returns `html` / `attribute` / `script` correctly for
      each placement.
- [x] `stop_event` halts the scan mid-run.
- [x] `tests/test_xss_tester.py` passes (11/11).

## Group 3 — Open Redirect Detector engine

- [x] `302` with `Location` host = sentinel → `is_vulnerable=True`.
- [x] `302` with same-origin `Location` → not vulnerable.
- [x] `200` (no redirect) → not vulnerable.
- [x] Scheme-relative `//sentinel` and backslash `/\sentinel` both flagged.
- [x] Suffix-bypass host (`target.com.sentinel`) flagged.
- [x] `scan` calls `send` with `follow_redirects=False`.
- [x] `tests/test_open_redirect.py` passes (13/13).

## Group 4 — CSRF Analyser engine

- [x] Missing `SameSite` attribute → `warn` finding.
- [x] `SameSite=None` without `Secure` → `high` finding.
- [x] `SameSite=Strict` → `ok` finding.
- [x] Form containing a hidden anti-CSRF token field → `ok` finding.
- [x] Form with no token field → `warn` finding.
- [x] Multiple `Set-Cookie` headers are each evaluated.
- [x] `tests/test_csrf_analyser.py` passes (11/11).

## Group 5 — UI pages

- [x] XSS Tester page: URL + method + optional params, disclaimer banner, live
      results table. *(CSV/TXT export not added — pages mirror the SQLi Tester,
      which also has no export; can be added in a follow-up if desired.)*
- [x] Open Redirect page: same shell; Status/Location columns populate.
- [x] CSRF Analyser page: single-URL input, findings table with severity colour
      coding.
- [x] No spurious mid-page scrollbar on any of the three pages at default and
      minimum window sizes; Treeview scrollbar auto-hides when not needed
      (verified via geometry smoke-test: `vsb_shown=False`, `yview_last=1.0`).
- [x] Each page runs its scan on a background thread — the UI never freezes, and
      Stop (where present) aborts cleanly.

## Group 6 — Integration

- [x] All three tools appear under **Web / Active Testing** in the sidebar
      accordion and navigate correctly.
- [x] All three home-page cards show as **Active** and open the right page.
- [x] Sidebar version label reads **v4.1.0**.
- [ ] Manual: XSS Tester flags a reflected parameter on a known-vulnerable public
      target and does **not** flag an encoded/safe one. *(network-dependent)*
- [ ] Manual: Open Redirect Detector flags a known open-redirect parameter on a
      public practice target. *(network-dependent)*
- [ ] Manual: CSRF Analyser reports sensible findings against a real login form.
      *(network-dependent)*

## Group 7 — Documentation

- [x] `roadmap.md` marks v4.1 ✅ Complete.
- [ ] `CHANGELOG.md` has a v4.1 entry. *(added at commit time via `/sdd-changelog`)*
- [x] Spec files (`requirements.md`, `plan.md`, `validation.md`) committed with
      the validation checklist filled in.

> **Note on scope:** A CSV/TXT export control was specified in the plan for the
> XSS and Open Redirect pages but deferred — the existing SQLi Tester page (the
> template these follow) has no export either, so adding it is tracked as a small
> consistency follow-up rather than a v4.1 blocker.
