# v4.1 — Web Attack Expansion — Plan

Build order is bottom-up: shared helper first (with SQLi refactor proving it),
then the three engines (each with tests), then the three UI pages, then wiring.
Each group is independently verifiable before the next begins.

---

## Group 1 — Shared injection helper

1.1 Create `app/modules/web_injection.py` exposing:
   - `parse_params(url) -> list[str]` — query-string parameter names.
   - `inject(url, method, param, payload) -> dict{"url", "body"}` — returns the
     mutated URL (GET) or form body (POST), preserving other params.
   (Logic lifted verbatim from `sqli_tester._parse_params` / `_inject`.)

1.2 Refactor `app/modules/sqli_tester.py` to import `parse_params` / `inject`
   from `web_injection` and delete its private copies (keep behaviour identical).

1.3 Add `tests/test_web_injection.py`: GET injection mutates only the target
   param; POST injection moves params to body; multi-param preservation;
   blank-value handling; `parse_params` on URLs with/without a query string.

1.4 Run the existing `tests/test_sqli_tester.py` — all 15 must still pass
   (regression guard for the refactor).

---

## Group 2 — XSS Tester engine

2.1 Create `app/modules/xss_tester.py`:
   - `XSSResult` dataclass: `parameter, payload, reflected, encoded, context,
     is_vulnerable`.
   - `PAYLOADS` list with a `{MARKER}` placeholder (`<script>{MARKER}</script>`,
     `"><img src=x onerror={MARKER}>`, `<svg onload={MARKER}>`, attribute-breakout
     and JS-context variants).
   - `scan(url, method, params, timeout, progress_cb, result_cb, stop_event)` —
     for each param, inject each payload (marker = random token), fetch via
     `http_builder.send`, classify reflection.

2.2 Reflection classifier (`_classify_reflection(body, payload, marker)`):
   - raw payload substring present → `reflected=True, encoded=False,
     is_vulnerable=True`;
   - only HTML-entity-encoded form present → `reflected=True, encoded=True,
     is_vulnerable=False`;
   - marker absent → not reflected.
   - `_detect_context(body, marker)` → `"html" | "attribute" | "script" | "—"`.

2.3 Add `tests/test_xss_tester.py` (mocked `send`): raw reflection flagged
   vulnerable; encoded reflection flagged safe; non-reflection negative;
   context detection for each of html/attribute/script; stop_event aborts.

---

## Group 3 — Open Redirect Detector engine

3.1 Create `app/modules/open_redirect.py`:
   - `RedirectResult` dataclass: `parameter, payload, status_code, location,
     is_vulnerable`.
   - `SENTINEL = "cyberkit-redirect-test.example"` and `PAYLOADS`
     (`//{S}`, `https://{S}`, `http://{S}`, `/\{S}`, `\/{S}`, `https:{S}`, and a
     `target.com.{S}` suffix-bypass built per-target).
   - `scan(...)` — inject each payload per param, `send(..., follow_redirects=
     False)`, inspect `Location`.

3.2 `_is_external_redirect(location, sentinel) -> bool` — parse `Location`,
   normalise scheme-relative/backslash forms, return True when the resolved host
   equals or ends with the sentinel.

3.3 Add `tests/test_open_redirect.py` (mocked `send`): 302→sentinel Location
   flagged; 302→same-origin not flagged; 200 (no redirect) not flagged;
   scheme-relative `//sentinel` and backslash `/\sentinel` both flagged;
   suffix-bypass host flagged.

---

## Group 4 — CSRF Analyser engine

4.1 Create `app/modules/csrf_analyser.py`:
   - `CSRFFinding` dataclass: `check, detail, severity` (`ok|info|warn|high`),
     mirroring Header Analyser's finding shape.
   - `analyse(url, timeout) -> list[CSRFFinding]` — single GET, then:
     `_check_samesite(headers)` per `Set-Cookie`; `_check_token(body)` scans form
     HTML for hidden anti-CSRF inputs (name matches `csrf|token|_token|
     authenticity_token|xsrf`); `_check_origin(url, timeout)` resends a POST with
     a spoofed `Origin`/`Referer` and reports whether it appears accepted
     (informational).

4.2 Helpers pure and unit-testable: `_check_samesite`, `_check_token`,
   `_parse_set_cookie`.

4.3 Add `tests/test_csrf_analyser.py`: SameSite missing → warn; SameSite=None
   without Secure → high; SameSite=Strict → ok; form with hidden token → ok;
   form without token → warn; multiple Set-Cookie handled.

---

## Group 5 — UI pages

5.1 `app/ui/pages/xss_tester.py` — URL entry, GET/POST selector, optional params
   field (auto-parse from URL when blank), disclaimer banner, results
   `ttk.Treeview` (Param, Payload, Reflected, Encoded, Context, Verdict),
   CSV/TXT export, background thread + `queue` polling, `height=1` on the
   Treeview (per the v4.0 scroll fix). Follow `sqli_tester.py` page layout.

5.2 `app/ui/pages/open_redirect.py` — same shell; columns (Param, Payload,
   Status, Location, Verdict).

5.3 `app/ui/pages/csrf_analyser.py` — single-URL input (no per-param table);
   findings `ttk.Treeview` (Check, Detail, Severity) with severity colour tags,
   matching Header Analyser styling.

5.4 Each page: confirm no spurious scrollbar (canvas/grid behaviour from v4.0),
   `autohide_vsb` on the Treeview scrollbar.

---

## Group 6 — Wiring & integration

6.1 `app/data/categories.py` — add three `ToolEntry`s under `web_active`:
   XSS Tester (`xss_tester`), CSRF Analyser (`csrf_analyser`), Open Redirect
   (`open_redirect`), with icons.

6.2 `app/ui/pages/home.py` — add three **Active** `CARD_DATA` entries.

6.3 `app/ui/app_window.py` — import + `_add_page` for the three pages.

6.4 `app/ui/sidebar.py` — bump version label `v4.0.0` → `v4.1.0`.

6.5 Launch the app; navigate to each new tool from both the sidebar accordion
   and its home card; confirm pages render and scroll correctly.

---

## Group 7 — Documentation

7.1 Mark **v4.1 ✅ Complete** in `roadmap.md`.

7.2 Update `CHANGELOG.md` (via `/sdd-changelog`) with the v4.1 entry.

7.3 Commit the three spec files and the completed `validation.md` checklist.
