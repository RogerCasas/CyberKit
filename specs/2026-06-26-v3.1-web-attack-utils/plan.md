# v3.1 — Web Attack Utilities: Implementation Plan

---

## Group 1 — HTTP request engine

**Goal:** a thin, testable wrapper around `requests` that the SQLi tester can reuse.

1.1 Create `app/modules/http_builder.py`:
- `RequestResult` dataclass: `status_code: int`, `reason: str`, `headers: dict`, `body: str`, `elapsed_ms: int`, `error: str`
- `send(method, url, headers, body, follow_redirects, timeout) → RequestResult`
- Catches `requests.RequestException`, `ValueError` (invalid URL), and bare `Exception`; populates `error` field, never raises

1.2 Verify: write `tests/test_http_builder.py` with mocked `requests.Session.request`:
- Successful GET → correct `status_code`, `headers`, `body`, `elapsed_ms`
- Connection error → `error` populated, all other fields at defaults
- Invalid URL (no scheme) → `error` populated without crash

---

## Group 2 — HTTP Builder UI

**Goal:** a fully functional request-crafting page, independently testable before SQLi work begins.

2.1 Create `app/ui/pages/http_builder.py`:
- Row 0: page header label
- Row 1: controls card — method dropdown (CTkOptionMenu: GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS), URL entry, follow-redirects checkbox, Send button, status label
- Row 2: two-column body card (weight split ~40/60):
  - Left: headers editor — scrollable list of key/value `CTkEntry` pairs; Add Header / Clear All buttons
  - Right: request body — `CTkTextbox` for raw body text; label "Request Body"
- Row 3 (weight=1): response card — status badge (colour-coded by status class), elapsed label, headers section (CTkTextbox, read-only), body section (CTkTextbox, read-only, monospace)

2.2 Background thread + queue protocol: `("ok", RequestResult)` or `("error", str)`

2.3 `_collect_headers()` helper: reads all non-empty key/value pairs from the headers editor into a `dict`

---

## Group 3 — SQLi detection engine

**Goal:** a scan engine that calls `http_builder.send()` for all probes and returns structured results.

3.1 Create `app/modules/sqli_tester.py`:
- `InjectionResult` dataclass: `parameter: str`, `payload: str`, `detection_type: str`, `evidence: str`, `is_vulnerable: bool`
- `ERROR_PATTERNS`: list of regex patterns for MySQL, MSSQL, Oracle, PostgreSQL, and SQLite error strings
- `BOOLEAN_PAYLOADS`: `("' AND 1=1--", "' AND 1=2--")` pair
- `ERROR_PAYLOAD`: `"'"`

3.2 `scan(url, method, params, timeout, progress_cb) → list[InjectionResult]`:
- Accepts `params`: list of parameter names to test; if empty, auto-parses from URL query string
- For each parameter: injects `ERROR_PAYLOAD`, checks response body against `ERROR_PATTERNS` → error-based result
- For each parameter: sends baseline + true-condition + false-condition probes; flags boolean injection if true-condition length ≈ baseline and false-condition length differs by > 20 %
- Calls `progress_cb(current, total)` after each parameter tested
- Uses `http_builder.send()` for all HTTP calls

3.3 Verify: write `tests/test_sqli_tester.py` with `unittest.mock.patch("app.modules.http_builder.send")`:
- Mock response containing a MySQL error string → `is_vulnerable=True`, `detection_type="error-based"`
- Mock responses where true/false probes return different lengths → `is_vulnerable=True`, `detection_type="boolean-based"`
- Mock clean responses → `is_vulnerable=False` for all results

---

## Group 4 — SQLi Tester UI

**Goal:** a scan page that drives the engine and presents findings in a Treeview.

4.1 Create `app/ui/pages/sqli_tester.py`:
- Row 0: page header + disclaimer banner ("⚠ Only test systems you own or have explicit permission to test.")
- Row 1: controls card — URL entry, method toggle (GET / POST, `tkraise()` pattern), Scan / Stop buttons, status + progress label
- Row 2: parameters card — editable list of parameter names (auto-populated from URL query string on parse button click; user can add/remove manually)
- Row 3 (weight=1): results card — `ttk.Treeview` with columns: Parameter, Payload, Type, Evidence, Verdict (colour-coded: vulnerable=red, clean=green)

4.2 Background thread + queue protocol: `("progress", current, total)`, `("result", InjectionResult)`, `("done",)`, `("error", str)`

4.3 `_parse_params()`: parses `urllib.parse.urlparse(url).query` → list of parameter names; populates the parameters editor

---

## Group 5 — Integration

5.1 Register both pages in `app/ui/app_window.py`:
- `self._pages["http_builder"] = HttpBuilderPage(self._content)`
- `self._pages["sqli_tester"] = SqliTesterPage(self._content)`

5.2 Add nav items to `app/ui/sidebar.py`:
- `("HTTP Builder", "📡", "http_builder")`
- `("SQLi Tester", "💉", "sqli_tester")`
- Bump version label to `v3.1.0`

5.3 Add two Active module cards to `app/ui/pages/home.py`

5.4 Mark v3.1 `✅ Complete` with `✅ Done` on both module rows in `roadmap.md`
