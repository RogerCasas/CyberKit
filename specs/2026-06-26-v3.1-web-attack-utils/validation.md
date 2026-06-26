# v3.1 — Web Attack Utilities: Validation Checklist

---

## Group 1 — HTTP request engine (automated)

Run `python tests/test_http_builder.py`:

- [x] A mocked successful GET response populates `status_code`, `reason`, `headers`, `body`, and `elapsed_ms` correctly.
- [x] A mocked `requests.ConnectionError` results in `error` being non-empty and `status_code` being 0 — no exception raised.
- [x] Passing a URL without a scheme (e.g. `"example.com"`) results in `error` being non-empty — no exception raised.

---

## Group 2 — HTTP Builder UI (manual)

- [x] HTTP Builder page loads from the sidebar without errors.
- [x] Sending a GET request to a reachable URL (e.g. `http://httpbin.org/get`) returns a 200 response with headers and body displayed.
- [x] Sending a POST request with a JSON body returns the correct response.
- [x] Adding custom headers (e.g. `X-Test: hello`) and verifying the server echoes them back works correctly.
- [x] Toggling follow-redirects off and requesting a URL that redirects returns the redirect response (3xx) instead of the final destination.
- [x] Entering an unreachable host shows an inline error and does not crash.
- [x] Switching methods between GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS all send correctly.

---

## Group 3 — SQLi detection engine (automated)

Run `python tests/test_sqli_tester.py` (18 tests):

- [x] MySQL, MSSQL, Oracle, PostgreSQL, and SQLite error patterns each detected correctly via `_check_error_patterns`.
- [x] Clean response body (no DB error strings) is not flagged.
- [x] AND (string), AND (numeric), and OR (string) boolean probe sets each detected when true≈baseline and false≠baseline.
- [x] Identical-length true/false responses are not flagged as boolean injection.
- [x] `_probe_error` stops iterating payloads on first match (early exit verified by call count).
- [x] `_probe_error` returns `is_vulnerable=False` when no payload triggers a DB error.
- [x] `_inject` GET modifies the query string and preserves other parameters; body is empty.
- [x] `_inject` POST builds a URL-encoded body; URL has no query string.
- [x] `_parse_params` extracts all parameter names from a URL query string.
- [x] `_parse_params` returns an empty list for a URL with no query string.
- [x] `scan()` reports an error-based finding when the server echoes a DB error.
- [x] `scan()` with an empty params list auto-parses parameters from the URL and tests each one.

---

## Group 4 — SQLi Tester UI (manual)

- [x] SQLi Tester page loads from the sidebar without errors.
- [x] The disclaimer banner ("Only test systems you own or have explicit permission to test.") is visible.
- [x] Entering a URL with query parameters (e.g. `http://localhost/?id=1`) and clicking parse auto-populates the parameter list.
- [x] Scanning a locally hosted vulnerable parameter (e.g. a simple PHP page that echoes a DB error) flags that parameter as vulnerable.
- [x] Scanning a URL with no injectable parameters shows all results as clean (not vulnerable).
- [x] A connection error during scan shows an inline error and does not crash.

---

## Group 5 — Integration (manual)

- [x] HTTP Builder and SQLi Tester both appear in the sidebar navigation and are reachable by clicking.
- [x] Both new module cards appear on the home page with the `Active` tag.
- [x] Switching between all existing modules and the two new ones produces no errors or layout corruption.
- [x] Sidebar version label reads `v3.1.0`.
- [x] `roadmap.md` v3.1 module rows are marked ✅ Done.

---

## Documentation

- [x] `CHANGELOG.md` contains a v3.1 entry describing both modules.
- [x] Spec files (`requirements.md`, `plan.md`, `validation.md`) are committed on the feature branch.
