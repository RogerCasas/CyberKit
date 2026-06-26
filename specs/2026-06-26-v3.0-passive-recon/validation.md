# v3.0 — Passive Recon Expansion: Validation Checklist

---

## Group 1 — SSL/TLS Analyser engine (automated)

Run `python tests/test_ssl_analyser.py`:

- [x] `is_expired` returns `True` when `not_after` is set to a date in the past.
- [x] `is_expired` returns `False` when `not_after` is set to a date in the future.
- [x] `is_near_expiry` returns `True` when fewer than 30 days remain (`not_after` = now + 10 days).
- [x] `is_near_expiry` returns `False` when more than 30 days remain (`not_after` = now + 60 days).
- [x] `is_self_signed` returns `True` when `subject_cn == issuer_cn` and `subject_org == issuer_org`.
- [x] `is_self_signed` returns `False` when issuer differs from subject.
- [x] SANs are extracted as a plain list of DNS name strings (no `DNS:` prefix, no IP SANs included).

---

## Group 2 — SSL/TLS Analyser UI (manual)

- [x] SSL/TLS Analyser page loads from the sidebar without errors.
- [x] Analysing `example.com:443` returns a result with a valid CN, non-empty issuer, two valid dates, and at least one SAN.
- [x] Status badges: a valid cert from a trusted CA shows `✔ Valid` in green.
- [x] Analysing a host with a self-signed cert (e.g. a local test server) shows the `⚠ Self-signed` badge.
- [x] Analysing a near-expiry or expired cert shows the appropriate amber/red badge.
- [x] Entering an unreachable host (e.g. `192.0.2.1`) shows an inline error and does not crash.
- [x] Port field defaults to `443`; changing it to `8443` and scanning a host on that port works correctly.

---

## Group 3 — WHOIS & Geolocation engines (automated)

Run `python tests/test_whois_geo.py`:

- [x] `WhoisInfo` is constructed correctly from a mocked `whois.whois()` response with all fields populated.
- [x] When the mock returns a list for `creation_date`, only the first element is used.
- [x] When the mock returns `None` for optional fields (`registrant_org`, `updated_date`), the result uses an empty string — no crash.
- [x] `GeoInfo` is constructed correctly from a mocked ip-api.com JSON response with `status == "success"`.
- [x] `lookup_geo()` raises `ValueError` when the API response contains `status == "fail"`.

---

## Group 4 — WHOIS & Geolocation UI (manual)

- [x] WHOIS & Geolocation page loads from the sidebar without errors.
- [x] WHOIS tab is the default active tab.
- [x] Looking up `google.com` in the WHOIS tab returns a registrar, creation date, and at least two name servers.
- [x] Looking up `8.8.8.8` in the Geolocation tab returns country `United States`, with a non-empty ISP and AS number.
- [x] Looking up a domain (e.g. `github.com`) in the Geolocation tab resolves it to an IP and returns a result.
- [x] Entering an invalid domain in the WHOIS tab shows an inline error and does not crash.
- [x] Entering an invalid IP/domain in the Geolocation tab shows an inline error and does not crash.

---

## Group 5 — Integration (manual)

- [x] Both modules appear in the sidebar navigation and are reachable by clicking.
- [x] Both module cards on the home page show `Active`.
- [x] Switching between all existing modules and the two new ones produces no errors or layout corruption.
- [x] `roadmap.md` v3.0 module rows are marked ✅ Done.
- [x] `CHANGELOG.md` contains a v3.0 entry describing both modules.
- [x] Spec files (`requirements.md`, `plan.md`, `validation.md`) are committed on the feature branch.
