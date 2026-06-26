# v3.0 — Passive Recon Expansion: Implementation Plan

---

## Group 1 — SSL/TLS Certificate Analyser engine

**1.1** Create `app/modules/ssl_analyser.py`
- Define `@dataclass CertInfo`: `host`, `port`, `subject_cn`, `subject_org`, `issuer_cn`, `issuer_org`, `not_before` (datetime), `not_after` (datetime), `san_list` (list[str] — DNS names), `serial` (hex str), `sig_alg` (str), `is_expired` (bool), `is_near_expiry` (bool, < 30 days), `is_self_signed` (bool)
- Implement `analyse(host: str, port: int = 443, timeout: int = 10) -> CertInfo`:
  - Open TLS connection with `check_hostname=False, verify_mode=ssl.CERT_NONE` to retrieve the cert regardless of validity
  - Call `getpeercert(binary_form=True)` → DER bytes
  - Parse with `cryptography.x509.load_der_x509_certificate()`
  - Extract all `CertInfo` fields; compute flags against `datetime.now(UTC)`
  - Propagate `ssl.SSLError`, `socket.timeout`, `OSError` to caller (UI shows inline error)

**1.2** Write `tests/test_ssl_analyser.py` — no network calls:
- Test `is_expired` flag: construct a `CertInfo` with `not_after` in the past → `True`
- Test `is_near_expiry` flag: `not_after` = now + 10 days → `True`; now + 60 days → `False`
- Test `is_self_signed` flag: `subject_cn == issuer_cn` and `subject_org == issuer_org` → `True`; mismatched → `False`
- Test SANs parsing: list of DNS names extracted correctly from a real cert created with `cryptography` in the test fixture

---

## Group 2 — SSL/TLS Certificate Analyser UI

**2.1** Create `app/ui/pages/ssl_analyser.py` — `SslAnalyserPage(CTkFrame)`:
- Row 0: page header + subtitle
- Row 1: controls card — host entry (placeholder `"example.com"`), port entry (default `443`, width 80), Analyse button, inline error label
- Row 2 (weight=1): results area — initially shows placeholder text; on success renders a structured card with field/value rows and coloured status badges

**2.2** Implement results display:
- Structured card rows: Subject, Issuer, Valid From, Valid Until, SANs (comma-joined), Serial, Signature Algorithm
- Status badges row: `✔ Valid` (green) / `✗ Expired` (red) / `⚠ Near-expiry` (amber) / `⚠ Self-signed` (amber) — only the applicable badge(s) shown
- Scan runs in a `threading.Thread`; result passed via `queue.Queue`; polled with `after()`

---

## Group 3 — WHOIS & Geolocation engines

**3.1** Create `app/modules/whois_engine.py`:
- Define `@dataclass WhoisInfo`: `domain`, `registrar`, `creation_date`, `expiry_date`, `updated_date`, `registrant_org`, `name_servers` (list[str])
- Implement `lookup(domain: str) -> WhoisInfo`:
  - Call `whois.whois(domain)` (python-whois)
  - Normalise fields: dates may be `list[datetime]` → take first; missing fields → empty string / empty list
  - Raise `ValueError` if python-whois returns no result

**3.2** Create `app/modules/geo_engine.py`:
- Define `@dataclass GeoInfo`: `query_ip`, `country`, `region`, `city`, `isp`, `org`, `as_number`
- Implement `lookup(ip_or_domain: str) -> GeoInfo`:
  - Resolve domain to IP via `socket.gethostbyname()` if not already an IP
  - GET `http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as`
  - Raise `ValueError` if `status != "success"`

**3.3** Write `tests/test_whois_geo.py` — no network calls:
- Test `WhoisInfo` construction from a mocked `whois.whois()` return dict (patched with `unittest.mock.patch`)
- Test date normalisation: list of datetimes → first entry taken
- Test missing-field handling: `None` values become empty string/list
- Test `GeoInfo` construction from a mocked ip-api.com JSON response
- Test `GeoInfo` raises `ValueError` when `status == "fail"`

**3.4** Add `python-whois>=0.9.0` to `requirements.txt` and `cryptography>=3.3` (making the transitive dep explicit)

---

## Group 4 — WHOIS & Geolocation UI

**4.1** Create `app/ui/pages/whois_geo.py` — `WhoisGeoPage(CTkFrame)`:
- Header + two-tab bar (WHOIS / Geolocation) using the `tkraise()` pattern
- WHOIS tab: domain entry + Lookup button + inline error + results card (registrar, dates, registrant org, name servers)
- Geolocation tab: IP/domain entry + Lookup button + inline error + results card (country, region, city, ISP, org, AS)
- Each tab runs its engine in a background thread; results via queue

---

## Group 5 — Integration

**5.1** Register both pages in `app/ui/app_window.py`

**5.2** Add sidebar nav items in `app/ui/sidebar.py`; bump version to v3.0.0

**5.3** Add two Active module cards on `app/ui/pages/home.py`

**5.4** Update `roadmap.md` — mark v3.0 rows ✅ Done
