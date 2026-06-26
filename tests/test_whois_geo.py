"""
CyberKit — WHOIS & Geolocation engine tests (no network)

Run: python tests/test_whois_geo.py
"""

import io
import sys
import os
from datetime import datetime
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from app.modules.whois_engine import _str, _fmt_date, _ns_list, WhoisInfo
from app.modules.geo_engine import GeoInfo


# ── WHOIS helper tests ────────────────────────────────────────────────────────

def test_whois_all_fields_populated():
    mock_w = MagicMock()
    mock_w.domain_name = "example.com"
    mock_w.registrar = "Example Registrar, Inc."
    mock_w.creation_date = datetime(2000, 1, 15)
    mock_w.expiration_date = datetime(2030, 1, 15)
    mock_w.updated_date = datetime(2023, 6, 1)
    mock_w.org = "Example Organisation"
    mock_w.name_servers = ["ns1.example.com", "ns2.example.com"]

    with patch("app.modules.whois_engine.whois.whois", return_value=mock_w):
        from app.modules.whois_engine import lookup
        info = lookup("example.com")

    assert info.registrar == "Example Registrar, Inc."
    assert info.creation_date == "2000-01-15"
    assert info.expiry_date == "2030-01-15"
    assert info.updated_date == "2023-06-01"
    assert info.registrant_org == "Example Organisation"
    assert "ns1.example.com" in info.name_servers
    print(f"  whois all-fields populated: OK  (registrar={info.registrar!r})")


def test_whois_date_is_list_takes_first():
    mock_w = MagicMock()
    mock_w.domain_name = "example.com"
    mock_w.registrar = "Registrar"
    mock_w.creation_date = [datetime(2001, 3, 10), datetime(2001, 3, 11)]
    mock_w.expiration_date = None
    mock_w.updated_date = None
    mock_w.org = None
    mock_w.name_servers = []

    with patch("app.modules.whois_engine.whois.whois", return_value=mock_w):
        from app.modules.whois_engine import lookup
        info = lookup("example.com")

    assert info.creation_date == "2001-03-10", f"Expected first date, got {info.creation_date!r}"
    print(f"  date list → first element taken: OK  ({info.creation_date})")


def test_whois_none_fields_become_empty():
    mock_w = MagicMock()
    mock_w.domain_name = "example.com"
    mock_w.registrar = None
    mock_w.creation_date = None
    mock_w.expiration_date = None
    mock_w.updated_date = None
    mock_w.org = None
    mock_w.name_servers = None

    with patch("app.modules.whois_engine.whois.whois", return_value=mock_w):
        from app.modules.whois_engine import lookup
        info = lookup("example.com")

    assert info.registrar == ""
    assert info.creation_date == ""
    assert info.registrant_org == ""
    assert info.name_servers == []
    print("  None fields → empty string / empty list: OK")


# ── Geo engine tests ──────────────────────────────────────────────────────────

def test_geo_success_response():
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "status": "success",
        "country": "United States",
        "regionName": "California",
        "city": "Mountain View",
        "isp": "Google LLC",
        "org": "Google LLC",
        "as": "AS15169 Google LLC",
    }
    mock_resp.raise_for_status = MagicMock()

    with patch("app.modules.geo_engine.socket.gethostbyname", return_value="8.8.8.8"), \
         patch("app.modules.geo_engine.requests.get", return_value=mock_resp):
        from app.modules.geo_engine import lookup
        info = lookup("8.8.8.8")

    assert info.query_ip == "8.8.8.8"
    assert info.country == "United States"
    assert info.city == "Mountain View"
    assert info.as_number == "AS15169 Google LLC"
    print(f"  geo success: OK  (country={info.country!r}, city={info.city!r})")


def test_geo_fail_status_raises():
    mock_resp = MagicMock()
    mock_resp.json.return_value = {"status": "fail", "message": "private range"}
    mock_resp.raise_for_status = MagicMock()

    with patch("app.modules.geo_engine.socket.gethostbyname", return_value="192.168.1.1"), \
         patch("app.modules.geo_engine.requests.get", return_value=mock_resp):
        from app.modules.geo_engine import lookup
        try:
            lookup("192.168.1.1")
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "private range" in str(e)
            print(f"  geo fail status → ValueError: OK  ({e})")


if __name__ == "__main__":
    tests = [
        test_whois_all_fields_populated,
        test_whois_date_is_list_takes_first,
        test_whois_none_fields_become_empty,
        test_geo_success_response,
        test_geo_fail_status_raises,
    ]
    passed = 0
    print(f"Running {len(tests)} WHOIS & Geo tests...\n")
    for t in tests:
        try:
            t()
            passed += 1
        except AssertionError as e:
            print(f"  FAIL {t.__name__}: {e}")
        except Exception as e:
            print(f"  ERROR {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} tests passed")
    sys.exit(0 if passed == len(tests) else 1)
