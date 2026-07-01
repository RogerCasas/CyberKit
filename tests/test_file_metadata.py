"""
CyberKit — File Metadata Extractor engine tests

Run: python tests/test_file_metadata.py
Tests use only dataclass construction and the public extract() API;
no real image/PDF files required for the first three tests.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.modules.file_metadata import MetaField, MetaResult, extract, _gps_to_decimal


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_unknown_extension():
    """extract() on an unsupported extension → file_type='unknown', no error."""
    result = extract("some_file.xyz")
    assert result.file_type == "unknown", f"Expected 'unknown', got '{result.file_type}'"
    assert result.error == "", f"Expected no error, got '{result.error}'"
    assert result.fields == [], f"Expected no fields, got {result.fields}"
    print("  unknown_extension: OK")


def test_pdf_error_handling():
    """extract() on a non-existent .pdf → error field non-empty, no exception."""
    result = extract("nonexistent_file_that_does_not_exist.pdf")
    assert result.file_type == "pdf", f"Expected 'pdf', got '{result.file_type}'"
    assert result.error != "", f"Expected an error message, got empty string"
    print(f"  pdf_error_handling: error='{result.error[:40]}…': OK")


def test_meta_field_sensitive_flag():
    """MetaField with sensitive=True is constructable and attribute is accessible."""
    f = MetaField(key="GPS Latitude", value="40.123456", sensitive=True)
    assert f.sensitive is True, f"Expected sensitive=True, got {f.sensitive}"
    assert f.key == "GPS Latitude"
    assert f.value == "40.123456"

    f2 = MetaField(key="DateTime", value="2024:01:15 12:00:00")
    assert f2.sensitive is False, f"Default sensitive should be False, got {f2.sensitive}"
    print("  meta_field_sensitive_flag: OK")


def test_gps_decimal_conversion():
    """Known GPS rational input produces correct decimal degrees."""
    # 40° 41' 21.5" N  →  40 + 41/60 + 21.5/3600 ≈ 40.689306
    rationals = [(40, 1), (41, 1), (215, 10)]
    result = _gps_to_decimal(rationals, "N")
    expected = 40 + 41 / 60 + 21.5 / 3600
    assert abs(result - expected) < 0.001, f"Expected ≈{expected:.6f}, got {result}"

    # Southern hemisphere → negative
    result_s = _gps_to_decimal(rationals, "S")
    assert result_s < 0, f"Southern hemisphere should be negative, got {result_s}"
    print(f"  gps_decimal_conversion: {result:.6f}°N: OK")


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_unknown_extension,
        test_pdf_error_handling,
        test_meta_field_sensitive_flag,
        test_gps_decimal_conversion,
    ]
    passed = 0
    print(f"Running {len(tests)} File Metadata Extractor tests…\n")
    for t in tests:
        try:
            t()
            passed += 1
        except AssertionError as e:
            print(f"  FAIL {t.__name__}: {e}")
        except Exception as e:
            import traceback
            print(f"  ERROR {t.__name__}: {e}")
            traceback.print_exc()
    print(f"\n{passed}/{len(tests)} tests passed")
    sys.exit(0 if passed == len(tests) else 1)
