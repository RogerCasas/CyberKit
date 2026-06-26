"""
CyberKit — SSL/TLS Analyser engine tests (no network)

Run: python tests/test_ssl_analyser.py
"""

import io
import sys
import os
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from app.modules.ssl_analyser import _compute_status, _extract_sans

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_cert(cn="test.example.com", issuer_cn=None, days=365, sans=None):
    """Build a minimal self-signed cert using the cryptography library."""
    if issuer_cn is None:
        issuer_cn = cn
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
    ])
    issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org" if issuer_cn == cn else "Issuer Org"),
    ])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=days))
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]),
            critical=False,
        )
    return builder.sign(key, hashes.SHA256())


# ── _compute_status tests ─────────────────────────────────────────────────────

def test_expired_in_past():
    past = datetime.now(timezone.utc) - timedelta(days=1)
    is_expired, is_near = _compute_status(past)
    assert is_expired, "Expected is_expired=True for a date in the past"
    assert not is_near, "Near-expiry should be False when already expired"
    print("  expired (past date) → is_expired=True, is_near_expiry=False: OK")


def test_valid_far_future():
    future = datetime.now(timezone.utc) + timedelta(days=365)
    is_expired, is_near = _compute_status(future)
    assert not is_expired
    assert not is_near
    print("  valid far future → is_expired=False, is_near_expiry=False: OK")


def test_near_expiry_10_days():
    near = datetime.now(timezone.utc) + timedelta(days=10)
    is_expired, is_near = _compute_status(near)
    assert not is_expired
    assert is_near, "Expected is_near_expiry=True for 10 days remaining"
    print("  near-expiry (10 days) → is_near_expiry=True: OK")


def test_not_near_expiry_60_days():
    far = datetime.now(timezone.utc) + timedelta(days=60)
    is_expired, is_near = _compute_status(far)
    assert not is_expired
    assert not is_near, "Expected is_near_expiry=False for 60 days remaining"
    print("  not near-expiry (60 days) → is_near_expiry=False: OK")


# ── Self-signed detection test ────────────────────────────────────────────────

def test_self_signed_detection():
    cert = _make_cert(cn="self.example.com", issuer_cn="self.example.com")
    assert cert.subject == cert.issuer, "Self-signed cert should have subject == issuer"
    print("  self-signed cert subject == issuer: OK")


def test_not_self_signed():
    cert = _make_cert(cn="leaf.example.com", issuer_cn="ca.example.com")
    assert cert.subject != cert.issuer, "CA-signed cert should have subject != issuer"
    print("  CA-signed cert subject != issuer: OK")


# ── SANs extraction test ──────────────────────────────────────────────────────

def test_sans_extracted_correctly():
    expected = ["example.com", "www.example.com", "api.example.com"]
    cert = _make_cert(sans=expected)
    result = _extract_sans(cert)
    assert result == expected, f"Expected {expected}, got {result}"
    print(f"  SANs extracted: {result}: OK")


def test_no_sans_returns_empty():
    cert = _make_cert()  # no SANs extension
    result = _extract_sans(cert)
    assert result == [], f"Expected [], got {result}"
    print("  no SANs extension → empty list: OK")


if __name__ == "__main__":
    tests = [
        test_expired_in_past,
        test_valid_far_future,
        test_near_expiry_10_days,
        test_not_near_expiry_60_days,
        test_self_signed_detection,
        test_not_self_signed,
        test_sans_extracted_correctly,
        test_no_sans_returns_empty,
    ]
    passed = 0
    print(f"Running {len(tests)} SSL analyser tests...\n")
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
