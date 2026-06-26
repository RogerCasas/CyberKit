"""
CyberKit — SSL/TLS Certificate Analyser engine
"""

import ssl
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID


@dataclass
class CertInfo:
    host: str
    port: int
    subject_cn: str
    subject_org: str
    issuer_cn: str
    issuer_org: str
    not_before: datetime
    not_after: datetime
    san_list: list
    serial: str
    sig_alg: str
    is_expired: bool
    is_near_expiry: bool
    is_self_signed: bool


def analyse(host: str, port: int = 443, timeout: int = 10) -> CertInfo:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)

    cert = x509.load_der_x509_certificate(der)

    subject_cn  = _attr(cert.subject, NameOID.COMMON_NAME)
    subject_org = _attr(cert.subject, NameOID.ORGANIZATION_NAME)
    issuer_cn   = _attr(cert.issuer,  NameOID.COMMON_NAME)
    issuer_org  = _attr(cert.issuer,  NameOID.ORGANIZATION_NAME)

    # cryptography >= 42 uses _utc variants; fall back for older installs
    try:
        not_before = cert.not_valid_before_utc
        not_after  = cert.not_valid_after_utc
    except AttributeError:
        not_before = cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after  = cert.not_valid_after.replace(tzinfo=timezone.utc)

    is_expired, is_near_expiry = _compute_status(not_after)
    is_self_signed = cert.subject == cert.issuer

    return CertInfo(
        host=host,
        port=port,
        subject_cn=subject_cn,
        subject_org=subject_org,
        issuer_cn=issuer_cn,
        issuer_org=issuer_org,
        not_before=not_before,
        not_after=not_after,
        san_list=_extract_sans(cert),
        serial=format(cert.serial_number, "X"),
        sig_alg=_sig_alg(cert),
        is_expired=is_expired,
        is_near_expiry=is_near_expiry,
        is_self_signed=is_self_signed,
    )


# ── Helpers (exported for unit tests) ────────────────────────────────────────

def _compute_status(not_after: datetime):
    """Return (is_expired, is_near_expiry) for a given not_after datetime."""
    now = datetime.now(timezone.utc)
    is_expired     = not_after < now
    is_near_expiry = not is_expired and (not_after - now) < timedelta(days=30)
    return is_expired, is_near_expiry


def _extract_sans(cert: x509.Certificate) -> list:
    """Return a list of DNS SAN strings from the certificate."""
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return list(ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        return []


def _attr(name: x509.Name, oid) -> str:
    attrs = name.get_attributes_for_oid(oid)
    return attrs[0].value if attrs else ""


def _sig_alg(cert: x509.Certificate) -> str:
    try:
        return cert.signature_hash_algorithm.name
    except Exception:
        return "unknown"
