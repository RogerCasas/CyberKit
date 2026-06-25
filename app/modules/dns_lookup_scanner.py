"""
CyberKit — DNS Record Lookup Engine

Resolves A, AAAA, MX, NS, TXT records for a domain synchronously.
"""

from dataclasses import dataclass

import dns.resolver
import dns.exception

SUPPORTED_TYPES = ("A", "AAAA", "MX", "NS", "TXT")


@dataclass
class DNSRecord:
    record_type: str
    value:       str
    ttl:         int


def resolve_records(domain: str, record_types: list[str]) -> tuple[list[DNSRecord], list[str]]:
    """Return (records, errors) for the requested record types."""
    records: list[DNSRecord] = []
    errors:  list[str]  = []

    for rtype in record_types:
        if rtype not in SUPPORTED_TYPES:
            continue
        try:
            answer = dns.resolver.resolve(domain, rtype, lifetime=10)
            ttl = answer.rrset.ttl if answer.rrset else 0
            for rdata in answer:
                records.append(DNSRecord(
                    record_type=rtype,
                    value=rdata.to_text(),
                    ttl=ttl,
                ))
        except dns.resolver.NXDOMAIN:
            errors.append(f"{rtype}: domain does not exist")
        except dns.resolver.NoAnswer:
            pass  # record type simply not present — not an error
        except dns.resolver.Timeout:
            errors.append(f"{rtype}: query timed out")
        except dns.exception.DNSException as exc:
            errors.append(f"{rtype}: {exc}")

    return records, errors
