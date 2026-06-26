"""
CyberKit — IP Geolocation engine (ip-api.com, free tier, no key)
"""

import socket
from dataclasses import dataclass

import requests

_GEO_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as"
_TIMEOUT = 10


@dataclass
class GeoInfo:
    query_ip: str
    country: str
    region: str
    city: str
    isp: str
    org: str
    as_number: str


def lookup(ip_or_domain: str) -> GeoInfo:
    # Resolve domain → IP if needed
    try:
        ip = socket.gethostbyname(ip_or_domain)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve {ip_or_domain!r}: {exc}") from exc

    try:
        resp = requests.get(_GEO_URL.format(ip=ip), timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        raise ValueError(f"Geolocation request failed: {exc}") from exc

    if data.get("status") != "success":
        msg = data.get("message", "unknown error")
        raise ValueError(f"ip-api.com returned an error: {msg}")

    return GeoInfo(
        query_ip=ip,
        country=data.get("country", ""),
        region=data.get("regionName", ""),
        city=data.get("city", ""),
        isp=data.get("isp", ""),
        org=data.get("org", ""),
        as_number=data.get("as", ""),
    )
