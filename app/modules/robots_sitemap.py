"""
CyberKit — Robots.txt & Sitemap Parser Engine

Fetches and parses robots.txt (directives, sitemap references) and
sitemap XML files (urlset and sitemapindex, one level of recursion).
"""

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests


@dataclass
class RobotsResult:
    url:          str
    raw_text:     str
    directives:   list[tuple[str, str]]  # (user_agent, disallow_path)
    sitemap_urls: list[str]
    error:        str  # empty if successful


@dataclass
class SitemapResult:
    source_url: str
    urls:       list[str]
    error:      str  # empty if successful


# ── Parsing helpers (pure functions, testable without network) ────────────────

def _parse_robots_text(text: str) -> tuple[list[tuple[str, str]], list[str]]:
    """
    Parse robots.txt content into (directives, sitemap_urls).

    directives  — list of (user_agent, disallow_path) pairs
    sitemap_urls — list of Sitemap: directive values
    """
    directives:   list[tuple[str, str]] = []
    sitemap_urls: list[str]             = []
    current_agent = "*"

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key   = key.strip().lower()
        value = value.strip()

        if key == "user-agent":
            current_agent = value or "*"
        elif key == "disallow":
            directives.append((current_agent, value))
        elif key == "sitemap":
            if value:
                sitemap_urls.append(value)

    return directives, sitemap_urls


def _strip_ns(tag: str) -> str:
    """Remove XML namespace prefix from a tag name."""
    return tag.split("}")[-1] if "}" in tag else tag


def _parse_sitemap_xml(xml_text: str) -> tuple[list[str], bool]:
    """
    Parse sitemap XML and return (urls, is_index).

    urls     — list of <loc> values found
    is_index — True if this is a sitemapindex (not a urlset)
    """
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return [], False

    tag = _strip_ns(root.tag).lower()
    is_index = tag == "sitemapindex"

    child_tag = "sitemap" if is_index else "url"
    urls: list[str] = []
    for child in root:
        if _strip_ns(child.tag).lower() == child_tag:
            for sub in child:
                if _strip_ns(sub.tag).lower() == "loc":
                    if sub.text and sub.text.strip():
                        urls.append(sub.text.strip())

    return urls, is_index


# ── Network helpers ───────────────────────────────────────────────────────────

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0 Safari/537.36"
    ),
    "Accept": "text/plain,application/xml,text/xml,*/*;q=0.9",
}

_TIMEOUT = 12


def _normalise_domain(domain: str) -> str:
    """Ensure domain has a scheme for URL construction."""
    domain = domain.strip().rstrip("/")
    if "://" not in domain:
        domain = "https://" + domain
    parsed = urlparse(domain)
    return f"{parsed.scheme}://{parsed.netloc}"


# ── Public API ────────────────────────────────────────────────────────────────

def fetch_robots(domain: str) -> RobotsResult:
    """
    Fetch and parse robots.txt for a domain.
    Falls back to http:// if https:// fails with an SSL error.
    Never raises.
    """
    base = _normalise_domain(domain)
    url  = f"{base}/robots.txt"

    try:
        resp = requests.get(url, headers=_HEADERS, timeout=_TIMEOUT)
        resp.raise_for_status()
        text = resp.text
    except requests.exceptions.SSLError:
        fallback = url.replace("https://", "http://", 1)
        try:
            resp = requests.get(fallback, headers=_HEADERS, timeout=_TIMEOUT)
            resp.raise_for_status()
            text = resp.text
            url  = fallback
        except Exception as exc:
            return RobotsResult(url=url, raw_text="", directives=[], sitemap_urls=[],
                                error=str(exc))
    except Exception as exc:
        return RobotsResult(url=url, raw_text="", directives=[], sitemap_urls=[],
                            error=str(exc))

    directives, sitemap_urls = _parse_robots_text(text)
    return RobotsResult(
        url=url,
        raw_text=text,
        directives=directives,
        sitemap_urls=sitemap_urls,
        error="",
    )


def fetch_sitemap(url: str) -> SitemapResult:
    """
    Fetch and parse a sitemap URL (urlset or sitemapindex).
    For sitemapindex, fetches each child sitemap one level deep.
    Never raises.
    """
    url = url.strip()
    try:
        resp = requests.get(url, headers=_HEADERS, timeout=_TIMEOUT)
        resp.raise_for_status()
        xml_text = resp.text
    except Exception as exc:
        return SitemapResult(source_url=url, urls=[], error=str(exc))

    child_urls, is_index = _parse_sitemap_xml(xml_text)

    if not is_index:
        return SitemapResult(source_url=url, urls=child_urls, error="")

    # Sitemapindex: fetch each child sitemap and collect their <loc> entries
    all_urls: list[str] = []
    for child_url in child_urls:
        try:
            r2 = requests.get(child_url, headers=_HEADERS, timeout=_TIMEOUT)
            r2.raise_for_status()
            page_urls, _ = _parse_sitemap_xml(r2.text)
            all_urls.extend(page_urls)
        except Exception:
            pass  # partial results are better than nothing

    return SitemapResult(source_url=url, urls=all_urls, error="")
