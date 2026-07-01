"""
CyberKit — Robots.txt & Sitemap Parser engine tests

Run: python tests/test_robots_sitemap.py
All tests use fixture strings — no network calls.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from app.modules.robots_sitemap import _parse_robots_text, _parse_sitemap_xml

# ── Fixtures ──────────────────────────────────────────────────────────────────

ROBOTS_TXT = """\
User-agent: *
Disallow: /admin/
Disallow: /private/
Allow: /public/

User-agent: Googlebot
Disallow: /no-google/

Sitemap: https://example.com/sitemap.xml
Sitemap: https://example.com/sitemap-news.xml
"""

ROBOTS_EMPTY = ""

URLSET_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/page1</loc></url>
  <url><loc>https://example.com/page2</loc></url>
  <url><loc>https://example.com/page3</loc></url>
</urlset>
"""

SITEMAPINDEX_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>https://example.com/sitemap-pages.xml</loc></sitemap>
  <sitemap><loc>https://example.com/sitemap-blog.xml</loc></sitemap>
</sitemapindex>
"""

MALFORMED_XML = "this is not xml <<<"


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_parse_directives():
    """Multi-agent robots.txt yields correct directives and sitemap URLs."""
    directives, sitemap_urls = _parse_robots_text(ROBOTS_TXT)

    # Should have 3 Disallow entries (2 for * + 1 for Googlebot)
    assert len(directives) == 3, f"Expected 3 directives, got {len(directives)}: {directives}"

    # Check specific directives
    assert ("*", "/admin/") in directives, f"/admin/ missing from directives: {directives}"
    assert ("*", "/private/") in directives, f"/private/ missing: {directives}"
    assert ("Googlebot", "/no-google/") in directives, f"Googlebot entry missing: {directives}"

    # Two sitemap URLs
    assert len(sitemap_urls) == 2, f"Expected 2 sitemap URLs, got {len(sitemap_urls)}: {sitemap_urls}"
    assert "https://example.com/sitemap.xml" in sitemap_urls
    assert "https://example.com/sitemap-news.xml" in sitemap_urls
    print(f"  parse_directives: {len(directives)} directives, {len(sitemap_urls)} sitemaps: OK")


def test_parse_sitemap_urlset():
    """urlset XML with 3 <loc> entries produces 3 URLs."""
    urls, is_index = _parse_sitemap_xml(URLSET_XML)
    assert not is_index, "urlset should not be flagged as sitemapindex"
    assert len(urls) == 3, f"Expected 3 URLs, got {len(urls)}: {urls}"
    assert "https://example.com/page1" in urls
    assert "https://example.com/page2" in urls
    assert "https://example.com/page3" in urls
    print(f"  parse_sitemap_urlset: {len(urls)} URLs: OK")


def test_parse_sitemap_index():
    """sitemapindex XML with 2 entries produces 2 child sitemap URLs."""
    urls, is_index = _parse_sitemap_xml(SITEMAPINDEX_XML)
    assert is_index, "Should be flagged as sitemapindex"
    assert len(urls) == 2, f"Expected 2 child sitemap URLs, got {len(urls)}: {urls}"
    assert "https://example.com/sitemap-pages.xml" in urls
    assert "https://example.com/sitemap-blog.xml" in urls
    print(f"  parse_sitemap_index: {len(urls)} child sitemap URLs (is_index=True): OK")


def test_empty_robots():
    """Empty robots.txt produces zero directives and zero sitemaps."""
    directives, sitemap_urls = _parse_robots_text(ROBOTS_EMPTY)
    assert directives == [], f"Expected no directives, got {directives}"
    assert sitemap_urls == [], f"Expected no sitemap URLs, got {sitemap_urls}"
    print("  empty_robots: OK")


def test_malformed_xml_no_raise():
    """Malformed XML is handled gracefully — no exception raised."""
    try:
        urls, is_index = _parse_sitemap_xml(MALFORMED_XML)
        assert urls == [], f"Expected empty list for malformed XML, got {urls}"
    except Exception as e:
        raise AssertionError(f"_parse_sitemap_xml raised on malformed XML: {e}")
    print("  malformed_xml_no_raise: OK")


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_parse_directives,
        test_parse_sitemap_urlset,
        test_parse_sitemap_index,
        test_empty_robots,
        test_malformed_xml_no_raise,
    ]
    passed = 0
    print(f"Running {len(tests)} Robots & Sitemap Parser tests…\n")
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
