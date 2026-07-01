"""
Category registry — single source of truth for sidebar accordion and home page sections.

Each entry: (key, label, tools)
  key   — stable identifier used in _cat_expanded dict
  label — display name shown in sidebar header and home page section heading
  tools — list of (nav_label, icon, page_key) matching app_window page keys
"""

from typing import NamedTuple


class ToolEntry(NamedTuple):
    label: str
    icon: str
    page_key: str


class Category(NamedTuple):
    key: str
    label: str
    tools: list  # list[ToolEntry]


CATEGORIES: list[Category] = [
    Category("web_active", "Web / Active Testing", [
        ToolEntry("Dir Fuzzer",      "⬡",  "fuzzer"),
        ToolEntry("Header Analyser", "🛡", "header_analyser"),
        ToolEntry("HTTP Builder",    "📡", "http_builder"),
        ToolEntry("SQLi Tester",     "💉", "sqli_tester"),
        ToolEntry("XSS Tester",      "🧨", "xss_tester"),
        ToolEntry("CSRF Analyser",   "🎫", "csrf_analyser"),
        ToolEntry("Open Redirect",   "↪",  "open_redirect"),
    ]),
    Category("network_recon", "Network / Recon", [
        ToolEntry("Port Scanner",    "🔍", "port_scanner"),
        ToolEntry("ARP Scanner",     "📡", "arp_scanner"),
        ToolEntry("Traceroute",      "🗺", "traceroute"),
        ToolEntry("Banner Grabber",  "🖧", "banner_grabber"),
        ToolEntry("Packet Sniffer",  "🔬", "packet_sniffer"),
    ]),
    Category("auth_exploit", "Auth & Exploitation", [
        ToolEntry("Cred Tester",     "🔑", "credential_tester"),
    ]),
    Category("dns_osint", "DNS & OSINT", [
        ToolEntry("DNS Enumerator",  "🌐", "dns_enumerator"),
        ToolEntry("WHOIS & Geo",     "🌍", "whois_geo"),
    ]),
    Category("crypto_encoding", "Cryptanalysis & Encoding", [
        ToolEntry("Hash Tool",       "#",  "hash_tool"),
        ToolEntry("Encoder/Decoder", "🔤", "encoder_decoder"),
        ToolEntry("JWT Forge & Verify", "🔑", "jwt_tool"),
        ToolEntry("Cipher Identifier",  "🔐", "cipher_solver"),
    ]),
    Category("tech_analysis", "Tech Analysis", [
        ToolEntry("Tech Fingerprint","🖥", "tech_fingerprinter"),
        ToolEntry("SSL Analyser",    "🔒", "ssl_analyser"),
    ]),
    Category("wordlist_utils", "Wordlist & Utilities", [
        ToolEntry("Wordlist Gen",    "📝", "wordlist_generator"),
    ]),
]

# Reverse map: page_key → category key (excludes "home" which has no category)
PAGE_TO_CATEGORY: dict[str, str] = {
    tool.page_key: cat.key
    for cat in CATEGORIES
    for tool in cat.tools
}
