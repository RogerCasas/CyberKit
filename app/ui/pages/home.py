"""
CyberKit — Home / Dashboard page
"""

import customtkinter as ctk
from app.data.categories import CATEGORIES

# ── Palette ───────────────────────────────────────────────────────────────────
BG_MAIN        = "#0f1117"
BG_CARD        = "#161b22"
BG_CARD_HOVER  = "#1a2332"
ACCENT_CYAN    = "#00d4ff"
TEXT_PRIMARY   = "#e6edf3"
TEXT_MUTED     = "#8b949e"
TEXT_DIM       = "#484f58"
BORDER_COLOR   = "#21262d"
WARNING_BG     = "#1a1500"
WARNING_BORDER = "#f0a500"
WARNING_TEXT   = "#f0a500"

# ── Card definitions — keyed by page_key ─────────────────────────────────────
CARD_DATA: dict[str, dict] = {
    "fuzzer": {
        "icon": "⬡",
        "title": "Directory Fuzzer",
        "desc": "Detect exposed directories and paths on a target web server using a curated 600+ entry wordlist.",
        "tag": "Active", "tag_color": "#22c55e",
    },
    "header_analyser": {
        "icon": "🛡",
        "title": "Header Analyser",
        "desc": "Inspect HTTP security headers for misconfigurations: CSP, HSTS, X-Frame-Options, and more.",
        "tag": "Active", "tag_color": "#22c55e",
    },
    "http_builder": {
        "icon": "📡",
        "title": "HTTP Builder",
        "desc": "Craft custom HTTP requests (method, headers, body) and inspect the full raw response: status, headers, body.",
        "tag": "Active", "tag_color": "#22c55e",
    },
    "sqli_tester": {
        "icon": "💉",
        "title": "SQLi Tester",
        "desc": "Detect SQL injection in GET/POST parameters via error-based and boolean-based techniques. Detection only.",
        "tag": "Active", "tag_color": "#22c55e",
    },
    "xss_tester": {
        "icon": "🧨",
        "title": "XSS Tester",
        "desc": "Detect reflected XSS by injecting marked payloads into GET/POST parameters and finding unescaped reflections. Detection only.",
        "tag": "Active", "tag_color": "#22c55e",
    },
    "csrf_analyser": {
        "icon": "🎫",
        "title": "CSRF Analyser",
        "desc": "Inspect CSRF posture: SameSite cookie flags, anti-CSRF form tokens, and Origin/Referer validation.",
        "tag": "Active", "tag_color": "#22c55e",
    },
    "open_redirect": {
        "icon": "↪",
        "title": "Open Redirect",
        "desc": "Detect unvalidated redirects by injecting external-host payloads and inspecting 3xx Location headers. Detection only.",
        "tag": "Active", "tag_color": "#22c55e",
    },
    "port_scanner": {
        "icon": "🔍",
        "title": "Port Scanner",
        "desc": "Scan open TCP ports on a target host. Identify running services and potential entry points.",
        "tag": "Active", "tag_color": "#22c55e",
    },
    "arp_scanner": {
        "icon": "📡",
        "title": "ARP Scanner",
        "desc": "Discover live hosts on a local subnet via layer-2 ARP broadcast. Shows IP, MAC, vendor, and hostname. Requires administrator privileges.",
        "tag": "Active", "tag_color": "#22c55e",
    },
    "credential_tester": {
        "icon": "🔑",
        "title": "Credential Tester",
        "desc": "Test credentials against HTTP Basic, form-based, and SSH login endpoints with rate-limiting and live results.",
        "tag": "Active", "tag_color": "#22c55e",
    },
    "dns_enumerator": {
        "icon": "🌐",
        "title": "DNS Enumerator",
        "desc": "Resolve A, AAAA, MX, NS, TXT records and brute-force subdomains from a built-in or custom wordlist.",
        "tag": "Active", "tag_color": "#22c55e",
    },
    "whois_geo": {
        "icon": "🌍",
        "title": "WHOIS & Geo",
        "desc": "Look up domain registration data (registrar, dates, name servers) and IP geolocation (country, city, ASN).",
        "tag": "Active", "tag_color": "#22c55e",
    },
    "hash_tool": {
        "icon": "#",
        "title": "Hash Tool",
        "desc": "Identify hash algorithm by pattern (MD5, SHA-1, SHA-256, bcrypt…) and run a dictionary attack.",
        "tag": "Active", "tag_color": "#22c55e",
    },
    "encoder_decoder": {
        "icon": "🔤",
        "title": "Encoder / Decoder",
        "desc": "Bidirectional transforms: URL, Base64, HTML entities, hex, ROT-13, and JWT inspection.",
        "tag": "Active", "tag_color": "#22c55e",
    },
    "tech_fingerprinter": {
        "icon": "🖥",
        "title": "Tech Fingerprinter",
        "desc": "Detect CMS, server software, frameworks, and CDNs from HTTP response headers and body signatures.",
        "tag": "Active", "tag_color": "#22c55e",
    },
    "ssl_analyser": {
        "icon": "🔒",
        "title": "SSL Analyser",
        "desc": "Inspect TLS certificates: expiry, issuer, SANs, serial, and signature algorithm. Flags expired, near-expiry, and self-signed certs.",
        "tag": "Active", "tag_color": "#22c55e",
    },
    "wordlist_generator": {
        "icon": "📝",
        "title": "Wordlist Generator",
        "desc": "Generate custom wordlists via charset brute-force or seed-phrase mutation (leet, caps, suffixes). Export to .txt.",
        "tag": "Active", "tag_color": "#22c55e",
    },
}

TAG_BG_MAP = {
    "#22c55e": "#0d2818",
    TEXT_MUTED: "#1c1f26",
}


class HomePage(ctk.CTkFrame):
    def __init__(self, parent, navigate_callback, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, corner_radius=0, **kwargs)
        self.navigate = navigate_callback
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        # ── Hero ──────────────────────────────────────────────────────────────
        hero = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        hero.grid(row=0, column=0, sticky="ew", padx=40, pady=(40, 0))
        hero.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            hero,
            text="⚡ CyberKit",
            font=ctk.CTkFont(family="Segoe UI", size=36, weight="bold"),
            text_color=ACCENT_CYAN, anchor="w",
        ).grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(
            hero,
            text="Unified Cybersecurity Learning Platform",
            font=ctk.CTkFont(family="Segoe UI", size=16),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        # ── Disclaimer banner ─────────────────────────────────────────────────
        banner = ctk.CTkFrame(
            self, fg_color=WARNING_BG, corner_radius=8,
            border_width=1, border_color=WARNING_BORDER,
        )
        banner.grid(row=1, column=0, sticky="ew", padx=40, pady=(20, 0))
        banner.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            banner, text="⚠",
            font=ctk.CTkFont(size=16), text_color=WARNING_TEXT,
        ).grid(row=0, column=0, padx=(14, 8), pady=12)

        ctk.CTkLabel(
            banner,
            text="For educational use only. Only scan systems you own or have explicit permission to test.",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=WARNING_TEXT, anchor="w",
        ).grid(row=0, column=1, sticky="w", pady=12, padx=(0, 14))

        # ── Category sections ─────────────────────────────────────────────────
        sections_frame = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        sections_frame.grid(row=2, column=0, sticky="nsew", padx=40, pady=(28, 20))
        sections_frame.grid_columnconfigure(0, weight=1)

        section_row = 0
        for cat in CATEGORIES:
            # Section heading
            ctk.CTkLabel(
                sections_frame,
                text=cat.label.upper(),
                font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
                text_color=TEXT_DIM, anchor="w",
            ).grid(row=section_row, column=0, sticky="w", pady=(20 if section_row > 0 else 0, 8))
            section_row += 1

            # Separator line under heading
            ctk.CTkFrame(
                sections_frame, height=1, fg_color=BORDER_COLOR, corner_radius=0,
            ).grid(row=section_row, column=0, sticky="ew", pady=(0, 10))
            section_row += 1

            # Card sub-grid for this category
            grid = ctk.CTkFrame(sections_frame, fg_color="transparent", corner_radius=0)
            grid.grid(row=section_row, column=0, sticky="ew")
            grid.grid_columnconfigure((0, 1), weight=1)
            section_row += 1

            for i, tool in enumerate(cat.tools):
                card_info = CARD_DATA.get(tool.page_key)
                if card_info is None:
                    continue
                row, col = divmod(i, 2)
                self._make_card(grid, tool.page_key, card_info, row, col)

    def _make_card(self, parent, page_key: str, mod: dict, row: int, col: int):
        is_active = True  # all cards in CARD_DATA are active tools

        card = ctk.CTkFrame(
            parent,
            fg_color=BG_CARD, corner_radius=12,
            border_width=1, border_color=BORDER_COLOR,
            cursor="hand2",
        )
        card.grid(row=row, column=col, padx=8, pady=8, sticky="nsew")
        card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            card, text=mod["icon"],
            font=ctk.CTkFont(size=28),
            text_color=ACCENT_CYAN,
        ).grid(row=0, column=0, rowspan=2, padx=(18, 12), pady=20, sticky="n")

        title_row = ctk.CTkFrame(card, fg_color="transparent")
        title_row.grid(row=0, column=1, sticky="ew", padx=(0, 16), pady=(18, 2))
        title_row.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            title_row, text=mod["title"],
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, sticky="w")

        tag_bg = TAG_BG_MAP.get(mod["tag_color"], "#1c1f26")
        ctk.CTkLabel(
            title_row, text=mod["tag"],
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color=mod["tag_color"],
            fg_color=tag_bg, corner_radius=4, padx=6, pady=2,
        ).grid(row=0, column=1, padx=(8, 0))

        ctk.CTkLabel(
            card, text=mod["desc"],
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED, anchor="w",
            wraplength=260, justify="left",
        ).grid(row=1, column=1, sticky="w", padx=(0, 16), pady=(0, 18))

        def enter(e, c=card):
            c.configure(fg_color=BG_CARD_HOVER, border_color=ACCENT_CYAN)

        def leave(e, c=card):
            c.configure(fg_color=BG_CARD, border_color=BORDER_COLOR)

        def click(e, p=page_key):
            self.navigate(p)

        def _bind_tree(w):
            w.bind("<Enter>", enter)
            w.bind("<Leave>", leave)
            w.bind("<Button-1>", click)
            for child in w.winfo_children():
                _bind_tree(child)

        _bind_tree(card)
