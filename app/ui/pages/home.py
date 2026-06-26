"""
CyberKit — Home / Dashboard page
"""

import customtkinter as ctk

# ── Palette ───────────────────────────────────────────────────────────────────
BG_MAIN       = "#0f1117"
BG_CARD       = "#161b22"
BG_CARD_HOVER = "#1a2332"
ACCENT_CYAN   = "#00d4ff"
ACCENT_PURPLE = "#7c3aed"
TEXT_PRIMARY  = "#e6edf3"
TEXT_MUTED    = "#8b949e"
TEXT_DIM      = "#484f58"
BORDER_COLOR  = "#21262d"
WARNING_BG    = "#1a1500"
WARNING_BORDER = "#f0a500"
WARNING_TEXT  = "#f0a500"

# ── Module cards shown on dashboard ──────────────────────────────────────────
MODULE_CARDS = [
    {
        "icon": "⬡",
        "title": "Directory Fuzzer",
        "desc": "Detect exposed directories and paths on a target web server using a curated 600+ entry wordlist.",
        "tag": "Active",
        "tag_color": "#22c55e",
        "page": "fuzzer",
    },
    {
        "icon": "🔍",
        "title": "Port Scanner",
        "desc": "Scan open TCP ports on a target host. Identify running services and potential entry points.",
        "tag": "Active",
        "tag_color": "#22c55e",
        "page": "port_scanner",
    },
    {
        "icon": "🔑",
        "title": "Credential Tester",
        "desc": "Test credentials against HTTP Basic, form-based, and SSH login endpoints with rate-limiting and live results.",
        "tag": "Active",
        "tag_color": "#22c55e",
        "page": "credential_tester",
    },
    {
        "icon": "🛡",
        "title": "Header Analyser",
        "desc": "Inspect HTTP security headers for misconfigurations: CSP, HSTS, X-Frame-Options, and more.",
        "tag": "Active",
        "tag_color": "#22c55e",
        "page": "header_analyser",
    },
    {
        "icon": "🌐",
        "title": "DNS Enumerator",
        "desc": "Resolve A, AAAA, MX, NS, TXT records and brute-force subdomains from a built-in or custom wordlist.",
        "tag": "Active",
        "tag_color": "#22c55e",
        "page": "dns_enumerator",
    },
    {
        "icon": "🔤",
        "title": "Encoder / Decoder",
        "desc": "Bidirectional transforms: URL, Base64, HTML entities, hex, ROT-13, and JWT inspection.",
        "tag": "Active",
        "tag_color": "#22c55e",
        "page": "encoder_decoder",
    },
    {
        "icon": "#",
        "title": "Hash Tool",
        "desc": "Identify hash algorithm by pattern (MD5, SHA-1, SHA-256, bcrypt…) and run a dictionary attack.",
        "tag": "Active",
        "tag_color": "#22c55e",
        "page": "hash_tool",
    },
    {
        "icon": "🖥",
        "title": "Tech Fingerprinter",
        "desc": "Detect CMS, server software, frameworks, and CDNs from HTTP response headers and body signatures.",
        "tag": "Active",
        "tag_color": "#22c55e",
        "page": "tech_fingerprinter",
    },
]


class HomePage(ctk.CTkFrame):
    def __init__(self, parent, navigate_callback, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, corner_radius=0, **kwargs)
        self.navigate = navigate_callback
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        # ── Hero section ──────────────────────────────────────────────────────
        hero = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        hero.grid(row=0, column=0, sticky="ew", padx=40, pady=(40, 0))
        hero.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            hero,
            text="⚡ CyberKit",
            font=ctk.CTkFont(family="Segoe UI", size=36, weight="bold"),
            text_color=ACCENT_CYAN,
            anchor="w",
        ).grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(
            hero,
            text="Unified Cybersecurity Learning Platform",
            font=ctk.CTkFont(family="Segoe UI", size=16),
            text_color=TEXT_MUTED,
            anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        # ── Disclaimer banner ─────────────────────────────────────────────────
        banner = ctk.CTkFrame(
            self,
            fg_color=WARNING_BG,
            corner_radius=8,
            border_width=1,
            border_color=WARNING_BORDER,
        )
        banner.grid(row=1, column=0, sticky="ew", padx=40, pady=(20, 0))
        banner.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            banner,
            text="⚠",
            font=ctk.CTkFont(size=16),
            text_color=WARNING_TEXT,
        ).grid(row=0, column=0, padx=(14, 8), pady=12)

        ctk.CTkLabel(
            banner,
            text="For educational use only. Only scan systems you own or have explicit permission to test.",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=WARNING_TEXT,
            anchor="w",
        ).grid(row=0, column=1, sticky="w", pady=12, padx=(0, 14))

        # ── Section heading ───────────────────────────────────────────────────
        ctk.CTkLabel(
            self,
            text="AVAILABLE MODULES",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=TEXT_DIM,
            anchor="w",
        ).grid(row=2, column=0, sticky="w", padx=40, pady=(32, 10))

        # ── Module card grid ──────────────────────────────────────────────────
        card_container = ctk.CTkScrollableFrame(
            self, fg_color="transparent", corner_radius=0,
            scrollbar_button_color=BORDER_COLOR,
            scrollbar_button_hover_color=TEXT_DIM,
        )
        card_container.grid(row=3, column=0, sticky="nsew", padx=40, pady=(0, 20))
        card_container.grid_columnconfigure((0, 1), weight=1)

        for i, mod in enumerate(MODULE_CARDS):
            row, col = divmod(i, 2)
            self._make_card(card_container, mod, row, col)

    def _make_card(self, parent, mod: dict, row: int, col: int):
        is_active = mod["page"] is not None

        card = ctk.CTkFrame(
            parent,
            fg_color=BG_CARD,
            corner_radius=12,
            border_width=1,
            border_color=BORDER_COLOR,
            cursor="hand2" if is_active else "arrow",
        )
        card.grid(row=row, column=col, padx=8, pady=8, sticky="nsew")
        card.grid_columnconfigure(1, weight=1)

        # Icon
        ctk.CTkLabel(
            card,
            text=mod["icon"],
            font=ctk.CTkFont(size=28),
            text_color=ACCENT_CYAN if is_active else TEXT_MUTED,
        ).grid(row=0, column=0, rowspan=2, padx=(18, 12), pady=20, sticky="n")

        # Title + tag row
        title_row = ctk.CTkFrame(card, fg_color="transparent")
        title_row.grid(row=0, column=1, sticky="ew", padx=(0, 16), pady=(18, 2))
        title_row.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            title_row,
            text=mod["title"],
            font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
            text_color=TEXT_PRIMARY if is_active else TEXT_MUTED,
            anchor="w",
        ).grid(row=0, column=0, sticky="w")

        # Derive a muted background from the tag colour (Tkinter needs 6-digit hex)
        tag_bg_map = {
            "#22c55e": "#0d2818",  # green → dark green
            TEXT_MUTED: "#1c1f26",  # muted → dark grey
        }
        tag_bg = tag_bg_map.get(mod["tag_color"], "#1c1f26")
        tag_lbl = ctk.CTkLabel(
            title_row,
            text=mod["tag"],
            font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
            text_color=mod["tag_color"],
            fg_color=tag_bg,
            corner_radius=4,
            padx=6,
            pady=2,
        )
        tag_lbl.grid(row=0, column=1, padx=(8, 0))

        # Description
        ctk.CTkLabel(
            card,
            text=mod["desc"],
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED,
            anchor="w",
            wraplength=260,
            justify="left",
        ).grid(row=1, column=1, sticky="w", padx=(0, 16), pady=(0, 18))

        # Hover + click for active cards
        if is_active:
            def enter(e, c=card):
                c.configure(fg_color=BG_CARD_HOVER, border_color=ACCENT_CYAN)
            def leave(e, c=card):
                c.configure(fg_color=BG_CARD, border_color=BORDER_COLOR)
            def click(e, p=mod["page"]):
                self.navigate(p)

            for w in card.winfo_children():
                w.bind("<Enter>", enter)
                w.bind("<Leave>", leave)
                w.bind("<Button-1>", click)
            card.bind("<Enter>", enter)
            card.bind("<Leave>", leave)
            card.bind("<Button-1>", click)
