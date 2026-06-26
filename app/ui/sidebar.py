"""
CyberKit — Collapsible Sidebar (instant toggle, no animation)
"""

import customtkinter as ctk

# ── Palette ───────────────────────────────────────────────────────────────────
BG_SIDEBAR      = "#0d1117"
BG_ITEM_HOVER   = "#161b22"
BG_ITEM_ACTIVE  = "#1a2332"
ACCENT_CYAN     = "#00d4ff"
TEXT_PRIMARY    = "#e6edf3"
TEXT_MUTED      = "#8b949e"
BORDER_COLOR    = "#21262d"

SIDEBAR_W_EXPANDED  = 210
SIDEBAR_W_COLLAPSED = 56

# ── Nav items: (label, icon_char, page_key) ───────────────────────────────────
NAV_ITEMS = [
    ("Home",             "⌂",  "home"),
    ("Dir Fuzzer",       "⬡",  "fuzzer"),
    ("Port Scanner",     "🔍", "port_scanner"),
    ("Header Analyser",  "🛡", "header_analyser"),
    ("Cred Tester",      "🔑", "credential_tester"),
    ("DNS Enumerator",   "🌐", "dns_enumerator"),
    ("Encoder/Decoder",  "🔤", "encoder_decoder"),
    ("Hash Tool",        "#",  "hash_tool"),
    ("Tech Fingerprint", "🖥", "tech_fingerprinter"),
    ("SSL Analyser",     "🔒", "ssl_analyser"),
    ("WHOIS & Geo",      "🌍", "whois_geo"),
]


class Sidebar(ctk.CTkFrame):
    """
    Collapsible sidebar with instant toggle.

    Layout strategy so the toggle button is ALWAYS visible:
      - toggle_row (row 0): always rendered, contains logo (hides when collapsed)
        and the toggle button (never hidden).
      - The toggle button is gridded in column=1 and survives grid_remove on column=0.
    """

    def __init__(self, parent, navigate_callback, **kwargs):
        super().__init__(
            parent,
            width=SIDEBAR_W_EXPANDED,
            corner_radius=0,
            fg_color=BG_SIDEBAR,
            border_width=0,
            **kwargs,
        )
        self.navigate      = navigate_callback
        self._expanded     = True
        self._active_page  = "home"
        self._item_frames:   dict[str, ctk.CTkFrame] = {}
        self._label_widgets: dict[str, ctk.CTkLabel] = {}

        self.grid_propagate(False)
        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        self.grid_rowconfigure(99, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # ── Toggle row (always fully visible) ────────────────────────────────
        toggle_row = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        toggle_row.grid(row=0, column=0, sticky="ew", padx=0, pady=(8, 0))
        toggle_row.grid_columnconfigure(0, weight=1)

        self._logo_label = ctk.CTkLabel(
            toggle_row,
            text="⚡ CyberKit",
            font=ctk.CTkFont(family="Segoe UI", size=15, weight="bold"),
            text_color=ACCENT_CYAN,
            anchor="w",
        )
        self._logo_label.grid(row=0, column=0, sticky="w", padx=(14, 0))

        # Toggle button is in column=1 and is NEVER removed from grid
        self._toggle_btn = ctk.CTkButton(
            toggle_row,
            text="◀",
            width=30,
            height=30,
            corner_radius=6,
            fg_color="transparent",
            hover_color=BG_ITEM_HOVER,
            text_color=TEXT_MUTED,
            font=ctk.CTkFont(size=11),
            command=self.toggle,
        )
        self._toggle_btn.grid(row=0, column=1, padx=(0, 8))

        # ── Separator ─────────────────────────────────────────────────────────
        ctk.CTkFrame(self, height=1, fg_color=BORDER_COLOR,
                     corner_radius=0).grid(row=1, column=0, sticky="ew",
                                           padx=8, pady=(6, 4))

        # ── Section label ─────────────────────────────────────────────────────
        self._section_label = ctk.CTkLabel(
            self,
            text="MODULES",
            font=ctk.CTkFont(family="Segoe UI", size=9, weight="bold"),
            text_color=TEXT_MUTED,
            anchor="w",
        )
        self._section_label.grid(row=2, column=0, sticky="w", padx=16,
                                  pady=(2, 4))

        # ── Nav items ─────────────────────────────────────────────────────────
        for idx, (label, icon, key) in enumerate(NAV_ITEMS):
            frame = ctk.CTkFrame(self, fg_color="transparent",
                                 corner_radius=8, cursor="hand2")
            frame.grid(row=3 + idx, column=0, sticky="ew", padx=6, pady=2)
            frame.grid_columnconfigure(1, weight=1)

            icon_lbl = ctk.CTkLabel(
                frame, text=icon, width=28,
                font=ctk.CTkFont(size=15),
                text_color=TEXT_MUTED, anchor="center",
            )
            icon_lbl.grid(row=0, column=0, padx=(8, 0), pady=8)

            text_lbl = ctk.CTkLabel(
                frame, text=label,
                font=ctk.CTkFont(family="Segoe UI", size=13),
                text_color=TEXT_MUTED, anchor="w",
            )
            text_lbl.grid(row=0, column=1, sticky="w", padx=(8, 8))

            self._item_frames[key]   = frame
            self._label_widgets[key] = text_lbl

            for w in (frame, icon_lbl, text_lbl):
                w.bind("<Button-1>", lambda e, k=key: self._on_click(k))
                w.bind("<Enter>",    lambda e, f=frame, k=key: self._on_hover(f, k, True))
                w.bind("<Leave>",    lambda e, f=frame, k=key: self._on_hover(f, k, False))

        # ── Version label ─────────────────────────────────────────────────────
        self._version_label = ctk.CTkLabel(
            self, text="v3.0.0",
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color=TEXT_MUTED,
        )
        self._version_label.grid(row=99, column=0, pady=(0, 12))

        self._set_active("home")

    # ── Interaction ───────────────────────────────────────────────────────────

    def _on_click(self, key: str):
        self._set_active(key)
        self.navigate(key)

    def _on_hover(self, frame: ctk.CTkFrame, key: str, entering: bool):
        if key == self._active_page:
            return
        frame.configure(fg_color=BG_ITEM_HOVER if entering else "transparent")

    def _set_active(self, key: str):
        if self._active_page in self._item_frames:
            self._item_frames[self._active_page].configure(fg_color="transparent")
            self._label_widgets[self._active_page].configure(text_color=TEXT_MUTED)
        self._active_page = key
        if key in self._item_frames:
            self._item_frames[key].configure(fg_color=BG_ITEM_ACTIVE)
            self._label_widgets[key].configure(text_color=ACCENT_CYAN)

    # ── Toggle (instant — text-swap + single geometry flush) ─────────────────

    def toggle(self):
        self._expanded = not self._expanded
        if self._expanded:
            for nav_label, _icon, key in NAV_ITEMS:
                if key in self._label_widgets:
                    self._label_widgets[key].configure(text=nav_label)
            self._logo_label.configure(text="⚡ CyberKit")
            self._section_label.configure(text="MODULES")
            self._version_label.configure(text="v3.0.0")
            self.configure(width=SIDEBAR_W_EXPANDED)
            self._toggle_btn.configure(text="◀")
        else:
            for lbl in self._label_widgets.values():
                lbl.configure(text="")
            self._logo_label.configure(text="")
            self._section_label.configure(text="")
            self._version_label.configure(text="")
            self.configure(width=SIDEBAR_W_COLLAPSED)
            self._toggle_btn.configure(text="▶")
        self.winfo_toplevel().update_idletasks()

    def set_active_page(self, key: str):
        self._set_active(key)
