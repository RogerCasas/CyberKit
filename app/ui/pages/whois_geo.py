"""
CyberKit — WHOIS & IP Geolocation Page
"""

import queue
import threading

import customtkinter as ctk

from app.modules.whois_engine import WhoisInfo, lookup as whois_lookup
from app.modules.geo_engine import GeoInfo, lookup as geo_lookup

# ── Palette ───────────────────────────────────────────────────────────────────
BG_MAIN      = "#0f1117"
BG_CARD      = "#161b22"
BG_INPUT     = "#0d1117"
ACCENT_CYAN  = "#00d4ff"
TEXT_PRIMARY = "#e6edf3"
TEXT_MUTED   = "#8b949e"
TEXT_DIM     = "#484f58"
BORDER_COLOR = "#21262d"
CLR_ERROR    = "#ef4444"

POLL_MS = 100


class WhoisGeoPage(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, corner_radius=0, **kwargs)
        self._whois_queue: queue.Queue = queue.Queue()
        self._geo_queue:   queue.Queue = queue.Queue()
        self._whois_poll_id = None
        self._geo_poll_id   = None
        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=30, pady=(28, 0))
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            hdr, text="🌍  WHOIS & IP Geolocation",
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            hdr,
            text="Domain registration data via WHOIS  •  IP geolocation via ip-api.com",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        # Tab bar
        tab_bar = ctk.CTkFrame(self, fg_color="transparent")
        tab_bar.grid(row=1, column=0, sticky="ew", padx=30, pady=(18, 0))

        self._tab_whois_btn = ctk.CTkButton(
            tab_bar, text="WHOIS",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            width=110, height=34, corner_radius=8,
            fg_color=ACCENT_CYAN, hover_color="#00aacc", text_color="#0f1117",
            command=lambda: self._switch_tab("whois"),
        )
        self._tab_whois_btn.grid(row=0, column=0, padx=(0, 6))

        self._tab_geo_btn = ctk.CTkButton(
            tab_bar, text="Geolocation",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            width=130, height=34, corner_radius=8,
            fg_color=BG_CARD, hover_color=BG_INPUT, text_color=TEXT_MUTED,
            command=lambda: self._switch_tab("geo"),
        )
        self._tab_geo_btn.grid(row=0, column=1)

        # Stacked tab frames
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.grid(row=2, column=0, sticky="nsew", padx=30, pady=(12, 30))
        container.grid_columnconfigure(0, weight=1)
        container.grid_rowconfigure(0, weight=1)

        self._whois_frame = self._build_whois_tab(container)
        self._geo_frame   = self._build_geo_tab(container)

        self._whois_frame.grid(row=0, column=0, sticky="nsew")
        self._geo_frame.grid(row=0, column=0, sticky="nsew")
        self._whois_frame.tkraise()

    def _switch_tab(self, tab: str):
        if tab == "whois":
            self._whois_frame.tkraise()
            self._tab_whois_btn.configure(fg_color=ACCENT_CYAN, hover_color="#00aacc", text_color="#0f1117")
            self._tab_geo_btn.configure(fg_color=BG_CARD, hover_color=BG_INPUT, text_color=TEXT_MUTED)
        else:
            self._geo_frame.tkraise()
            self._tab_geo_btn.configure(fg_color=ACCENT_CYAN, hover_color="#00aacc", text_color="#0f1117")
            self._tab_whois_btn.configure(fg_color=BG_CARD, hover_color=BG_INPUT, text_color=TEXT_MUTED)

    # ── WHOIS Tab ─────────────────────────────────────────────────────────────

    def _build_whois_tab(self, parent) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        # Controls
        ctrl = ctk.CTkFrame(frame, fg_color=BG_CARD, corner_radius=12,
                            border_width=1, border_color=BORDER_COLOR)
        ctrl.grid(row=0, column=0, sticky="ew")
        ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            ctrl, text="Domain",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED,
        ).grid(row=0, column=0, padx=(18, 10), pady=(14, 4), sticky="w")

        self._whois_error = ctk.CTkLabel(
            ctrl, text="",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=CLR_ERROR, anchor="w",
        )
        self._whois_error.grid(row=0, column=1, sticky="w", padx=(0, 18), pady=(14, 4))

        self._whois_entry = ctk.CTkEntry(
            ctrl,
            placeholder_text="google.com",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, height=38,
        )
        self._whois_entry.grid(row=1, column=0, columnspan=2, sticky="ew",
                               padx=18, pady=(0, 6))
        self._whois_entry.bind("<Return>", lambda e: self._start_whois())

        self._whois_btn = ctk.CTkButton(
            ctrl, text="🔍  Lookup",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color="#0f1117", height=36, width=130, corner_radius=8,
            command=self._start_whois,
        )
        self._whois_btn.grid(row=2, column=0, padx=(18, 10), pady=(0, 14), sticky="w")

        self._whois_status = ctk.CTkLabel(
            ctrl, text="Enter a domain name and click Lookup.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_MUTED, anchor="w",
        )
        self._whois_status.grid(row=2, column=1, sticky="w", padx=(0, 18), pady=(0, 14))

        # Results card
        results = ctk.CTkFrame(frame, fg_color=BG_CARD, corner_radius=12,
                               border_width=1, border_color=BORDER_COLOR)
        results.grid(row=1, column=0, sticky="nsew", pady=(12, 0))
        results.grid_columnconfigure(0, weight=1)
        results.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            results, text="Registration Data",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(12, 6))

        self._whois_placeholder = ctk.CTkLabel(
            results,
            text="Enter a domain name and click Lookup.",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=TEXT_DIM,
        )
        self._whois_placeholder.place(relx=0.5, rely=0.55, anchor="center")

        self._whois_fields_frame = ctk.CTkFrame(results, fg_color="transparent")
        self._whois_fields_frame.grid_columnconfigure(1, weight=1)

        return frame

    # ── Geo Tab ───────────────────────────────────────────────────────────────

    def _build_geo_tab(self, parent) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        # Controls
        ctrl = ctk.CTkFrame(frame, fg_color=BG_CARD, corner_radius=12,
                            border_width=1, border_color=BORDER_COLOR)
        ctrl.grid(row=0, column=0, sticky="ew")
        ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            ctrl, text="IP / Domain",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED,
        ).grid(row=0, column=0, padx=(18, 10), pady=(14, 4), sticky="w")

        self._geo_error = ctk.CTkLabel(
            ctrl, text="",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=CLR_ERROR, anchor="w",
        )
        self._geo_error.grid(row=0, column=1, sticky="w", padx=(0, 18), pady=(14, 4))

        self._geo_entry = ctk.CTkEntry(
            ctrl,
            placeholder_text="8.8.8.8 or github.com",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, height=38,
        )
        self._geo_entry.grid(row=1, column=0, columnspan=2, sticky="ew",
                             padx=18, pady=(0, 6))
        self._geo_entry.bind("<Return>", lambda e: self._start_geo())

        self._geo_btn = ctk.CTkButton(
            ctrl, text="🔍  Lookup",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color="#0f1117", height=36, width=130, corner_radius=8,
            command=self._start_geo,
        )
        self._geo_btn.grid(row=2, column=0, padx=(18, 10), pady=(0, 14), sticky="w")

        self._geo_status = ctk.CTkLabel(
            ctrl, text="Enter an IP address or domain and click Lookup.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_MUTED, anchor="w",
        )
        self._geo_status.grid(row=2, column=1, sticky="w", padx=(0, 18), pady=(0, 14))

        # Results card
        results = ctk.CTkFrame(frame, fg_color=BG_CARD, corner_radius=12,
                               border_width=1, border_color=BORDER_COLOR)
        results.grid(row=1, column=0, sticky="nsew", pady=(12, 0))
        results.grid_columnconfigure(0, weight=1)
        results.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            results, text="Geolocation Data",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(12, 6))

        self._geo_placeholder = ctk.CTkLabel(
            results,
            text="Enter an IP address or domain and click Lookup.",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=TEXT_DIM,
        )
        self._geo_placeholder.place(relx=0.5, rely=0.55, anchor="center")

        self._geo_fields_frame = ctk.CTkFrame(results, fg_color="transparent")
        self._geo_fields_frame.grid_columnconfigure(1, weight=1)

        return frame

    # ── WHOIS scan ────────────────────────────────────────────────────────────

    def _start_whois(self):
        self._whois_error.configure(text="")
        domain = self._whois_entry.get().strip().lower()
        if not domain:
            self._whois_error.configure(text="Please enter a domain name.")
            return
        domain = domain.removeprefix("https://").removeprefix("http://").split("/")[0]

        self._whois_btn.configure(state="disabled")
        self._whois_status.configure(text=f"Looking up {domain}…")
        self._whois_queue = queue.Queue()

        threading.Thread(
            target=self._run_whois, args=(domain,), daemon=True
        ).start()
        self._whois_poll_id = self.after(POLL_MS, self._poll_whois)

    def _run_whois(self, domain: str):
        try:
            info = whois_lookup(domain)
            self._whois_queue.put(("ok", info))
        except Exception as exc:
            self._whois_queue.put(("error", str(exc)))

    def _poll_whois(self):
        try:
            kind, data = self._whois_queue.get_nowait()
        except queue.Empty:
            self._whois_poll_id = self.after(POLL_MS, self._poll_whois)
            return

        self._whois_btn.configure(state="normal")
        if kind == "error":
            self._whois_error.configure(text=f"Error: {data}")
            self._whois_status.configure(text="Lookup failed.")
        else:
            self._whois_status.configure(text="Lookup complete.")
            self._show_whois(data)

    def _show_whois(self, info: WhoisInfo):
        self._whois_placeholder.place_forget()
        for w in self._whois_fields_frame.winfo_children():
            w.destroy()

        ns_text = "\n".join(info.name_servers) if info.name_servers else "—"
        fields = [
            ("Registrar",   info.registrar      or "—"),
            ("Created",     info.creation_date  or "—"),
            ("Expires",     info.expiry_date    or "—"),
            ("Updated",     info.updated_date   or "—"),
            ("Registrant",  info.registrant_org or "—"),
            ("Name Servers", ns_text),
        ]
        _populate_fields(self._whois_fields_frame, fields)
        self._whois_fields_frame.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 14))

    # ── Geo scan ──────────────────────────────────────────────────────────────

    def _start_geo(self):
        self._geo_error.configure(text="")
        target = self._geo_entry.get().strip()
        if not target:
            self._geo_error.configure(text="Please enter an IP address or domain.")
            return
        target = target.removeprefix("https://").removeprefix("http://").split("/")[0]

        self._geo_btn.configure(state="disabled")
        self._geo_status.configure(text=f"Looking up {target}…")
        self._geo_queue = queue.Queue()

        threading.Thread(
            target=self._run_geo, args=(target,), daemon=True
        ).start()
        self._geo_poll_id = self.after(POLL_MS, self._poll_geo)

    def _run_geo(self, target: str):
        try:
            info = geo_lookup(target)
            self._geo_queue.put(("ok", info))
        except Exception as exc:
            self._geo_queue.put(("error", str(exc)))

    def _poll_geo(self):
        try:
            kind, data = self._geo_queue.get_nowait()
        except queue.Empty:
            self._geo_poll_id = self.after(POLL_MS, self._poll_geo)
            return

        self._geo_btn.configure(state="normal")
        if kind == "error":
            self._geo_error.configure(text=f"Error: {data}")
            self._geo_status.configure(text="Lookup failed.")
        else:
            self._geo_status.configure(text="Lookup complete.")
            self._show_geo(data)

    def _show_geo(self, info: GeoInfo):
        self._geo_placeholder.place_forget()
        for w in self._geo_fields_frame.winfo_children():
            w.destroy()

        fields = [
            ("Queried IP",    info.query_ip  or "—"),
            ("Country",       info.country   or "—"),
            ("Region",        info.region    or "—"),
            ("City",          info.city      or "—"),
            ("ISP",           info.isp       or "—"),
            ("Organisation",  info.org       or "—"),
            ("AS Number",     info.as_number or "—"),
        ]
        _populate_fields(self._geo_fields_frame, fields)
        self._geo_fields_frame.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 14))


# ── Shared helper ─────────────────────────────────────────────────────────────

def _populate_fields(parent: ctk.CTkFrame, fields: list):
    """Render a list of (label, value) pairs as a two-column grid."""
    parent.grid_columnconfigure(1, weight=1)
    for i, (label, value) in enumerate(fields):
        ctk.CTkLabel(
            parent, text=label,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED, anchor="e", width=110,
        ).grid(row=i, column=0, sticky="ne", padx=(0, 10), pady=4)
        ctk.CTkLabel(
            parent, text=value,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_PRIMARY, anchor="nw",
            wraplength=380, justify="left",
        ).grid(row=i, column=1, sticky="nw", pady=4)
