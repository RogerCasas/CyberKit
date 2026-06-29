"""
CyberKit — SSL/TLS Certificate Analyser Page
"""

import queue
import threading

import customtkinter as ctk

from app.modules.ssl_analyser import CertInfo, analyse

# ── Palette ───────────────────────────────────────────────────────────────────
BG_MAIN      = "#0f1117"
BG_CARD      = "#161b22"
BG_INPUT     = "#0d1117"
ACCENT_CYAN  = "#00d4ff"
TEXT_PRIMARY = "#e6edf3"
TEXT_MUTED   = "#8b949e"
TEXT_DIM     = "#484f58"
BORDER_COLOR = "#21262d"
CLR_OK       = "#22c55e"
CLR_WARN     = "#f59e0b"
CLR_ERROR    = "#ef4444"

POLL_MS = 100


class SslAnalyserPage(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, corner_radius=0, **kwargs)
        self._result_queue: queue.Queue = queue.Queue()
        self._poll_id = None
        self._scanning = False
        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=30, pady=(28, 0))
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            hdr, text="🔒  SSL/TLS Certificate Analyser",
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            hdr,
            text="Inspect the TLS certificate of any host  •  Expiry, SANs, issuer, self-signed detection",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        self._build_controls()
        self._build_results()

    def _build_controls(self):
        ctrl = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=12,
                            border_width=1, border_color=BORDER_COLOR)
        ctrl.grid(row=1, column=0, sticky="ew", padx=30, pady=(20, 0))
        ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            ctrl, text="Host",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED,
        ).grid(row=0, column=0, padx=(18, 10), pady=(14, 4), sticky="w")

        self._inline_error = ctk.CTkLabel(
            ctrl, text="",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=CLR_ERROR, anchor="w",
        )
        self._inline_error.grid(row=0, column=1, columnspan=2,
                                sticky="w", padx=(0, 18), pady=(14, 4))

        self._host_entry = ctk.CTkEntry(
            ctrl,
            placeholder_text="example.com",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, height=38,
        )
        self._host_entry.grid(row=1, column=0, columnspan=2, sticky="ew",
                              padx=18, pady=(0, 6))
        self._host_entry.bind("<Return>", lambda e: self._start_scan())

        ctk.CTkLabel(
            ctrl, text="Port",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED,
        ).grid(row=2, column=0, padx=(18, 10), pady=(2, 4), sticky="w")

        self._port_entry = ctk.CTkEntry(
            ctrl,
            width=80, height=36,
            font=ctk.CTkFont(family="Segoe UI", size=13),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
        )
        self._port_entry.insert(0, "443")
        self._port_entry.grid(row=2, column=0, padx=(18, 0), pady=(2, 14), sticky="w")
        # shift port entry to be after the label — rebuild with correct column
        self._port_entry.grid_forget()

        # Re-layout: host spans 2 cols, port is narrow in col 0 below the label
        self._port_entry = ctk.CTkEntry(
            ctrl, width=80, height=36,
            font=ctk.CTkFont(family="Segoe UI", size=13),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
        )
        self._port_entry.insert(0, "443")
        self._port_entry.grid(row=2, column=0, padx=(18, 10), pady=(2, 14), sticky="w")

        self._scan_btn = ctk.CTkButton(
            ctrl, text="▶  Analyse",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color="#0f1117", height=36, width=130, corner_radius=8,
            command=self._start_scan,
        )
        self._scan_btn.grid(row=2, column=1, padx=(0, 18), pady=(2, 14), sticky="w")

        self._status_lbl = ctk.CTkLabel(
            ctrl, text="Enter a hostname and click Analyse.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_MUTED, anchor="w",
        )
        self._status_lbl.grid(row=2, column=2, sticky="ew", padx=(0, 18), pady=(2, 14))
        ctrl.grid_columnconfigure(2, weight=1)

    def _build_results(self):
        card = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=12,
                            border_width=1, border_color=BORDER_COLOR)
        card.grid(row=2, column=0, sticky="nsew", padx=30, pady=(16, 30))
        card.grid_columnconfigure(0, weight=1)
        card.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            card, text="Certificate Details",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(12, 6))

        self._cert_placeholder = ctk.CTkLabel(
            card,
            text="Enter a hostname and click Analyse.",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=TEXT_DIM,
        )
        self._cert_placeholder.place(relx=0.5, rely=0.55, anchor="center")

        self._cert_scroll = ctk.CTkFrame(
            card, fg_color="transparent", corner_radius=0,
        )
        self._cert_scroll.grid_columnconfigure(1, weight=1)
        # Not gridded until first result

    # ── Scan ──────────────────────────────────────────────────────────────────

    def _start_scan(self):
        if self._scanning:
            return
        self._inline_error.configure(text="")

        raw_host = self._host_entry.get().strip()
        if not raw_host:
            self._inline_error.configure(text="Please enter a hostname.")
            return

        # Strip scheme/path if user pastes a URL
        host = raw_host
        if "://" in host:
            host = host.split("://", 1)[1]
        host = host.split("/")[0].split(":")[0].strip()
        if not host:
            self._inline_error.configure(text="Could not parse a hostname from that input.")
            return

        port_str = self._port_entry.get().strip()
        try:
            port = int(port_str)
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError:
            self._inline_error.configure(text="Port must be a number between 1 and 65535.")
            return

        self._scanning = True
        self._scan_btn.configure(state="disabled")
        self._status_lbl.configure(text=f"Connecting to {host}:{port}…")
        self._result_queue = queue.Queue()

        threading.Thread(
            target=self._run_scan, args=(host, port), daemon=True
        ).start()
        self._poll_id = self.after(POLL_MS, self._poll)

    def _run_scan(self, host: str, port: int):
        try:
            info = analyse(host, port)
            self._result_queue.put(("ok", info))
        except Exception as exc:
            self._result_queue.put(("error", str(exc)))

    def _poll(self):
        try:
            kind, data = self._result_queue.get_nowait()
        except queue.Empty:
            self._poll_id = self.after(POLL_MS, self._poll)
            return

        self._scanning = False
        self._scan_btn.configure(state="normal")

        if kind == "error":
            self._inline_error.configure(text=f"Error: {data}")
            self._status_lbl.configure(text="Analysis failed.")
        else:
            self._status_lbl.configure(text="Analysis complete.")
            self._show_result(data)

    # ── Results display ───────────────────────────────────────────────────────

    def _show_result(self, info: CertInfo):
        self._cert_placeholder.place_forget()

        # Clear previous content
        for w in self._cert_scroll.winfo_children():
            w.destroy()

        self._cert_scroll.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))

        # Badges row
        badge_row = ctk.CTkFrame(self._cert_scroll, fg_color="transparent")
        badge_row.grid(row=0, column=0, columnspan=2, sticky="w", padx=8, pady=(8, 4))
        self._render_badges(badge_row, info)

        # Separator
        ctk.CTkFrame(
            self._cert_scroll, height=1, fg_color=BORDER_COLOR, corner_radius=0,
        ).grid(row=1, column=0, columnspan=2, sticky="ew", padx=8, pady=(2, 8))

        # Field rows
        fields = [
            ("Subject CN",  info.subject_cn  or "—"),
            ("Subject Org", info.subject_org or "—"),
            ("Issuer CN",   info.issuer_cn   or "—"),
            ("Issuer Org",  info.issuer_org  or "—"),
            ("Valid From",  info.not_before.strftime("%Y-%m-%d %H:%M UTC")),
            ("Valid Until", info.not_after.strftime("%Y-%m-%d %H:%M UTC")),
            ("SANs",        ", ".join(info.san_list) if info.san_list else "—"),
            ("Serial",      info.serial      or "—"),
            ("Signature",   info.sig_alg     or "—"),
        ]
        for i, (label, value) in enumerate(fields):
            row = i + 2
            ctk.CTkLabel(
                self._cert_scroll, text=label,
                font=ctk.CTkFont(family="Segoe UI", size=12),
                text_color=TEXT_MUTED, anchor="e", width=110,
            ).grid(row=row, column=0, sticky="e", padx=(8, 10), pady=3)
            ctk.CTkLabel(
                self._cert_scroll, text=value,
                font=ctk.CTkFont(family="Segoe UI", size=12),
                text_color=TEXT_PRIMARY, anchor="w", wraplength=420, justify="left",
            ).grid(row=row, column=1, sticky="w", padx=(0, 8), pady=3)

    def _render_badges(self, parent: ctk.CTkFrame, info: CertInfo):
        col = 0
        if info.is_expired:
            _badge(parent, "✗  Expired",    CLR_ERROR, "#2a0a0a", col); col += 1
        if info.is_near_expiry:
            _badge(parent, "⚠  Near-expiry", CLR_WARN, "#1a1500", col); col += 1
        if info.is_self_signed:
            _badge(parent, "⚠  Self-signed", CLR_WARN, "#1a1500", col); col += 1
        if not info.is_expired and not info.is_near_expiry:
            _badge(parent, "✔  Valid",       CLR_OK,   "#0d2818", col)


def _badge(parent, text, fg, bg, col):
    ctk.CTkLabel(
        parent, text=text,
        font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
        text_color=fg, fg_color=bg, corner_radius=4,
        padx=8, pady=3,
    ).grid(row=0, column=col, padx=(0, 6), sticky="w")
