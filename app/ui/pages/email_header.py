"""
CyberKit — Email Header Analyser Page
"""

import tkinter as tk
from tkinter import ttk

import customtkinter as ctk

from app.modules.email_header import HeaderSummary, parse

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
CLR_ERROR    = "#ef4444"
CLR_WARN     = "#f0a500"
CLR_UNKNOWN  = "#484f58"

# Treeview style
_STYLE_INIT = False


def _init_treeview_style():
    global _STYLE_INIT
    if _STYLE_INIT:
        return
    _STYLE_INIT = True
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Hops.Treeview",
                    background="#161b22", fieldbackground="#161b22",
                    foreground="#e6edf3", rowheight=26,
                    borderwidth=0, relief="flat",
                    font=("Segoe UI", 11))
    style.configure("Hops.Treeview.Heading",
                    background="#12171e", foreground="#8b949e",
                    borderwidth=0, relief="flat",
                    font=("Segoe UI", 10, "bold"))
    style.map("Hops.Treeview",
              background=[("selected", "#1a2332")],
              foreground=[("selected", "#00d4ff")])


class EmailHeaderPage(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, corner_radius=0, **kwargs)
        _init_treeview_style()
        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        self.grid_columnconfigure(0, weight=1)

        # Header
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=30, pady=(28, 0))
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            hdr, text="📧  Email Header Analyser",
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            hdr,
            text="Paste raw email headers to reconstruct relay hops, evaluate SPF/DKIM/DMARC, and surface suspicious patterns.",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED, anchor="w", wraplength=700,
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        # Input card
        input_card = self._card(row=1)
        input_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            input_card, text="Raw Email Header",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 4))

        self._paste_box = ctk.CTkTextbox(
            input_card,
            height=180,
            fg_color=BG_INPUT,
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(family="Consolas", size=11),
            border_width=1, border_color=BORDER_COLOR,
            corner_radius=8,
            wrap="none",
        )
        self._paste_box.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 4))

        btn_row = ctk.CTkFrame(input_card, fg_color="transparent")
        btn_row.grid(row=2, column=0, sticky="e", padx=16, pady=(4, 14))
        ctk.CTkButton(
            btn_row, text="Clear",
            width=80, height=32, corner_radius=8,
            fg_color="transparent", hover_color=BG_INPUT,
            border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED,
            command=self._clear,
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            btn_row, text="Analyse",
            width=110, height=32, corner_radius=8,
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color=BG_MAIN, font=ctk.CTkFont(weight="bold"),
            command=self._analyse,
        ).pack(side="left")

        # Summary card
        self._build_summary_card(row=2)

        # Auth card
        self._build_auth_card(row=3)

        # Hops card
        self._build_hops_card(row=4)

        # Flags card
        self._build_flags_card(row=5)

    def _card(self, row: int, title: str = "") -> ctk.CTkFrame:
        card = ctk.CTkFrame(
            self, fg_color=BG_CARD, corner_radius=12,
            border_width=1, border_color=BORDER_COLOR,
        )
        card.grid(row=row, column=0, sticky="ew", padx=30, pady=(16, 0))
        card.grid_columnconfigure(0, weight=1)
        if title:
            ctk.CTkLabel(
                card, text=title,
                font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                text_color=TEXT_MUTED, anchor="w",
            ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 6))
        return card

    def _build_summary_card(self, row: int):
        card = self._card(row=row, title="Message Summary")
        fields = [("From", "from_"), ("To", "to"), ("Subject", "subject"),
                  ("Date", "date"), ("Message-ID", "message_id"), ("Mailer", "mailer")]
        self._summary_labels: dict[str, ctk.CTkLabel] = {}
        for i, (label, key) in enumerate(fields):
            ctk.CTkLabel(
                card, text=f"{label}:",
                font=ctk.CTkFont(family="Segoe UI", size=11),
                text_color=TEXT_MUTED, anchor="w", width=90,
            ).grid(row=i + 1, column=0, sticky="w", padx=(16, 4), pady=3)
            val_lbl = ctk.CTkLabel(
                card, text="—",
                font=ctk.CTkFont(family="Segoe UI", size=11),
                text_color=TEXT_PRIMARY, anchor="w",
            )
            val_lbl.grid(row=i + 1, column=1, sticky="w", padx=(4, 16), pady=3)
            self._summary_labels[key] = val_lbl
        card.grid_columnconfigure(1, weight=1)
        ctk.CTkFrame(card, height=1, fg_color="transparent").grid(
            row=len(fields) + 1, column=0, pady=(0, 8))

    def _build_auth_card(self, row: int):
        card = self._card(row=row, title="Authentication Results")
        card.grid_columnconfigure((0, 1, 2), weight=1)
        self._auth_frames: dict[str, ctk.CTkFrame] = {}
        self._auth_labels: dict[str, ctk.CTkLabel] = {}
        for col, name in enumerate(["SPF", "DKIM", "DMARC"]):
            frame = ctk.CTkFrame(card, fg_color=BG_INPUT, corner_radius=8)
            frame.grid(row=1, column=col, padx=8, pady=(0, 14), sticky="ew")
            ctk.CTkLabel(
                frame, text=name,
                font=ctk.CTkFont(family="Segoe UI", size=10, weight="bold"),
                text_color=TEXT_DIM,
            ).pack(pady=(10, 2))
            lbl = ctk.CTkLabel(
                frame, text="—",
                font=ctk.CTkFont(family="Segoe UI", size=14, weight="bold"),
                text_color=CLR_UNKNOWN,
            )
            lbl.pack(pady=(0, 10))
            self._auth_frames[name.lower()] = frame
            self._auth_labels[name.lower()] = lbl

    def _build_hops_card(self, row: int):
        card = self._card(row=row, title="Relay Hops  (oldest → newest)")

        cols = ("hop", "from_", "by", "ip", "timestamp", "delta")
        self._hops_tree = ttk.Treeview(
            card, style="Hops.Treeview",
            columns=cols, show="headings", height=6,
        )
        headings = {"hop": "#", "from_": "From", "by": "By (Receiver)",
                    "ip": "IP", "timestamp": "Timestamp", "delta": "Δ"}
        widths   = {"hop": 40, "from_": 180, "by": 180, "ip": 110, "timestamp": 200, "delta": 70}
        for col in cols:
            self._hops_tree.heading(col, text=headings[col])
            self._hops_tree.column(col, width=widths[col], anchor="w", minwidth=40)

        self._hops_tree.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 14))
        card.grid_columnconfigure(0, weight=1)

    def _build_flags_card(self, row: int):
        card = self._card(row=row, title="Findings & Warnings")
        self._flags_inner = ctk.CTkFrame(card, fg_color="transparent")
        self._flags_inner.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 14))
        self._flags_inner.grid_columnconfigure(0, weight=1)
        self._no_flags_lbl = ctk.CTkLabel(
            self._flags_inner, text="No issues detected.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=CLR_OK,
        )
        self._no_flags_lbl.grid(row=0, column=0, sticky="w")

    # ── Actions ───────────────────────────────────────────────────────────────

    def _analyse(self):
        raw = self._paste_box.get("1.0", "end-1c").strip()
        if not raw:
            return
        result = parse(raw)
        self._populate(result)

    def _clear(self):
        self._paste_box.delete("1.0", "end")
        for key, lbl in self._summary_labels.items():
            lbl.configure(text="—")
        for name in ["spf", "dkim", "dmarc"]:
            self._auth_labels[name].configure(text="—", text_color=CLR_UNKNOWN)
            self._auth_frames[name].configure(fg_color=BG_INPUT)
        for item in self._hops_tree.get_children():
            self._hops_tree.delete(item)
        for w in self._flags_inner.winfo_children():
            w.destroy()
        self._no_flags_lbl = ctk.CTkLabel(
            self._flags_inner, text="No issues detected.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=CLR_OK,
        )
        self._no_flags_lbl.grid(row=0, column=0, sticky="w")

    def _populate(self, result: HeaderSummary):
        # Summary
        mapping = {
            "from_": result.from_, "to": result.to, "subject": result.subject,
            "date": result.date, "message_id": result.message_id, "mailer": result.mailer,
        }
        for key, value in mapping.items():
            self._summary_labels[key].configure(text=value or "—")

        # Auth
        _COLOR = {"pass": CLR_OK, "fail": CLR_ERROR, "softfail": CLR_WARN,
                  "permerror": CLR_ERROR, "temperror": CLR_WARN,
                  "none": CLR_WARN, "neutral": TEXT_MUTED, "unknown": CLR_UNKNOWN}
        _BG    = {"pass": "#0d2818", "fail": "#2a0d0d", "softfail": "#1a1200",
                  "permerror": "#2a0d0d", "temperror": "#1a1200",
                  "none": "#1a1200", "neutral": BG_INPUT, "unknown": BG_INPUT}
        for name in ["spf", "dkim", "dmarc"]:
            val   = getattr(result.auth, name)
            color = _COLOR.get(val, CLR_UNKNOWN)
            bg    = _BG.get(val, BG_INPUT)
            self._auth_labels[name].configure(text=val.upper(), text_color=color)
            self._auth_frames[name].configure(fg_color=bg)

        # Hops
        for item in self._hops_tree.get_children():
            self._hops_tree.delete(item)
        for hop in result.hops:
            delta_str = f"{hop.delta_s}s" if hop.delta_s is not None else "—"
            self._hops_tree.insert("", "end", values=(
                hop.index, hop.from_ or "—", hop.by or "—",
                hop.ip or "—", hop.timestamp or "—", delta_str,
            ))

        # Flags
        for w in self._flags_inner.winfo_children():
            w.destroy()
        if not result.flags:
            ctk.CTkLabel(
                self._flags_inner, text="✓  No issues detected.",
                font=ctk.CTkFont(family="Segoe UI", size=11),
                text_color=CLR_OK,
            ).grid(row=0, column=0, sticky="w")
        else:
            for i, flag in enumerate(result.flags):
                color = CLR_ERROR if ("fail" in flag.lower() or "spoofing" in flag.lower()) else CLR_WARN
                ctk.CTkLabel(
                    self._flags_inner,
                    text=f"⚠  {flag}",
                    font=ctk.CTkFont(family="Segoe UI", size=11),
                    text_color=color, anchor="w", wraplength=700,
                ).grid(row=i, column=0, sticky="w", pady=2)
