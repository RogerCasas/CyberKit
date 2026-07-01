"""
CyberKit — CVE / Vulnerability Lookup Page
"""

import queue
import threading
from tkinter import ttk

import customtkinter as ctk

from app.modules.cve_lookup import CveResult, search

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

POLL_MS = 120

_STYLE_INIT = False

# Row colours by severity
_SEV_FG = {
    "CRITICAL": "#ff6b6b",
    "HIGH":     "#ffa94d",
    "MEDIUM":   "#ffd43b",
    "LOW":      "#8b949e",
    "NONE":     "#484f58",
}
_SEV_TAG = {sev: sev.lower() for sev in _SEV_FG}


def _init_style():
    global _STYLE_INIT
    if _STYLE_INIT:
        return
    _STYLE_INIT = True
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("CVE.Treeview",
                    background="#161b22", fieldbackground="#161b22",
                    foreground="#e6edf3", rowheight=26,
                    borderwidth=0, relief="flat",
                    font=("Segoe UI", 11))
    style.configure("CVE.Treeview.Heading",
                    background="#12171e", foreground="#8b949e",
                    borderwidth=0, relief="flat",
                    font=("Segoe UI", 10, "bold"))
    style.map("CVE.Treeview",
              background=[("selected", "#1a2332")],
              foreground=[("selected", "#00d4ff")])


class CveLookupPage(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, corner_radius=0, **kwargs)
        _init_style()
        self._q:          queue.Queue    = queue.Queue()
        self._stop_event: threading.Event = threading.Event()
        self._running     = False
        self._poll_id     = None
        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        self.grid_columnconfigure(0, weight=1)

        # Header
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=30, pady=(28, 0))
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            hdr, text="🔎  CVE / Vulnerability Lookup",
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            hdr,
            text="Query the NIST NVD database by product and version to find known CVEs sorted by CVSS severity.",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED, anchor="w", wraplength=700,
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        # Input card
        input_card = ctk.CTkFrame(
            self, fg_color=BG_CARD, corner_radius=12,
            border_width=1, border_color=BORDER_COLOR,
        )
        input_card.grid(row=1, column=0, sticky="ew", padx=30, pady=(20, 0))
        input_card.grid_columnconfigure((1, 3), weight=1)

        ctk.CTkLabel(
            input_card, text="Product:",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED,
        ).grid(row=0, column=0, padx=(16, 6), pady=14)
        self._product_entry = ctk.CTkEntry(
            input_card,
            placeholder_text="e.g. Apache HTTP Server",
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            height=36,
        )
        self._product_entry.grid(row=0, column=1, sticky="ew", pady=14)
        self._product_entry.bind("<Return>", lambda _: self._start())

        ctk.CTkLabel(
            input_card, text="Version:",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED,
        ).grid(row=0, column=2, padx=(12, 6), pady=14)
        self._version_entry = ctk.CTkEntry(
            input_card,
            placeholder_text="e.g. 2.4.51",
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            height=36, width=120,
        )
        self._version_entry.grid(row=0, column=3, sticky="ew", pady=14)
        self._version_entry.bind("<Return>", lambda _: self._start())

        btn_row = ctk.CTkFrame(input_card, fg_color="transparent")
        btn_row.grid(row=0, column=4, padx=(8, 12), pady=14)
        self._search_btn = ctk.CTkButton(
            btn_row, text="Search",
            width=90, height=36, corner_radius=8,
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color=BG_MAIN, font=ctk.CTkFont(weight="bold"),
            command=self._start,
        )
        self._search_btn.pack(side="left", padx=(0, 6))
        self._stop_btn = ctk.CTkButton(
            btn_row, text="Stop",
            width=70, height=36, corner_radius=8,
            fg_color="transparent", hover_color=BG_INPUT,
            border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED,
            state="disabled",
            command=self._stop,
        )
        self._stop_btn.pack(side="left")

        # Hints row inside the input card (spans all columns)
        hints = ctk.CTkFrame(input_card, fg_color="transparent")
        hints.grid(row=1, column=0, columnspan=5, sticky="ew", padx=16, pady=(0, 10))
        ctk.CTkLabel(
            hints,
            text="ℹ  Rate limited to 1 req / 6 s without an API key.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_DIM, anchor="w",
        ).pack(side="left", padx=(0, 16))
        ctk.CTkLabel(
            hints,
            text="💡  No results? Try searching without the version number.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_DIM, anchor="w",
        ).pack(side="left")

        # Status
        self._status_lbl = ctk.CTkLabel(
            self, text="",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_MUTED,
        )
        self._status_lbl.grid(row=2, column=0, sticky="w", padx=30, pady=(6, 0))

        # Results card
        self._build_results_card(row=3)

    def _build_results_card(self, row: int):
        card = ctk.CTkFrame(
            self, fg_color=BG_CARD, corner_radius=12,
            border_width=1, border_color=BORDER_COLOR,
        )
        card.grid(row=row, column=0, sticky="ew", padx=30, pady=(16, 30))
        card.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(card, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 6))
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            hdr, text="CVE Results",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=0, column=0, sticky="w")
        self._count_lbl = ctk.CTkLabel(
            hdr, text="",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_DIM, anchor="e",
        )
        self._count_lbl.grid(row=0, column=1, sticky="e")

        cols = ("cve_id", "score", "severity", "published", "description")
        self._cve_tree = ttk.Treeview(
            card, style="CVE.Treeview",
            columns=cols, show="headings", height=16,
        )
        headings = {
            "cve_id": "CVE ID", "score": "CVSS",
            "severity": "Severity", "published": "Published",
            "description": "Description",
        }
        widths = {"cve_id": 130, "score": 60, "severity": 90, "published": 90, "description": 500}
        for col in cols:
            self._cve_tree.heading(col, text=headings[col])
            self._cve_tree.column(col, width=widths[col], anchor="w", minwidth=50)
        self._cve_tree.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 14))

        # Per-severity row tag colours
        for sev, fg in _SEV_FG.items():
            self._cve_tree.tag_configure(sev.lower(), foreground=fg)

    # ── Search logic ──────────────────────────────────────────────────────────

    def _start(self):
        product = self._product_entry.get().strip()
        version = self._version_entry.get().strip()
        if not product or self._running:
            return

        self._running = True
        self._search_btn.configure(state="disabled", text="Searching…")
        self._stop_btn.configure(state="normal")
        self._status_lbl.configure(text="Preparing query…", text_color=TEXT_MUTED)
        self._clear_results()
        self._stop_event.clear()

        threading.Thread(
            target=self._worker, args=(product, version), daemon=True,
        ).start()
        self._poll()

    def _stop(self):
        self._stop_event.set()

    def _worker(self, product: str, version: str):
        def on_progress(msg: str):
            self._q.put(("status", msg))

        result = search(product, version, self._stop_event, on_progress=on_progress)
        self._q.put(("result", result))

    def _poll(self):
        try:
            while True:
                tag, data = self._q.get_nowait()
                if tag == "status":
                    self._status_lbl.configure(text=data, text_color=TEXT_MUTED)
                elif tag == "result":
                    self._populate(data)
                    self._on_done()
                    return
        except queue.Empty:
            pass
        self._poll_id = self.after(POLL_MS, self._poll)

    def _on_done(self):
        self._running = False
        self._search_btn.configure(state="normal", text="Search")
        self._stop_btn.configure(state="disabled")

    # ── Population ────────────────────────────────────────────────────────────

    def _clear_results(self):
        for item in self._cve_tree.get_children():
            self._cve_tree.delete(item)
        self._count_lbl.configure(text="")

    def _populate(self, result: CveResult):
        if result.error == "Stopped":
            self._status_lbl.configure(text="Stopped.", text_color=TEXT_MUTED)
            return
        if result.error:
            self._status_lbl.configure(
                text=f"Error: {result.error}", text_color=CLR_ERROR,
            )
            return

        self._status_lbl.configure(
            text=f"Done — {len(result.entries)} results shown.",
            text_color=CLR_OK,
        )

        shown = len(result.entries)
        total = result.total_results
        label = f"Showing {shown} of {total} results"
        self._count_lbl.configure(text=label)

        for entry in result.entries:
            score_str = f"{entry.cvss_score:.1f}" if entry.cvss_score else "N/A"
            tag       = _SEV_TAG.get(entry.severity, "none")
            desc      = entry.description[:120] + "…" if len(entry.description) > 120 else entry.description
            self._cve_tree.insert("", "end",
                values=(entry.cve_id, score_str, entry.severity, entry.published, desc),
                tags=(tag,),
            )
