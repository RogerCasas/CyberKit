"""
CyberKit — CSRF Analyser Page (posture inspection, detection only)
"""

import queue
import threading
import tkinter as tk
from tkinter import ttk

import customtkinter as ctk
from app.ui.scrollable import autohide_vsb

from app.modules.csrf_analyser import CSRFFinding, analyse as csrf_analyse

# ── Palette ───────────────────────────────────────────────────────────────────
BG_MAIN        = "#0f1117"
BG_CARD        = "#161b22"
BG_INPUT       = "#0d1117"
BG_TABLE_ROW   = "#161b22"
BG_TABLE_ALT   = "#0f1117"
ACCENT_CYAN    = "#00d4ff"
TEXT_PRIMARY   = "#e6edf3"
TEXT_MUTED     = "#8b949e"
TEXT_DIM       = "#484f58"
BORDER_COLOR   = "#21262d"
CLR_OK         = "#22c55e"
CLR_INFO       = "#00d4ff"
CLR_WARN       = "#f0a500"
CLR_HIGH       = "#ef4444"
WARNING_BG     = "#1a1500"
WARNING_BORDER = "#f0a500"
WARNING_TEXT   = "#f0a500"

POLL_MS = 100

_SEV_COLOR = {"ok": CLR_OK, "info": CLR_INFO, "warn": CLR_WARN, "high": CLR_HIGH}
_SEV_LABEL = {"ok": "OK", "info": "INFO", "warn": "WARN", "high": "HIGH"}


class CsrfAnalyserPage(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, corner_radius=0, **kwargs)
        self._result_queue: queue.Queue = queue.Queue()
        self._running = False
        self._poll_id = None
        self._row_count = 0
        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=30, pady=(28, 0))
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            hdr, text="🎫  CSRF Analyser",
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            hdr,
            text="Inspect CSRF posture  •  SameSite cookies, anti-CSRF tokens, Origin/Referer validation",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        banner = ctk.CTkFrame(self, fg_color=WARNING_BG, corner_radius=8,
                              border_width=1, border_color=WARNING_BORDER)
        banner.grid(row=1, column=0, sticky="ew", padx=30, pady=(16, 0))
        banner.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(banner, text="⚠", font=ctk.CTkFont(size=14),
                     text_color=WARNING_TEXT).grid(row=0, column=0, padx=(14, 8), pady=10)
        ctk.CTkLabel(
            banner,
            text="Only test systems you own or have explicit permission to test.",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=WARNING_TEXT, anchor="w",
        ).grid(row=0, column=1, sticky="w", padx=(0, 14), pady=10)

        self._build_controls()
        self._build_table()

    def _build_controls(self):
        ctrl = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=12,
                            border_width=1, border_color=BORDER_COLOR)
        ctrl.grid(row=2, column=0, sticky="ew", padx=30, pady=(14, 0))
        ctrl.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            ctrl, text="Target URL",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=0, column=0, columnspan=2, padx=18, pady=(14, 4), sticky="w")

        self._inline_error = ctk.CTkLabel(
            ctrl, text="",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=CLR_HIGH, anchor="w",
        )
        self._inline_error.grid(row=0, column=1, sticky="e", padx=(0, 18), pady=(14, 4))

        self._url_entry = ctk.CTkEntry(
            ctrl,
            placeholder_text="http://localhost/login",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, height=38,
        )
        self._url_entry.grid(row=1, column=0, sticky="ew", padx=(18, 8), pady=(0, 14))
        self._url_entry.bind("<Return>", lambda e: self._start_scan())

        self._scan_btn = ctk.CTkButton(
            ctrl, text="▶  Analyse",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color="#0f1117", height=38, width=130, corner_radius=8,
            command=self._start_scan,
        )
        self._scan_btn.grid(row=1, column=1, padx=(0, 18), pady=(0, 14))

        self._status_lbl = ctk.CTkLabel(
            ctrl, text="Enter a URL and click Analyse.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_MUTED, anchor="w",
        )
        self._status_lbl.grid(row=2, column=0, columnspan=2, sticky="w",
                              padx=18, pady=(0, 12))

    def _build_table(self):
        wrapper = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=12,
                               border_width=1, border_color=BORDER_COLOR)
        wrapper.grid(row=3, column=0, sticky="nsew", padx=30, pady=(14, 30))
        wrapper.grid_columnconfigure(0, weight=1)
        wrapper.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            wrapper, text="Findings",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(12, 8))

        style = ttk.Style()
        style.configure("Csrf.Treeview",
            background=BG_TABLE_ROW, foreground=TEXT_PRIMARY,
            fieldbackground=BG_TABLE_ROW, rowheight=34,
            borderwidth=0, relief="flat", font=("Segoe UI", 11))
        style.configure("Csrf.Treeview.Heading",
            background=BG_INPUT, foreground=TEXT_MUTED,
            borderwidth=0, relief="flat", font=("Segoe UI", 11, "bold"))
        style.map("Csrf.Treeview",
            background=[("selected", "#1a2332")],
            foreground=[("selected", TEXT_PRIMARY)])
        style.map("Csrf.Treeview.Heading",
            background=[("active", BG_CARD), ("pressed", BG_INPUT)],
            relief=[("active", "flat"), ("pressed", "flat")])
        style.configure("Csrf.Vertical.TScrollbar",
            background=BORDER_COLOR, troughcolor=BG_CARD,
            arrowcolor=TEXT_MUTED, borderwidth=0, relief="flat")
        style.map("Csrf.Vertical.TScrollbar", background=[("active", TEXT_MUTED)])

        tree_frame = tk.Frame(wrapper, bg=BG_CARD)
        tree_frame.grid(row=1, column=0, sticky="nsew")
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical",
                            style="Csrf.Vertical.TScrollbar")
        vsb.grid(row=0, column=1, sticky="ns")

        self._tree = ttk.Treeview(
            tree_frame,
            columns=("severity", "check", "detail"),
            show="headings", style="Csrf.Treeview",
            yscrollcommand=autohide_vsb(vsb), height=1,
        )
        vsb.configure(command=self._tree.yview)
        self._tree.grid(row=0, column=0, sticky="nsew")

        for col, head, w, anc, stretch, mw in [
            ("severity", "Severity", 90,  "center", False, 70),
            ("check",    "Check",    230, "w",      False, 140),
            ("detail",   "Detail",   420, "w",      True,  200),
        ]:
            self._tree.heading(col, text=head, anchor=anc)
            self._tree.column(col, width=w, anchor=anc, stretch=stretch, minwidth=mw)

        for sev, color in _SEV_COLOR.items():
            self._tree.tag_configure(f"sev_{sev}", foreground=color)
        self._tree.tag_configure("row_even", background=BG_TABLE_ROW)
        self._tree.tag_configure("row_odd",  background=BG_TABLE_ALT)

        self._empty_label = ctk.CTkLabel(
            tree_frame, text="Analyse a URL to see CSRF findings.",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=TEXT_DIM, fg_color="transparent",
        )
        self._empty_label.place(relx=0.5, rely=0.5, anchor="center")

    # ── Scan ──────────────────────────────────────────────────────────────────

    def _start_scan(self):
        if self._running:
            return
        self._inline_error.configure(text="")
        url = self._url_entry.get().strip()
        if not url:
            self._inline_error.configure(text="Please enter a target URL.")
            return
        if not url.startswith(("http://", "https://")):
            url = "http://" + url

        self._running = True
        self._result_queue = queue.Queue()
        self._row_count = 0
        self._tree.delete(*self._tree.get_children())
        self._empty_label.place_forget()

        self._scan_btn.configure(state="disabled")
        self._status_lbl.configure(text=f"Analysing {url}…", text_color=TEXT_MUTED)

        threading.Thread(target=self._run_scan, args=(url,), daemon=True).start()
        self._poll_id = self.after(POLL_MS, self._poll)

    def _run_scan(self, url):
        try:
            findings = csrf_analyse(url, timeout=10)
            self._result_queue.put(("done", findings))
        except Exception as exc:
            self._result_queue.put(("error", str(exc)))

    def _poll(self):
        try:
            msg = self._result_queue.get_nowait()
        except queue.Empty:
            self._poll_id = self.after(POLL_MS, self._poll)
            return

        kind = msg[0]
        if kind == "done":
            for f in msg[1]:
                self._insert_row(f)
            self._finish_scan(msg[1])
        elif kind == "error":
            self._inline_error.configure(text=f"Error: {msg[1]}")
            self._running = False
            self._scan_btn.configure(state="normal")
            self._status_lbl.configure(text="Analysis failed.", text_color=CLR_HIGH)

    def _insert_row(self, f: CSRFFinding):
        alt = "row_even" if self._row_count % 2 == 0 else "row_odd"
        sev = f.severity if f.severity in _SEV_COLOR else "info"
        self._tree.insert(
            "", "end",
            values=(_SEV_LABEL.get(sev, sev.upper()), f.check, f.detail),
            tags=(f"sev_{sev}", alt),
        )
        self._row_count += 1

    def _finish_scan(self, findings):
        self._running = False
        self._scan_btn.configure(state="normal")
        highs = sum(1 for f in findings if f.severity == "high")
        warns = sum(1 for f in findings if f.severity == "warn")
        if highs or warns:
            self._status_lbl.configure(
                text=f"Done — {highs} high, {warns} warning(s) across {len(findings)} check(s)",
                text_color=CLR_HIGH if highs else CLR_WARN)
        else:
            self._status_lbl.configure(
                text=f"Done — no CSRF weaknesses flagged across {len(findings)} check(s)",
                text_color=CLR_OK)
