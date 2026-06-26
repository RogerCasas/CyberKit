"""
CyberKit — Tech Fingerprinter Page
"""

import queue
import threading
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, ttk

import customtkinter as ctk

from app.modules.tech_fingerprinter import TechFingerprintEngine, FingerprintResult

# ── Palette ───────────────────────────────────────────────────────────────────
BG_MAIN      = "#0f1117"
BG_CARD      = "#161b22"
BG_INPUT     = "#0d1117"
BG_TABLE_ROW = "#161b22"
BG_TABLE_ALT = "#0f1117"
ACCENT_CYAN  = "#00d4ff"
TEXT_PRIMARY = "#e6edf3"
TEXT_MUTED   = "#8b949e"
TEXT_DIM     = "#484f58"
BORDER_COLOR = "#21262d"
CLR_ERROR    = "#ef4444"
CLR_OK       = "#22c55e"

WARNING_BG     = "#1a1500"
WARNING_BORDER = "#f0a500"
WARNING_TEXT   = "#f0a500"

POLL_MS     = 100
BATCH_LIMIT = 40

_CATEGORY_COLORS = {
    "CMS":                "#7c3aed",
    "Server":             "#00d4ff",
    "Language / Runtime": "#f59e0b",
    "Framework":          "#22c55e",
    "Frontend Library":   "#ec4899",
    "CDN / Security":     "#ef4444",
    "Cloud Storage":      "#6b7280",
}


class TechFingerprinterPage(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, corner_radius=0, **kwargs)

        self._engine: TechFingerprintEngine | None = None
        self._result_queue: queue.Queue = queue.Queue()
        self._stop_event:   threading.Event = threading.Event()
        self._results: list[FingerprintResult] = []
        self._running  = False
        self._poll_id  = None
        self._row_count = 0

        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        # Header
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=30, pady=(28, 0))
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            hdr, text="🖥  Tech Fingerprinter",
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            hdr,
            text="Detect CMS, server software, frameworks, and CDNs from HTTP response signatures",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        # Disclaimer
        banner = ctk.CTkFrame(self, fg_color=WARNING_BG, corner_radius=8,
                              border_width=1, border_color=WARNING_BORDER)
        banner.grid(row=1, column=0, sticky="ew", padx=30, pady=(16, 0))
        banner.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(banner, text="⚠", font=ctk.CTkFont(size=14),
                     text_color=WARNING_TEXT).grid(
            row=0, column=0, padx=(14, 8), pady=10)
        ctk.CTkLabel(
            banner,
            text="Only fingerprint websites you own or have explicit permission to test.",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=WARNING_TEXT, anchor="w",
        ).grid(row=0, column=1, sticky="w", padx=(0, 14), pady=10)

        self._build_controls()
        self._build_table()

    def _build_controls(self):
        ctrl = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=12,
                            border_width=1, border_color=BORDER_COLOR)
        ctrl.grid(row=2, column=0, sticky="ew", padx=30, pady=(16, 0))
        ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(ctrl, text="Target URL",
                     font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                     text_color=TEXT_MUTED).grid(
            row=0, column=0, padx=(18, 10), pady=(14, 4), sticky="w")

        self._inline_error = ctk.CTkLabel(
            ctrl, text="",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=CLR_ERROR, anchor="w",
        )
        self._inline_error.grid(row=0, column=1, sticky="w", padx=(0, 18), pady=(14, 4))

        self._url_entry = ctk.CTkEntry(
            ctrl,
            placeholder_text="https://example.com",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, height=38,
        )
        self._url_entry.grid(row=1, column=0, columnspan=2, sticky="ew",
                             padx=18, pady=(0, 6))
        self._url_entry.bind("<Return>", lambda e: self._start_scan())

        btn_row = ctk.CTkFrame(ctrl, fg_color="transparent")
        btn_row.grid(row=2, column=0, columnspan=2, sticky="w",
                     padx=18, pady=(0, 14))

        self._start_btn = ctk.CTkButton(
            btn_row, text="▶  Scan",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color="#0f1117", height=36, width=110, corner_radius=8,
            command=self._start_scan,
        )
        self._start_btn.grid(row=0, column=0, padx=(0, 8))

        self._stop_btn = ctk.CTkButton(
            btn_row, text="■  Stop",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=BG_INPUT, hover_color=BG_CARD,
            border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, height=36, width=110, corner_radius=8,
            state="disabled", command=self._stop_scan,
        )
        self._stop_btn.grid(row=0, column=1, padx=(0, 18))

        self._status_label = ctk.CTkLabel(
            btn_row, text="Enter a URL and click Scan.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_MUTED, anchor="w",
        )
        self._status_label.grid(row=0, column=2, padx=(4, 0))

    def _build_table(self):
        wrapper = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=12,
                               border_width=1, border_color=BORDER_COLOR)
        wrapper.grid(row=3, column=0, sticky="nsew", padx=30, pady=(16, 30))
        wrapper.grid_columnconfigure(0, weight=1)
        wrapper.grid_rowconfigure(1, weight=1)

        top = ctk.CTkFrame(wrapper, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 8))
        top.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(top, text="Detected Technologies",
                     font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                     text_color=TEXT_MUTED, anchor="w",
        ).grid(row=0, column=0, sticky="w")

        ctk.CTkButton(
            top, text="⬇ TXT", width=70, height=28, corner_radius=6,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, hover_color=BG_INPUT,
            font=ctk.CTkFont(family="Segoe UI", size=11),
            command=self._export_txt,
        ).grid(row=0, column=1)

        style = ttk.Style()
        style.configure("FP.Treeview",
            background=BG_TABLE_ROW, foreground=TEXT_PRIMARY,
            fieldbackground=BG_TABLE_ROW, rowheight=34, borderwidth=0,
            relief="flat", font=("Segoe UI", 11),
        )
        style.configure("FP.Treeview.Heading",
            background=BG_INPUT, foreground=TEXT_MUTED,
            borderwidth=0, relief="flat", font=("Segoe UI", 11, "bold"),
        )
        style.map("FP.Treeview",
            background=[("selected", "#1a2332")],
            foreground=[("selected", TEXT_PRIMARY)],
        )
        style.map("FP.Treeview.Heading",
            background=[("active", BG_CARD), ("pressed", BG_INPUT)],
            relief=[("active", "flat"), ("pressed", "flat")],
        )
        style.configure("FP.Vertical.TScrollbar",
            background=BORDER_COLOR, troughcolor=BG_CARD,
            arrowcolor=TEXT_MUTED, borderwidth=0, relief="flat",
        )
        style.map("FP.Vertical.TScrollbar",
            background=[("active", TEXT_MUTED)],
        )

        tree_frame = tk.Frame(wrapper, bg=BG_CARD)
        tree_frame.grid(row=1, column=0, sticky="nsew")
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)
        wrapper.grid_rowconfigure(1, weight=1)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical",
                            style="FP.Vertical.TScrollbar")
        vsb.grid(row=0, column=1, sticky="ns")

        self._tree = ttk.Treeview(
            tree_frame,
            columns=("#", "category", "name", "evidence"),
            show="headings",
            style="FP.Treeview",
            yscrollcommand=vsb.set,
        )
        vsb.configure(command=self._tree.yview)
        self._tree.grid(row=0, column=0, sticky="nsew")

        self._tree.heading("#",        text="#",           anchor="center")
        self._tree.heading("category", text="Category",   anchor="w")
        self._tree.heading("name",     text="Technology", anchor="w")
        self._tree.heading("evidence", text="Evidence",   anchor="w")

        self._tree.column("#",        width=40,  anchor="center", stretch=False, minwidth=36)
        self._tree.column("category", width=160, anchor="w",      stretch=False, minwidth=120)
        self._tree.column("name",     width=180, anchor="w",      stretch=False, minwidth=130)
        self._tree.column("evidence", width=400, anchor="w",      stretch=True,  minwidth=200)

        self._tree.tag_configure("row_even", background=BG_TABLE_ROW)
        self._tree.tag_configure("row_odd",  background=BG_TABLE_ALT)

        self._empty_label = ctk.CTkLabel(
            tree_frame, text="Run a scan to see results.",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=TEXT_DIM, fg_color="transparent",
        )
        self._empty_label.place(relx=0.5, rely=0.5, anchor="center")

    # ── Scan logic ────────────────────────────────────────────────────────────

    def _set_status(self, msg: str, error: bool = False):
        if error:
            self._inline_error.configure(text=msg)
        else:
            self._inline_error.configure(text="")
            self._status_label.configure(text=msg, text_color=TEXT_MUTED)

    def _start_scan(self):
        self._inline_error.configure(text="")
        url = self._url_entry.get().strip()
        if not url:
            self._set_status("Please enter a target URL.", error=True)
            return

        self._results.clear()
        self._row_count = 0
        self._tree.delete(*self._tree.get_children())
        self._empty_label.place(relx=0.5, rely=0.5, anchor="center")

        self._running = True
        self._stop_event = threading.Event()
        self._result_queue = queue.Queue()

        self._start_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._set_status(f"Scanning {url}…")

        engine = TechFingerprintEngine(url, self._result_queue, self._stop_event)
        threading.Thread(target=engine.run, daemon=True).start()
        self._poll_id = self.after(POLL_MS, self._poll)

    def _stop_scan(self):
        self._stop_event.set()

    def _poll(self):
        try:
            batch = 0
            while batch < BATCH_LIMIT:
                item = self._result_queue.get_nowait()
                batch += 1
                kind = item[0]
                if kind == "result":
                    self._add_row(item[1])
                elif kind == "error":
                    self._set_status(f"Error: {item[1]}", error=True)
                    self._on_done()
                    return
                elif kind == "done":
                    found = item[1]
                    self._set_status(
                        f"Scan complete — {found} technolog{'y' if found == 1 else 'ies'} detected."
                    )
                    self._on_done()
                    return
        except queue.Empty:
            pass
        self._poll_id = self.after(POLL_MS, self._poll)

    def _add_row(self, r: FingerprintResult):
        self._results.append(r)
        self._row_count += 1
        self._empty_label.place_forget()
        tag = "row_even" if self._row_count % 2 == 0 else "row_odd"
        self._tree.insert(
            "", "end",
            values=(self._row_count, r.category, r.name, r.evidence),
            tags=(tag,),
        )

    def _on_done(self):
        self._running = False
        self._start_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")
        if not self._results:
            self._empty_label.configure(text="No technologies detected.")
            self._empty_label.place(relx=0.5, rely=0.5, anchor="center")

    # ── Export ────────────────────────────────────────────────────────────────

    def _export_txt(self):
        if not self._results:
            self._set_status("No results to export — run a scan first.", error=True)
            return
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
            initialfile=f"cyberkit_fingerprint_{ts}.txt",
            title="Export Fingerprint Results",
        )
        if not path:
            return
        try:
            url = self._url_entry.get().strip()
            with open(path, "w", encoding="utf-8") as f:
                f.write("CyberKit — Tech Fingerprinter Report\n")
                f.write(f"URL  : {url}\n")
                f.write(f"Date : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Found: {len(self._results)} technologies\n")
                f.write("=" * 70 + "\n\n")
                for r in self._results:
                    f.write(f"[{r.category}]  {r.name}\n")
                    f.write(f"   Evidence: {r.evidence}\n\n")
            self._set_status("Export saved successfully.")
        except OSError as e:
            self._set_status(f"Export failed: {e}", error=True)
