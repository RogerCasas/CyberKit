"""
CyberKit — Port Scanner Page
"""

import csv
import queue
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

from app.data.port_lists import TOP_1000_PORTS
from app.modules.port_scanner import (
    PortScanEngine,
    PortResult,
    ScanSummary,
    STATUS_OPEN,
    STATUS_CLOSED,
    STATUS_FILTERED,
    STATUS_ERROR,
)

# ── Palette ───────────────────────────────────────────────────────────────────
BG_MAIN       = "#0f1117"
BG_CARD       = "#161b22"
BG_INPUT      = "#0d1117"
BG_TABLE_ROW  = "#161b22"
BG_TABLE_ALT  = "#0f1117"
ACCENT_CYAN   = "#00d4ff"
TEXT_PRIMARY  = "#e6edf3"
TEXT_MUTED    = "#8b949e"
TEXT_DIM      = "#484f58"
BORDER_COLOR  = "#21262d"

CLR_OPEN      = "#22c55e"
CLR_FILTERED  = "#f59e0b"
CLR_CLOSED    = "#6b7280"
CLR_ERROR     = "#ef4444"

STATUS_META = {
    STATUS_OPEN:     {"label": "Open",     "color": CLR_OPEN},
    STATUS_FILTERED: {"label": "Filtered", "color": CLR_FILTERED},
    STATUS_CLOSED:   {"label": "Closed",   "color": CLR_CLOSED},
    STATUS_ERROR:    {"label": "Error",    "color": CLR_ERROR},
}
STATUS_TAG = {
    STATUS_OPEN:     "st_open",
    STATUS_FILTERED: "st_filtered",
    STATUS_CLOSED:   "st_closed",
    STATUS_ERROR:    "st_error",
}

POLL_MS     = 80
BATCH_LIMIT = 60
FILTER_OPTIONS = ["All", "Open", "Filtered", "Closed", "Error"]


class PortScannerPage(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, corner_radius=0, **kwargs)

        self._engine: PortScanEngine | None = None
        self._result_queue: queue.Queue[PortResult] = queue.Queue()
        self._all_results: list[PortResult] = []
        self._scan_running = False
        self._poll_id = None
        self._tree_row_count = 0

        # Summary counters
        self._total    = tk.IntVar(value=0)
        self._n_open   = tk.IntVar(value=0)
        self._n_filt   = tk.IntVar(value=0)
        self._n_closed = tk.IntVar(value=0)
        self._n_errors = tk.IntVar(value=0)
        self._scanned  = tk.IntVar(value=0)

        # Filter state
        self._filter_cat = tk.StringVar(value="All")
        self._filter_cat.trace_add("write", lambda *_: self._apply_filter())
        self._show_closed = tk.BooleanVar(value=False)
        self._show_closed.trace_add("write", lambda *_: self._apply_filter())

        # Scan mode
        self._mode = tk.StringVar(value="Top 1000")

        self._build()

    # ── Build UI ──────────────────────────────────────────────────────────────

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=30, pady=(28, 0))
        hdr.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            hdr,
            text="🔍  Port Scanner",
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(
            hdr,
            text="TCP connect scan  •  Top 1000 ports or custom range  •  Optional banner grab",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        self._build_controls()
        self._build_summary()
        self._build_table()

    def _build_controls(self):
        ctrl = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=12,
                            border_width=1, border_color=BORDER_COLOR)
        ctrl.grid(row=1, column=0, sticky="ew", padx=30, pady=(20, 0))
        ctrl.grid_columnconfigure(1, weight=1)

        # Host entry
        ctk.CTkLabel(ctrl, text="Target Host",
                     font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                     text_color=TEXT_MUTED).grid(
            row=0, column=0, padx=(18, 10), pady=(16, 4), sticky="w")

        self._host_entry = ctk.CTkEntry(
            ctrl,
            placeholder_text="192.168.1.1 or hostname",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, height=38,
        )
        self._host_entry.grid(row=1, column=0, columnspan=3, sticky="ew",
                              padx=18, pady=(0, 6))

        # Disclaimer
        ctk.CTkLabel(
            ctrl,
            text="⚠  Only scan hosts you own or have explicit permission to test.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color="#f0a500", anchor="w",
        ).grid(row=2, column=0, columnspan=3, sticky="w", padx=18, pady=(0, 8))

        # Mode selector
        mode_frame = ctk.CTkFrame(ctrl, fg_color="transparent")
        mode_frame.grid(row=3, column=0, columnspan=3, sticky="w", padx=18, pady=(0, 6))

        ctk.CTkLabel(mode_frame, text="Scan Mode:",
                     font=ctk.CTkFont(family="Segoe UI", size=12),
                     text_color=TEXT_MUTED).grid(row=0, column=0, padx=(0, 10))

        self._mode_btn = ctk.CTkSegmentedButton(
            mode_frame,
            values=["Top 1000", "Custom Range"],
            variable=self._mode,
            command=self._on_mode_change,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            selected_color=ACCENT_CYAN, selected_hover_color="#00aacc",
            unselected_color=BG_INPUT, unselected_hover_color=BG_CARD,
            text_color="#0f1117", fg_color=BG_INPUT,
        )
        self._mode_btn.grid(row=0, column=1)

        # Custom range inputs (hidden by default)
        self._range_frame = ctk.CTkFrame(ctrl, fg_color="transparent")
        self._range_frame.grid(row=4, column=0, columnspan=3, sticky="w",
                               padx=18, pady=(0, 6))

        ctk.CTkLabel(self._range_frame, text="From port:",
                     font=ctk.CTkFont(family="Segoe UI", size=12),
                     text_color=TEXT_MUTED).grid(row=0, column=0, padx=(0, 6))

        self._from_entry = ctk.CTkEntry(
            self._range_frame, width=80, height=32,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, placeholder_text="1",
        )
        self._from_entry.grid(row=0, column=1, padx=(0, 12))

        ctk.CTkLabel(self._range_frame, text="To port:",
                     font=ctk.CTkFont(family="Segoe UI", size=12),
                     text_color=TEXT_MUTED).grid(row=0, column=2, padx=(0, 6))

        self._to_entry = ctk.CTkEntry(
            self._range_frame, width=80, height=32,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, placeholder_text="1024",
        )
        self._to_entry.grid(row=0, column=3)

        self._range_frame.grid_remove()  # hidden until Custom Range selected

        # Options row: banner + threads + timeout + start button
        opts = ctk.CTkFrame(ctrl, fg_color="transparent")
        opts.grid(row=5, column=0, columnspan=3, sticky="ew", padx=18, pady=(4, 6))

        self._banner_var = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            opts, text="Banner grab",
            variable=self._banner_var,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED,
            checkmark_color="#0f1117",
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
        ).grid(row=0, column=0, padx=(0, 20))

        ctk.CTkLabel(opts, text="Threads:",
                     font=ctk.CTkFont(family="Segoe UI", size=12),
                     text_color=TEXT_MUTED).grid(row=0, column=1, padx=(0, 6))

        self._thread_val = ctk.CTkLabel(opts, text="100",
                                        font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                                        text_color=ACCENT_CYAN, width=36)
        self._thread_val.grid(row=0, column=2, padx=(0, 4))

        self._thread_slider = ctk.CTkSlider(
            opts, from_=10, to=200, number_of_steps=19, width=130,
            button_color=ACCENT_CYAN, progress_color=ACCENT_CYAN,
            command=self._on_thread_slider,
        )
        self._thread_slider.set(100)
        self._thread_slider.grid(row=0, column=3, padx=(0, 20))

        ctk.CTkLabel(opts, text="Timeout:",
                     font=ctk.CTkFont(family="Segoe UI", size=12),
                     text_color=TEXT_MUTED).grid(row=0, column=4, padx=(0, 6))

        self._timeout_val = ctk.CTkLabel(opts, text="1.0 s",
                                         font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                                         text_color=ACCENT_CYAN, width=44)
        self._timeout_val.grid(row=0, column=5, padx=(0, 4))

        self._timeout_slider = ctk.CTkSlider(
            opts, from_=0.5, to=3.0, number_of_steps=5, width=130,
            button_color=ACCENT_CYAN, progress_color=ACCENT_CYAN,
            command=self._on_timeout_slider,
        )
        self._timeout_slider.set(1.0)
        self._timeout_slider.grid(row=0, column=6, padx=(0, 20))

        self._start_btn = ctk.CTkButton(
            opts,
            text="▶  Start Scan",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color="#0f1117", height=38, width=140, corner_radius=8,
            command=self._toggle_scan,
        )
        self._start_btn.grid(row=0, column=7, padx=(0, 0))

        # Progress bar + status
        self._progress_bar = ctk.CTkProgressBar(
            ctrl, fg_color=BG_INPUT, progress_color=ACCENT_CYAN,
            height=6, corner_radius=3,
        )
        self._progress_bar.set(0)
        self._progress_bar.grid(row=6, column=0, columnspan=3, sticky="ew",
                                padx=18, pady=(0, 6))

        self._status_label = ctk.CTkLabel(
            ctrl, text="Ready",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_MUTED, anchor="w",
        )
        self._status_label.grid(row=7, column=0, columnspan=3, sticky="w",
                                padx=18, pady=(0, 14))

    def _build_summary(self):
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.grid(row=2, column=0, sticky="ew", padx=30, pady=(16, 0))
        for i in range(5):
            row.grid_columnconfigure(i, weight=1)

        specs = [
            ("Total Ports",  self._total,    ACCENT_CYAN,  "⬡"),
            ("Open",         self._n_open,   CLR_OPEN,     "✓"),
            ("Filtered",     self._n_filt,   CLR_FILTERED, "⚑"),
            ("Closed",       self._n_closed, CLR_CLOSED,   "✕"),
            ("Errors",       self._n_errors, CLR_ERROR,    "⚠"),
        ]
        for col, (title, var, color, icon) in enumerate(specs):
            card = ctk.CTkFrame(row, fg_color=BG_CARD, corner_radius=10,
                                border_width=1, border_color=BORDER_COLOR)
            card.grid(row=0, column=col, sticky="ew", padx=5)
            card.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(card, text=f"{icon}  {title}",
                         font=ctk.CTkFont(family="Segoe UI", size=11),
                         text_color=TEXT_MUTED).grid(row=0, column=0, pady=(12, 2))
            ctk.CTkLabel(card, textvariable=var,
                         font=ctk.CTkFont(family="Segoe UI", size=28, weight="bold"),
                         text_color=color).grid(row=1, column=0, pady=(0, 12))

    def _build_table(self):
        wrapper = ctk.CTkFrame(
            self, fg_color=BG_CARD, corner_radius=12,
            border_width=1, border_color=BORDER_COLOR,
        )
        wrapper.grid(row=3, column=0, sticky="nsew", padx=30, pady=(16, 30))
        wrapper.grid_columnconfigure(0, weight=1)
        wrapper.grid_rowconfigure(1, weight=1)

        # Filter bar
        fbar = ctk.CTkFrame(wrapper, fg_color="transparent")
        fbar.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 8))
        fbar.grid_columnconfigure(0, weight=1)

        self._search_entry = ctk.CTkEntry(
            fbar,
            placeholder_text="🔍  Search port, service, banner…",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, height=32,
        )
        self._search_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self._search_entry.bind("<KeyRelease>", lambda e: self._apply_filter())

        self._cat_dropdown = ctk.CTkOptionMenu(
            fbar,
            values=FILTER_OPTIONS, variable=self._filter_cat,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color=BG_INPUT, button_color=BORDER_COLOR,
            button_hover_color=BG_CARD, text_color=TEXT_PRIMARY,
            dropdown_fg_color=BG_CARD, dropdown_text_color=TEXT_PRIMARY,
            dropdown_hover_color=BG_INPUT, width=120, height=32, corner_radius=6,
        )
        self._cat_dropdown.grid(row=0, column=1, padx=(0, 10))

        ctk.CTkCheckBox(
            fbar, text="Show closed",
            variable=self._show_closed,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED,
            checkmark_color="#0f1117",
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            width=120,
        ).grid(row=0, column=2, padx=(0, 10))

        ctk.CTkButton(
            fbar, text="⬇ CSV", width=70, height=32, corner_radius=6,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, hover_color=BG_INPUT,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            command=lambda: self._export("csv"),
        ).grid(row=0, column=3, padx=(0, 6))

        ctk.CTkButton(
            fbar, text="⬇ TXT", width=70, height=32, corner_radius=6,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, hover_color=BG_INPUT,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            command=lambda: self._export("txt"),
        ).grid(row=0, column=4)

        # Treeview
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Port.Treeview",
            background=BG_TABLE_ROW, foreground=TEXT_PRIMARY,
            fieldbackground=BG_TABLE_ROW, rowheight=34, borderwidth=0,
            relief="flat", font=("Segoe UI", 11),
        )
        style.configure("Port.Treeview.Heading",
            background=BG_INPUT, foreground=TEXT_MUTED,
            borderwidth=0, relief="flat", font=("Segoe UI", 11, "bold"),
        )
        style.map("Port.Treeview",
            background=[("selected", "#1a2332")],
            foreground=[("selected", TEXT_PRIMARY)],
        )
        style.map("Port.Treeview.Heading",
            background=[("active", BG_CARD), ("pressed", BG_INPUT)],
            relief=[("active", "flat"), ("pressed", "flat")],
        )
        style.configure("Port.Vertical.TScrollbar",
            background=BORDER_COLOR, troughcolor=BG_CARD,
            arrowcolor=TEXT_MUTED, borderwidth=0, relief="flat",
        )
        style.map("Port.Vertical.TScrollbar",
            background=[("active", TEXT_MUTED)],
        )

        tree_frame = tk.Frame(wrapper, bg=BG_CARD)
        tree_frame.grid(row=1, column=0, sticky="nsew")
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", style="Port.Vertical.TScrollbar")
        vsb.grid(row=0, column=1, sticky="ns")

        self._tree = ttk.Treeview(
            tree_frame,
            columns=("port", "service", "status", "banner", "ms"),
            show="headings",
            style="Port.Treeview",
            yscrollcommand=vsb.set,
        )
        vsb.configure(command=self._tree.yview)
        self._tree.grid(row=0, column=0, sticky="nsew")

        self._tree.heading("port",    text="Port",         anchor="w")
        self._tree.heading("service", text="Service",      anchor="w")
        self._tree.heading("status",  text="Status",       anchor="center")
        self._tree.heading("banner",  text="Banner",       anchor="w")
        self._tree.heading("ms",      text="Response (ms)", anchor="center")

        self._tree.column("port",    width=80,  anchor="w",      stretch=False, minwidth=60)
        self._tree.column("service", width=160, anchor="w",      stretch=False, minwidth=100)
        self._tree.column("status",  width=100, anchor="center", stretch=False, minwidth=80)
        self._tree.column("banner",  width=300, anchor="w",      stretch=True,  minwidth=120)
        self._tree.column("ms",      width=110, anchor="center", stretch=False, minwidth=80)

        self._tree.tag_configure("row_even",  background=BG_TABLE_ROW)
        self._tree.tag_configure("row_odd",   background=BG_TABLE_ALT)
        self._tree.tag_configure("st_open",     foreground=CLR_OPEN)
        self._tree.tag_configure("st_filtered", foreground=CLR_FILTERED)
        self._tree.tag_configure("st_closed",   foreground=CLR_CLOSED)
        self._tree.tag_configure("st_error",    foreground=CLR_ERROR)

        self._empty_label = ctk.CTkLabel(
            tree_frame,
            text="Start a scan to see results here.",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=TEXT_DIM, fg_color="transparent",
        )
        self._empty_label.place(relx=0.5, rely=0.5, anchor="center")

        self._result_count_label = ctk.CTkLabel(
            wrapper, text="0 results shown",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_DIM, anchor="e",
        )
        self._result_count_label.grid(row=2, column=0, sticky="e",
                                      padx=16, pady=(4, 10))

    # ── Controls interaction ──────────────────────────────────────────────────

    def _on_mode_change(self, val: str):
        if val == "Custom Range":
            self._range_frame.grid()
        else:
            self._range_frame.grid_remove()

    def _on_thread_slider(self, val):
        self._thread_val.configure(text=str(int(val)))

    def _on_timeout_slider(self, val):
        self._timeout_val.configure(text=f"{val:.1f} s")

    # ── Scan control ──────────────────────────────────────────────────────────

    def _toggle_scan(self):
        if self._scan_running:
            self._stop_scan()
        else:
            self._start_scan()

    def _start_scan(self):
        host = self._host_entry.get().strip()
        if not host:
            messagebox.showwarning("Missing Host", "Please enter a target host or IP.")
            return

        mode = self._mode.get()
        if mode == "Custom Range":
            try:
                p_from = int(self._from_entry.get().strip() or "1")
                p_to   = int(self._to_entry.get().strip() or "1024")
            except ValueError:
                messagebox.showerror("Invalid Range", "Port range must be integers.")
                return
            if not (1 <= p_from <= 65535 and 1 <= p_to <= 65535):
                messagebox.showerror("Invalid Range", "Ports must be between 1 and 65535.")
                return
            if p_from > p_to:
                messagebox.showerror("Invalid Range", "From port must be ≤ To port.")
                return
            ports = list(range(p_from, p_to + 1))
        else:
            ports = TOP_1000_PORTS

        self._all_results.clear()
        self._n_open.set(0); self._n_filt.set(0)
        self._n_closed.set(0); self._n_errors.set(0)
        self._scanned.set(0); self._total.set(len(ports))
        self._result_queue = queue.Queue()
        self._tree_row_count = 0

        self._tree.delete(*self._tree.get_children())
        self._empty_label.configure(text="Scanning…")
        self._empty_label.place(relx=0.5, rely=0.5, anchor="center")
        self._result_count_label.configure(text="0 results shown")
        self._progress_bar.set(0)

        threads = int(self._thread_slider.get())
        timeout = round(self._timeout_slider.get() * 2) / 2  # snap to 0.5 steps
        grab    = self._banner_var.get()

        self._engine = PortScanEngine(host, ports, threads=threads,
                                      timeout_s=timeout, grab_banner=grab)
        self._engine.start(on_result=self._on_result, on_done=self._on_done)

        self._scan_running = True
        self._start_btn.configure(text="⏹  Stop Scan", fg_color="#ef4444",
                                   hover_color="#cc0000", text_color=TEXT_PRIMARY)
        self._status_label.configure(
            text=f"Scanning {self._engine.host} — {len(ports)} ports…"
        )
        self._host_entry.configure(state="disabled")
        self._mode_btn.configure(state="disabled")
        self._poll_results()

    def _stop_scan(self):
        if self._engine:
            self._engine.stop()
        self._finalize_scan(aborted=True)

    def _finalize_scan(self, aborted=False):
        self._scan_running = False
        if self._poll_id:
            self.after_cancel(self._poll_id)
            self._poll_id = None

        while not self._result_queue.empty():
            try:
                r = self._result_queue.get_nowait()
                self._all_results.append(r)
                self._update_counters(r)
            except Exception:
                break

        self._apply_filter()
        self._start_btn.configure(text="▶  Start Scan", fg_color=ACCENT_CYAN,
                                   hover_color="#00aacc", text_color="#0f1117")
        self._host_entry.configure(state="normal")
        self._mode_btn.configure(state="normal")

        total = self._total.get()
        scanned = self._scanned.get()
        suffix = " (aborted)" if aborted else " — Complete ✓"
        self._status_label.configure(
            text=f"Scanned {scanned}/{total} ports{suffix}  •  "
                 f"{self._n_open.get()} open  •  {self._n_filt.get()} filtered"
        )
        self._progress_bar.set(1.0 if not aborted else (scanned / total if total else 0))

    # ── Result handling ───────────────────────────────────────────────────────

    def _on_result(self, result: PortResult):
        self._result_queue.put(result)

    def _on_done(self, summary: ScanSummary):
        self.after(0, self._finalize_scan)

    def _poll_results(self):
        count = 0
        while not self._result_queue.empty() and count < BATCH_LIMIT:
            r: PortResult = self._result_queue.get_nowait()
            self._all_results.append(r)
            self._update_counters(r)
            count += 1

        if count:
            text     = self._search_entry.get().strip().lower()
            cat_f    = self._filter_cat.get()
            show_cl  = self._show_closed.get()

            if not text and cat_f == "All" and show_cl:
                new = self._all_results[self._tree_row_count:]
                if new and self._tree_row_count == 0:
                    self._empty_label.place_forget()
                for r in new:
                    self._insert_tree_row(r, self._tree_row_count)
                    self._tree_row_count += 1
                self._result_count_label.configure(
                    text=f"{self._tree_row_count} results shown"
                )
            else:
                self._apply_filter()

        total = self._total.get()
        scanned = self._scanned.get()
        if total > 0:
            self._progress_bar.set(scanned / total)
            self._status_label.configure(
                text=f"Scanning {scanned}/{total} ports  •  "
                     f"{self._n_open.get()} open  •  {self._n_filt.get()} filtered"
            )

        if self._scan_running:
            self._poll_id = self.after(POLL_MS, self._poll_results)

    def _update_counters(self, r: PortResult):
        self._scanned.set(self._scanned.get() + 1)
        if r.status == STATUS_OPEN:
            self._n_open.set(self._n_open.get() + 1)
        elif r.status == STATUS_FILTERED:
            self._n_filt.set(self._n_filt.get() + 1)
        elif r.status == STATUS_CLOSED:
            self._n_closed.set(self._n_closed.get() + 1)
        else:
            self._n_errors.set(self._n_errors.get() + 1)

    # ── Treeview helpers ──────────────────────────────────────────────────────

    def _match(self, r: PortResult) -> bool:
        text    = self._search_entry.get().strip().lower()
        cat_f   = self._filter_cat.get()
        show_cl = self._show_closed.get()

        if cat_f == "Open"     and r.status != STATUS_OPEN:     return False
        if cat_f == "Filtered" and r.status != STATUS_FILTERED: return False
        if cat_f == "Closed"   and r.status != STATUS_CLOSED:   return False
        if cat_f == "Error"    and r.status != STATUS_ERROR:    return False
        if cat_f == "All" and not show_cl and r.status == STATUS_CLOSED:
            return False
        if text:
            if text not in f"{r.port} {r.service} {r.banner}".lower():
                return False
        return True

    def _insert_tree_row(self, r: PortResult, idx: int):
        tag_row = "row_even" if idx % 2 == 0 else "row_odd"
        tag_st  = STATUS_TAG.get(r.status, "st_closed")
        meta    = STATUS_META.get(r.status, {"label": r.status})
        self._tree.insert(
            "", "end",
            values=(r.port, r.service or "—", meta["label"],
                    r.banner or "—", f"{r.response_ms} ms"),
            tags=(tag_row, tag_st),
        )

    def _apply_filter(self):
        visible = [r for r in self._all_results if self._match(r)]

        self._tree.delete(*self._tree.get_children())

        if not visible:
            msg = ("No results match the current filter."
                   if self._all_results
                   else "Start a scan to see results here.")
            self._empty_label.configure(text=msg)
            self._empty_label.place(relx=0.5, rely=0.5, anchor="center")
            self._result_count_label.configure(text="0 results shown")
            return

        self._empty_label.place_forget()
        for idx, r in enumerate(visible):
            self._insert_tree_row(r, idx)

        text  = self._search_entry.get().strip().lower()
        cat_f = self._filter_cat.get()
        show_cl = self._show_closed.get()
        if not text and cat_f == "All" and show_cl:
            self._tree_row_count = len(visible)

        n = len(visible)
        self._result_count_label.configure(
            text=f"{n} result{'s' if n != 1 else ''} shown"
        )

    # ── Export ────────────────────────────────────────────────────────────────

    def _export(self, fmt: str):
        if not self._all_results:
            messagebox.showinfo("No Data", "Run a scan first.")
            return
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            defaultextension=f".{fmt}",
            filetypes=[("CSV files", "*.csv")] if fmt == "csv"
                      else [("Text files", "*.txt")],
            initialfile=f"cyberkit_portscan_{ts}.{fmt}",
            title="Export Port Scan Results",
        )
        if not path:
            return
        try:
            if fmt == "csv":
                self._write_csv(path)
            else:
                self._write_txt(path)
            messagebox.showinfo("Export Successful", f"Saved to:\n{path}")
        except OSError as e:
            messagebox.showerror("Export Failed", str(e))

    def _write_csv(self, path: str):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["Port", "Service", "Status", "Banner", "Response (ms)"])
            for r in self._all_results:
                w.writerow([r.port, r.service, r.status, r.banner, r.response_ms])

    def _write_txt(self, path: str):
        host = self._engine.host if self._engine else "unknown"
        with open(path, "w", encoding="utf-8") as f:
            f.write("CyberKit — Port Scanner Results\n")
            f.write(f"Host   : {host}\n")
            f.write(f"Date   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Open   : {self._n_open.get()}  "
                    f"Filtered: {self._n_filt.get()}  "
                    f"Closed: {self._n_closed.get()}  "
                    f"Errors: {self._n_errors.get()}\n")
            f.write("=" * 70 + "\n\n")
            for r in sorted(self._all_results, key=lambda x: x.port):
                meta = STATUS_META.get(r.status, {"label": r.status})
                svc  = f"  [{r.service}]" if r.service else ""
                bnr  = f"  {r.banner}" if r.banner else ""
                f.write(
                    f"{r.port:<6} {meta['label']:<10} {r.response_ms:>5} ms{svc}{bnr}\n"
                )
