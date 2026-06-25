"""
CyberKit — Directory Fuzzer Page

Result categories:
  FOUND        200            green   #22c55e
  INTERESTING  301/302/403   amber   #f59e0b
  NOT_FOUND    other         grey    #6b7280
  ERROR        network err   red     #ef4444
"""

import csv
import queue
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, ttk

import customtkinter as ctk

from app.data.wordlists import WORDLIST
from app.modules.dir_fuzzer import (
    FuzzerEngine,
    ScanResult,
    ScanSummary,
    STATUS_FOUND,
    STATUS_INTERESTING,
    STATUS_NOT_FOUND,
    STATUS_ERROR,
)

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

CLR_FOUND      = "#22c55e"
CLR_INTREST    = "#f59e0b"
CLR_NOT_FOUND  = "#6b7280"
CLR_ERROR      = "#ef4444"

CATEGORY_META = {
    STATUS_FOUND:       {"label": "200 OK",      "color": CLR_FOUND},
    STATUS_INTERESTING: {"label": "Interesting",  "color": CLR_INTREST},
    STATUS_NOT_FOUND:   {"label": "Not Found",    "color": CLR_NOT_FOUND},
    STATUS_ERROR:       {"label": "Error",        "color": CLR_ERROR},
}

# Maps status category → treeview tag name
CATEGORY_TAGS = {
    STATUS_FOUND:       "cat_found",
    STATUS_INTERESTING: "cat_interesting",
    STATUS_NOT_FOUND:   "cat_notfound",
    STATUS_ERROR:       "cat_error",
}

POLL_MS = 80        # ms between queue drains
BATCH_LIMIT = 60    # max results consumed per poll tick

FILTER_OPTIONS = ["All", "200 OK", "Interesting", "Not Found", "Error"]


class FuzzerPage(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, corner_radius=0, **kwargs)

        self._engine: FuzzerEngine | None = None
        self._result_queue: queue.Queue[ScanResult] = queue.Queue()
        self._all_results: list[ScanResult] = []
        self._scan_running = False
        self._poll_id = None
        self._tree_row_count = 0  # rows currently in the treeview (no-filter path)

        # Summary counters
        self._total     = tk.IntVar(value=0)
        self._found     = tk.IntVar(value=0)
        self._intrest   = tk.IntVar(value=0)
        self._not_found = tk.IntVar(value=0)
        self._errors    = tk.IntVar(value=0)
        self._scanned   = tk.IntVar(value=0)

        # Filter state
        self._filter_cat = tk.StringVar(value="All")
        self._filter_cat.trace_add("write", lambda *_: self._apply_filter())

        self._build()

    # ── Build UI ──────────────────────────────────────────────────────────────

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        # ── Page header ───────────────────────────────────────────────────────
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=30, pady=(28, 0))
        hdr.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            hdr,
            text="⬡  Directory Fuzzer",
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
            text_color=TEXT_PRIMARY,
            anchor="w",
        ).grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(
            hdr,
            text=f"Wordlist: {len(WORDLIST)} paths  •  HEAD → GET fallback  •  Results categorised by status code",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED,
            anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        self._build_controls()
        self._build_summary()
        self._build_table()

    def _build_controls(self):
        ctrl = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=12,
                            border_width=1, border_color=BORDER_COLOR)
        ctrl.grid(row=1, column=0, sticky="ew", padx=30, pady=(20, 0))
        ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            ctrl, text="Target URL",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED,
        ).grid(row=0, column=0, padx=(18, 10), pady=(16, 4), sticky="w")

        self._inline_error = ctk.CTkLabel(
            ctrl, text="",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=CLR_ERROR, anchor="w",
        )
        self._inline_error.grid(row=0, column=1, sticky="w", padx=(0, 18), pady=(16, 4))

        self._url_entry = ctk.CTkEntry(
            ctrl,
            placeholder_text="https://example.com",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            fg_color=BG_INPUT,
            border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            height=38,
        )
        self._url_entry.grid(row=1, column=0, columnspan=3, sticky="ew",
                             padx=18, pady=(0, 6))

        threads_frame = ctk.CTkFrame(ctrl, fg_color="transparent")
        threads_frame.grid(row=2, column=0, columnspan=2, sticky="w",
                           padx=18, pady=(4, 14))

        ctk.CTkLabel(
            threads_frame, text="Threads:",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED,
        ).grid(row=0, column=0, padx=(0, 8))

        self._thread_val_label = ctk.CTkLabel(
            threads_frame, text="10",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=ACCENT_CYAN, width=24,
        )
        self._thread_val_label.grid(row=0, column=1, padx=(0, 6))

        self._thread_slider = ctk.CTkSlider(
            threads_frame,
            from_=1, to=20, number_of_steps=19, width=160,
            button_color=ACCENT_CYAN, progress_color=ACCENT_CYAN,
            command=self._on_thread_slider,
        )
        self._thread_slider.set(10)
        self._thread_slider.grid(row=0, column=2)

        self._start_btn = ctk.CTkButton(
            ctrl,
            text="▶  Start Scan",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color="#0f1117", height=38, width=140, corner_radius=8,
            command=self._toggle_scan,
        )
        self._start_btn.grid(row=2, column=2, padx=(0, 18), pady=(4, 14), sticky="e")

        self._progress_bar = ctk.CTkProgressBar(
            ctrl,
            fg_color=BG_INPUT, progress_color=ACCENT_CYAN,
            height=6, corner_radius=3,
        )
        self._progress_bar.set(0)
        self._progress_bar.grid(row=3, column=0, columnspan=3, sticky="ew",
                                padx=18, pady=(0, 6))

        self._status_label = ctk.CTkLabel(
            ctrl, text="Ready",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_MUTED, anchor="w",
        )
        self._status_label.grid(row=4, column=0, columnspan=3, sticky="w",
                                padx=18, pady=(0, 14))

    def _build_summary(self):
        cards_row = ctk.CTkFrame(self, fg_color="transparent")
        cards_row.grid(row=2, column=0, sticky="ew", padx=30, pady=(16, 0))
        for i in range(5):
            cards_row.grid_columnconfigure(i, weight=1)

        specs = [
            ("Total Paths",  self._total,     ACCENT_CYAN,   "⬡"),
            ("200 OK",       self._found,     CLR_FOUND,     "✓"),
            ("Interesting",  self._intrest,   CLR_INTREST,   "⚑"),
            ("Not Found",    self._not_found, CLR_NOT_FOUND, "✕"),
            ("Errors",       self._errors,    CLR_ERROR,     "⚠"),
        ]

        for col, (title, var, color, icon) in enumerate(specs):
            card = ctk.CTkFrame(cards_row, fg_color=BG_CARD, corner_radius=10,
                                border_width=1, border_color=BORDER_COLOR)
            card.grid(row=0, column=col, sticky="ew", padx=5)
            card.grid_columnconfigure(0, weight=1)

            ctk.CTkLabel(card, text=f"{icon}  {title}",
                         font=ctk.CTkFont(family="Segoe UI", size=11),
                         text_color=TEXT_MUTED).grid(row=0, column=0, pady=(12, 2))

            ctk.CTkLabel(card, textvariable=var,
                         font=ctk.CTkFont(family="Segoe UI", size=28, weight="bold"),
                         text_color=color).grid(row=1, column=0, pady=(0, 12))

        self._total.set(len(WORDLIST))

    def _build_table(self):
        table_wrapper = ctk.CTkFrame(
            self, fg_color=BG_CARD, corner_radius=12,
            border_width=1, border_color=BORDER_COLOR,
        )
        table_wrapper.grid(row=3, column=0, sticky="nsew", padx=30, pady=(16, 30))
        table_wrapper.grid_columnconfigure(0, weight=1)
        table_wrapper.grid_rowconfigure(1, weight=1)

        # ── Filter bar ────────────────────────────────────────────────────────
        filter_bar = ctk.CTkFrame(table_wrapper, fg_color="transparent")
        filter_bar.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 8))
        filter_bar.grid_columnconfigure(0, weight=1)

        self._search_entry = ctk.CTkEntry(
            filter_bar,
            placeholder_text="🔍  Search path…",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, height=32,
        )
        self._search_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self._search_entry.bind("<KeyRelease>", lambda e: self._apply_filter())

        self._cat_dropdown = ctk.CTkOptionMenu(
            filter_bar,
            values=FILTER_OPTIONS, variable=self._filter_cat,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color=BG_INPUT, button_color=BORDER_COLOR,
            button_hover_color=BG_CARD, text_color=TEXT_PRIMARY,
            dropdown_fg_color=BG_CARD, dropdown_text_color=TEXT_PRIMARY,
            dropdown_hover_color=BG_INPUT, width=140, height=32, corner_radius=6,
        )
        self._cat_dropdown.grid(row=0, column=1, padx=(0, 10))

        ctk.CTkButton(
            filter_bar, text="⬇ CSV", width=70, height=32, corner_radius=6,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, hover_color=BG_INPUT,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            command=lambda: self._export("csv"),
        ).grid(row=0, column=2, padx=(0, 6))

        ctk.CTkButton(
            filter_bar, text="⬇ TXT", width=70, height=32, corner_radius=6,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, hover_color=BG_INPUT,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            command=lambda: self._export("txt"),
        ).grid(row=0, column=3)

        # ── Treeview (replaces the old CTkScrollableFrame + CTkLabel rows) ────
        # clam theme is the most styleable cross-platform ttk theme
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Fuzzer.Treeview",
            background=BG_TABLE_ROW,
            foreground=TEXT_PRIMARY,
            fieldbackground=BG_TABLE_ROW,
            rowheight=34,
            borderwidth=0,
            relief="flat",
            font=("Segoe UI", 11),
        )
        style.configure("Fuzzer.Treeview.Heading",
            background=BG_INPUT,
            foreground=TEXT_MUTED,
            borderwidth=0,
            relief="flat",
            font=("Segoe UI", 11, "bold"),
        )
        style.map("Fuzzer.Treeview",
            background=[("selected", "#1a2332")],
            foreground=[("selected", TEXT_PRIMARY)],
        )
        style.map("Fuzzer.Treeview.Heading",
            background=[("active", BG_CARD), ("pressed", BG_INPUT)],
            relief=[("active", "flat"), ("pressed", "flat")],
        )
        style.configure("Fuzzer.Vertical.TScrollbar",
            background=BORDER_COLOR,
            troughcolor=BG_CARD,
            arrowcolor=TEXT_MUTED,
            borderwidth=0,
            relief="flat",
        )
        style.map("Fuzzer.Vertical.TScrollbar",
            background=[("active", TEXT_MUTED)],
        )

        tree_frame = tk.Frame(table_wrapper, bg=BG_CARD)
        tree_frame.grid(row=1, column=0, sticky="nsew")
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical",
                            style="Fuzzer.Vertical.TScrollbar")
        vsb.grid(row=0, column=1, sticky="ns")

        self._tree = ttk.Treeview(
            tree_frame,
            columns=("path", "code", "cat", "time"),
            show="headings",
            style="Fuzzer.Treeview",
            yscrollcommand=vsb.set,
        )
        vsb.configure(command=self._tree.yview)
        self._tree.grid(row=0, column=0, sticky="nsew")

        self._tree.heading("path", text="Path",          anchor="w")
        self._tree.heading("code", text="Status",        anchor="center")
        self._tree.heading("cat",  text="Category",      anchor="center")
        self._tree.heading("time", text="Response (ms)", anchor="center")

        self._tree.column("path", width=280, anchor="w",      stretch=True,  minwidth=150)
        self._tree.column("code", width=90,  anchor="center", stretch=False, minwidth=70)
        self._tree.column("cat",  width=120, anchor="center", stretch=False, minwidth=90)
        self._tree.column("time", width=120, anchor="center", stretch=False, minwidth=90)

        # Per-row tags: alternating backgrounds + per-category foreground
        self._tree.tag_configure("row_even",       background=BG_TABLE_ROW)
        self._tree.tag_configure("row_odd",        background=BG_TABLE_ALT)
        self._tree.tag_configure("cat_found",      foreground=CLR_FOUND)
        self._tree.tag_configure("cat_interesting", foreground=CLR_INTREST)
        self._tree.tag_configure("cat_notfound",   foreground=CLR_NOT_FOUND)
        self._tree.tag_configure("cat_error",      foreground=CLR_ERROR)

        # Empty-state label — placed over the tree, hidden when rows exist
        self._empty_label = ctk.CTkLabel(
            tree_frame,
            text="Start a scan to see results here.",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=TEXT_DIM,
            fg_color="transparent",
        )
        self._empty_label.place(relx=0.5, rely=0.5, anchor="center")

        # ── Result count ──────────────────────────────────────────────────────
        self._result_count_label = ctk.CTkLabel(
            table_wrapper,
            text="0 results shown",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_DIM, anchor="e",
        )
        self._result_count_label.grid(row=2, column=0, sticky="e",
                                      padx=16, pady=(4, 10))

    def _set_status(self, msg: str, error: bool = False):
        if error:
            self._inline_error.configure(text=msg)
        else:
            self._inline_error.configure(text="")
            self._status_label.configure(text=msg, text_color=TEXT_MUTED)

    # ── Scan control ──────────────────────────────────────────────────────────

    def _on_thread_slider(self, val):
        self._thread_val_label.configure(text=str(int(val)))

    def _toggle_scan(self):
        if self._scan_running:
            self._stop_scan()
        else:
            self._start_scan()

    def _start_scan(self):
        self._inline_error.configure(text="")
        url = self._url_entry.get().strip()
        if not url:
            self._set_status("Please enter a target URL.", error=True)
            return

        # Reset state
        self._all_results.clear()
        self._found.set(0)
        self._intrest.set(0)
        self._not_found.set(0)
        self._errors.set(0)
        self._scanned.set(0)
        self._total.set(len(WORDLIST))
        self._result_queue = queue.Queue()
        self._tree_row_count = 0

        # Clear table immediately without any widget-creation cost
        self._tree.delete(*self._tree.get_children())
        self._empty_label.configure(text="Start a scan to see results here.")
        self._empty_label.place(relx=0.5, rely=0.5, anchor="center")
        self._result_count_label.configure(text="0 results shown")
        self._progress_bar.set(0)

        threads = int(self._thread_slider.get())
        self._engine = FuzzerEngine(url, WORDLIST, threads=threads)
        self._engine.start(on_result=self._on_result, on_done=self._on_done)

        self._scan_running = True
        self._start_btn.configure(text="⏹  Stop Scan", fg_color="#ef4444",
                                   hover_color="#cc0000", text_color=TEXT_PRIMARY)
        self._status_label.configure(text=f"Scanning {self._engine.base_url} …")
        self._url_entry.configure(state="disabled")
        self._thread_slider.configure(state="disabled")
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

        # Drain any results still in the queue
        while not self._result_queue.empty():
            try:
                result = self._result_queue.get_nowait()
                self._all_results.append(result)
                self._update_counters(result)
            except Exception:
                break

        self._apply_filter()

        self._start_btn.configure(text="▶  Start Scan", fg_color=ACCENT_CYAN,
                                   hover_color="#00aacc", text_color="#0f1117")
        self._url_entry.configure(state="normal")
        self._thread_slider.configure(state="normal")

        scanned = self._scanned.get()
        suffix = " (aborted)" if aborted else " — Complete ✓"
        self._status_label.configure(
            text=f"Scanned {scanned} / {len(WORDLIST)} paths{suffix}"
        )
        progress = 1.0 if not aborted else (scanned / len(WORDLIST) if len(WORDLIST) else 0)
        self._progress_bar.set(progress)

    # ── Result handling ───────────────────────────────────────────────────────

    def _on_result(self, result: ScanResult):
        """Called from worker thread — put on queue only, never touch Tk here."""
        self._result_queue.put(result)

    def _on_done(self, summary: ScanSummary):
        """Called from worker thread when scan finishes naturally."""
        self.after(0, self._finalize_scan)

    def _poll_results(self):
        """Drain the queue and update the UI from the main thread."""
        count = 0
        while not self._result_queue.empty() and count < BATCH_LIMIT:
            result: ScanResult = self._result_queue.get_nowait()
            self._all_results.append(result)
            self._update_counters(result)
            count += 1

        if count:
            text  = self._search_entry.get().strip().lower()
            cat_f = self._filter_cat.get()

            if not text and cat_f == "All":
                # Fast path: append only new rows — no full rebuild
                new_results = self._all_results[self._tree_row_count:]
                if new_results and self._tree_row_count == 0:
                    self._empty_label.place_forget()
                for r in new_results:
                    self._insert_tree_row(r, self._tree_row_count)
                    self._tree_row_count += 1
                self._result_count_label.configure(
                    text=f"{self._tree_row_count} results shown"
                )
            else:
                # Filter is active: full rebuild (only happens on user action)
                self._apply_filter()

        scanned = self._scanned.get()
        if len(WORDLIST) > 0:
            self._progress_bar.set(scanned / len(WORDLIST))
            self._status_label.configure(
                text=f"Scanning {scanned} / {len(WORDLIST)} paths — "
                     f"{self._found.get()} found  •  {self._intrest.get()} interesting"
            )

        if self._scan_running:
            self._poll_id = self.after(POLL_MS, self._poll_results)

    def _update_counters(self, result: ScanResult):
        self._scanned.set(self._scanned.get() + 1)
        if result.category == STATUS_FOUND:
            self._found.set(self._found.get() + 1)
        elif result.category == STATUS_INTERESTING:
            self._intrest.set(self._intrest.get() + 1)
        elif result.category == STATUS_ERROR:
            self._errors.set(self._errors.get() + 1)
        else:
            self._not_found.set(self._not_found.get() + 1)

    # ── Treeview helpers ──────────────────────────────────────────────────────

    def _insert_tree_row(self, r: ScanResult, idx: int):
        """Append a single row to the treeview."""
        meta    = CATEGORY_META.get(r.category, {"label": r.category})
        tag_row = "row_even" if idx % 2 == 0 else "row_odd"
        tag_cat = CATEGORY_TAGS.get(r.category, "cat_notfound")
        code_str = str(r.status_code) if r.status_code else "—"
        self._tree.insert(
            "", "end",
            values=(r.path, code_str, meta["label"], f"{r.response_time_ms} ms"),
            tags=(tag_row, tag_cat),
        )

    def _apply_filter(self):
        """Rebuild the treeview to match current search text + category filter."""
        text  = self._search_entry.get().strip().lower()
        cat_f = self._filter_cat.get()

        visible = [
            r for r in self._all_results
            if (not text or text in r.path.lower())
            and (cat_f == "All" or CATEGORY_META.get(r.category, {}).get("label", "") == cat_f)
        ]

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

        # Keep _tree_row_count in sync when the no-filter path would have been used
        if not text and cat_f == "All":
            self._tree_row_count = len(visible)

        count = len(visible)
        self._result_count_label.configure(
            text=f"{count} result{'s' if count != 1 else ''} shown"
        )

    # ── Export ────────────────────────────────────────────────────────────────

    def _export(self, fmt: str):
        if not self._all_results:
            self._set_status("No results to export — run a scan first.", error=True)
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"cyberkit_scan_{timestamp}.{fmt}"

        filetypes = [("CSV files", "*.csv")] if fmt == "csv" \
                    else [("Text files", "*.txt")]
        path = filedialog.asksaveasfilename(
            defaultextension=f".{fmt}",
            filetypes=filetypes,
            initialfile=default_name,
            title="Export Scan Results",
        )
        if not path:
            return

        try:
            if fmt == "csv":
                self._write_csv(path)
            else:
                self._write_txt(path)
            self._set_status("Export saved successfully.")
        except OSError as e:
            self._set_status(f"Export failed: {e}", error=True)

    def _write_csv(self, path: str):
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Path", "Full URL", "Status Code", "Category",
                              "Response (ms)"])
            for r in self._all_results:
                writer.writerow([
                    r.path, r.full_url,
                    r.status_code or "—",
                    CATEGORY_META.get(r.category, {}).get("label", r.category),
                    r.response_time_ms,
                ])

    def _write_txt(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            f.write("CyberKit — Directory Fuzzer Results\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 70 + "\n\n")
            for r in self._all_results:
                cat_label = CATEGORY_META.get(r.category, {}).get("label", r.category)
                code = r.status_code or "—"
                f.write(
                    f"[{cat_label:<12}]  {code:<5}  {r.response_time_ms:>6} ms  {r.path}\n"
                )
