"""
CyberKit — HTTP Header Analyser Page
"""

import queue
import threading
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, ttk

import customtkinter as ctk
from app.ui.scrollable import autohide_vsb

from app.modules.header_analyser import (
    HeaderFinding,
    analyse,
    compute_grade,
    STATUS_OK,
    STATUS_WARN,
    STATUS_MISSING,
    STATUS_SKIPPED,
    STATUS_INFO,
)

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

CLR_OK      = "#22c55e"
CLR_WARN    = "#f59e0b"
CLR_MISSING = "#ef4444"
CLR_SKIPPED = "#6b7280"
CLR_INFO    = "#00d4ff"

STATUS_ICON = {
    STATUS_OK:      "✓",
    STATUS_WARN:    "⚠",
    STATUS_MISSING: "✕",
    STATUS_SKIPPED: "—",
    STATUS_INFO:    "ℹ",
}
STATUS_COLOR = {
    STATUS_OK:      CLR_OK,
    STATUS_WARN:    CLR_WARN,
    STATUS_MISSING: CLR_MISSING,
    STATUS_SKIPPED: CLR_SKIPPED,
    STATUS_INFO:    CLR_INFO,
}
GRADE_COLOR = {
    "A+": CLR_OK, "A": CLR_OK,
    "B": ACCENT_CYAN,
    "C": CLR_WARN,
    "D": CLR_MISSING, "F": CLR_MISSING,
}


class HeaderAnalyserPage(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, corner_radius=0, **kwargs)

        self._findings: list[HeaderFinding] = []
        self._result_queue: queue.Queue = queue.Queue()
        self._poll_id = None
        self._analysing = False

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
            text="🛡  Header Analyser",
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(
            hdr,
            text="Checks 6 OWASP security headers + info-leak detection  •  Weighted A+ – F grade",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        self._build_controls()
        self._build_grade_area()
        self._build_table()

    def _build_controls(self):
        ctrl = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=12,
                            border_width=1, border_color=BORDER_COLOR)
        ctrl.grid(row=1, column=0, sticky="ew", padx=30, pady=(20, 0))
        ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(ctrl, text="Target URL",
                     font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                     text_color=TEXT_MUTED).grid(
            row=0, column=0, padx=(18, 10), pady=(16, 4), sticky="w")

        self._inline_error = ctk.CTkLabel(
            ctrl, text="",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=CLR_MISSING, anchor="w",
        )
        self._inline_error.grid(row=0, column=1, sticky="w", padx=(0, 18), pady=(16, 4))

        self._url_entry = ctk.CTkEntry(
            ctrl,
            placeholder_text="https://example.com",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, height=38,
        )
        self._url_entry.grid(row=1, column=0, columnspan=2, sticky="ew",
                             padx=18, pady=(0, 6))
        self._url_entry.bind("<Return>", lambda e: self._start_analysis())

        self._analyse_btn = ctk.CTkButton(
            ctrl,
            text="▶  Analyse",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color="#0f1117", height=38, width=140, corner_radius=8,
            command=self._start_analysis,
        )
        self._analyse_btn.grid(row=2, column=0, padx=(18, 10), pady=(0, 14), sticky="w")

        self._status_label = ctk.CTkLabel(
            ctrl, text="Enter a URL and click Analyse.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_MUTED, anchor="w",
        )
        self._status_label.grid(row=2, column=1, sticky="w", padx=(0, 18), pady=(0, 14))

    def _build_grade_area(self):
        self._grade_frame = ctk.CTkFrame(
            self, fg_color=BG_CARD, corner_radius=12,
            border_width=1, border_color=BORDER_COLOR,
        )
        self._grade_frame.grid(row=2, column=0, sticky="ew", padx=30, pady=(16, 0))
        self._grade_frame.grid_columnconfigure(1, weight=1)

        # Large grade letter
        self._grade_letter = ctk.CTkLabel(
            self._grade_frame,
            text="—",
            font=ctk.CTkFont(family="Segoe UI", size=64, weight="bold"),
            text_color=TEXT_DIM,
            width=100,
        )
        self._grade_letter.grid(row=0, column=0, rowspan=2, padx=(24, 16), pady=16)

        # Score + URL
        self._grade_score = ctk.CTkLabel(
            self._grade_frame,
            text="No analysis yet",
            font=ctk.CTkFont(family="Segoe UI", size=16),
            text_color=TEXT_MUTED, anchor="w",
        )
        self._grade_score.grid(row=0, column=1, sticky="w", pady=(16, 2))

        self._grade_url = ctk.CTkLabel(
            self._grade_frame,
            text="",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_DIM, anchor="w",
        )
        self._grade_url.grid(row=1, column=1, sticky="w", pady=(0, 16))

        # Export button
        ctk.CTkButton(
            self._grade_frame, text="⬇ TXT", width=80, height=32, corner_radius=6,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, hover_color=BG_INPUT,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            command=self._export_txt,
        ).grid(row=0, column=2, rowspan=2, padx=(0, 18))

    def _build_table(self):
        wrapper = ctk.CTkFrame(
            self, fg_color=BG_CARD, corner_radius=12,
            border_width=1, border_color=BORDER_COLOR,
        )
        wrapper.grid(row=3, column=0, sticky="nsew", padx=30, pady=(16, 30))
        wrapper.grid_columnconfigure(0, weight=1)
        wrapper.grid_rowconfigure(1, weight=1)

        # Column headings label
        ctk.CTkLabel(
            wrapper, text="Security Headers",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(12, 8))

        # Treeview
        style = ttk.Style()
        style.configure("Hdr.Treeview",
            background=BG_TABLE_ROW, foreground=TEXT_PRIMARY,
            fieldbackground=BG_TABLE_ROW, rowheight=34, borderwidth=0,
            relief="flat", font=("Segoe UI", 11),
        )
        style.configure("Hdr.Treeview.Heading",
            background=BG_INPUT, foreground=TEXT_MUTED,
            borderwidth=0, relief="flat", font=("Segoe UI", 11, "bold"),
        )
        style.map("Hdr.Treeview",
            background=[("selected", "#1a2332")],
            foreground=[("selected", TEXT_PRIMARY)],
        )
        style.map("Hdr.Treeview.Heading",
            background=[("active", BG_CARD), ("pressed", BG_INPUT)],
            relief=[("active", "flat"), ("pressed", "flat")],
        )
        style.configure("Hdr.Vertical.TScrollbar",
            background=BORDER_COLOR, troughcolor=BG_CARD,
            arrowcolor=TEXT_MUTED, borderwidth=0, relief="flat",
        )
        style.map("Hdr.Vertical.TScrollbar",
            background=[("active", TEXT_MUTED)],
        )

        tree_frame = tk.Frame(wrapper, bg=BG_CARD)
        tree_frame.grid(row=1, column=0, sticky="nsew")
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)
        wrapper.grid_rowconfigure(1, weight=1)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", style="Hdr.Vertical.TScrollbar")
        vsb.grid(row=0, column=1, sticky="ns")

        self._tree = ttk.Treeview(
            tree_frame,
            columns=("header", "value", "status", "severity", "tip"),
            show="headings",
            height=1,
            style="Hdr.Treeview",
            yscrollcommand=autohide_vsb(vsb),
        )
        vsb.configure(command=self._tree.yview)
        self._tree.grid(row=0, column=0, sticky="nsew")

        self._tree.heading("header",   text="Header",    anchor="w")
        self._tree.heading("value",    text="Value",     anchor="w")
        self._tree.heading("status",   text="Status",    anchor="center")
        self._tree.heading("severity", text="Severity",  anchor="center")
        self._tree.heading("tip",      text="Tip",       anchor="w")

        self._tree.column("header",   width=220, anchor="w",      stretch=False, minwidth=160)
        self._tree.column("value",    width=240, anchor="w",      stretch=True,  minwidth=120)
        self._tree.column("status",   width=90,  anchor="center", stretch=False, minwidth=70)
        self._tree.column("severity", width=90,  anchor="center", stretch=False, minwidth=70)
        self._tree.column("tip",      width=0,   anchor="w",      stretch=False, minwidth=0)

        self._tree.tag_configure("row_even",    background=BG_TABLE_ROW)
        self._tree.tag_configure("row_odd",     background=BG_TABLE_ALT)
        self._tree.tag_configure("st_ok",       foreground=CLR_OK)
        self._tree.tag_configure("st_warn",     foreground=CLR_WARN)
        self._tree.tag_configure("st_missing",  foreground=CLR_MISSING)
        self._tree.tag_configure("st_skipped",  foreground=CLR_SKIPPED)
        self._tree.tag_configure("st_info",     foreground=CLR_INFO)

        self._tree.bind("<<TreeviewSelect>>", self._on_row_select)

        self._empty_label = ctk.CTkLabel(
            tree_frame,
            text="Run an analysis to see results.",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=TEXT_DIM, fg_color="transparent",
        )
        self._empty_label.place(relx=0.5, rely=0.5, anchor="center")

        # Tip detail area
        tip_frame = ctk.CTkFrame(wrapper, fg_color=BG_INPUT, corner_radius=8,
                                  border_width=1, border_color=BORDER_COLOR)
        tip_frame.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 4))
        tip_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(tip_frame, text="Select a row to see detailed guidance",
                     font=ctk.CTkFont(family="Segoe UI", size=11),
                     text_color=TEXT_DIM, anchor="w").grid(
            row=0, column=0, sticky="w", padx=10, pady=(6, 0))

        self._tip_box = ctk.CTkTextbox(
            tip_frame,
            height=80, corner_radius=0,
            fg_color="transparent", text_color=TEXT_MUTED,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            border_width=0, state="disabled",
        )
        self._tip_box.grid(row=1, column=0, sticky="ew", padx=6, pady=(2, 8))

        # Info-leak card (hidden until leaks detected)
        self._leak_frame = ctk.CTkFrame(
            wrapper, fg_color="#1a0d00",
            corner_radius=8, border_width=1, border_color="#f59e0b",
        )
        self._leak_frame.grid(row=3, column=0, sticky="ew", padx=16, pady=(0, 12))
        self._leak_frame.grid_columnconfigure(0, weight=1)
        self._leak_frame.grid_remove()

        self._leak_label = ctk.CTkLabel(
            self._leak_frame,
            text="",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=CLR_WARN, anchor="w", justify="left",
        )
        self._leak_label.grid(row=0, column=0, sticky="w", padx=12, pady=10)

    def _set_status(self, msg: str, error: bool = False):
        if error:
            self._inline_error.configure(text=msg)
        else:
            self._inline_error.configure(text="")
            self._status_label.configure(text=msg, text_color=TEXT_MUTED)

    # ── Analysis ──────────────────────────────────────────────────────────────

    def _start_analysis(self):
        self._inline_error.configure(text="")
        url = self._url_entry.get().strip()
        if not url:
            self._set_status("Please enter a target URL.", error=True)
            return
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        self._analysing = True
        self._analyse_btn.configure(state="disabled")
        self._status_label.configure(text=f"Analysing {url}…")
        self._result_queue = queue.Queue()
        self._clear_results()

        threading.Thread(
            target=self._run_analysis,
            args=(url,),
            daemon=True,
        ).start()

        self._poll_id = self.after(100, self._poll_analysis)

    def _run_analysis(self, url: str):
        try:
            findings = analyse(url)
            self._result_queue.put(("ok", url, findings))
        except Exception as exc:
            self._result_queue.put(("error", url, str(exc)))

    def _poll_analysis(self):
        try:
            payload = self._result_queue.get_nowait()
            self._on_analysis_done(payload)
        except queue.Empty:
            self._poll_id = self.after(100, self._poll_analysis)

    def _on_analysis_done(self, payload: tuple):
        self._analysing = False
        self._analyse_btn.configure(state="normal")

        kind, url, data = payload
        if kind == "error":
            self._set_status(f"Error: {data}", error=True)
            return

        findings: list[HeaderFinding] = data
        self._findings = findings
        letter, score, max_score = compute_grade(findings)
        color = GRADE_COLOR.get(letter, CLR_MISSING)

        self._grade_letter.configure(text=letter, text_color=color)
        self._grade_score.configure(
            text=f"Grade: {letter}  ({score} / {max_score} pts)",
            text_color=color,
        )
        self._grade_url.configure(text=url)
        self._status_label.configure(text=f"Analysis complete — {len(findings)} headers checked")

        self._populate_table(findings)

    def _populate_table(self, findings: list[HeaderFinding]):
        self._tree.delete(*self._tree.get_children())

        leaks: list[HeaderFinding] = []
        for idx, f in enumerate(findings):
            tag_row = "row_even" if idx % 2 == 0 else "row_odd"
            tag_st  = f"st_{f.status}"
            icon    = STATUS_ICON.get(f.status, "?")
            val     = f.raw_value if f.raw_value is not None else "MISSING"
            self._tree.insert(
                "", "end",
                iid=str(idx),
                values=(f.rule.display, val, icon, f.rule.severity.upper(), f.tip),
                tags=(tag_row, tag_st),
            )
            if f.status == STATUS_INFO and f.raw_value is not None:
                leaks.append(f)

        if findings:
            self._empty_label.place_forget()

        # Update info-leak card
        if leaks:
            lines = ["ℹ  Info-leak headers detected — these reveal server details:"]
            for lk in leaks:
                lines.append(f"   {lk.rule.display}: {lk.raw_value}")
            lines.append("   → Remove or mask them in your server configuration.")
            self._leak_label.configure(text="\n".join(lines))
            self._leak_frame.grid()
        else:
            self._leak_frame.grid_remove()

    def _on_row_select(self, event):
        sel = self._tree.selection()
        if not sel:
            return
        values = self._tree.item(sel[0], "values")
        if values:
            tip = values[4]  # tip column
            self._tip_box.configure(state="normal")
            self._tip_box.delete("1.0", "end")
            self._tip_box.insert("1.0", tip)
            self._tip_box.configure(state="disabled")

    def _clear_results(self):
        self._tree.delete(*self._tree.get_children())
        self._empty_label.place(relx=0.5, rely=0.5, anchor="center")
        self._grade_letter.configure(text="—", text_color=TEXT_DIM)
        self._grade_score.configure(text="Analysing…", text_color=TEXT_MUTED)
        self._grade_url.configure(text="")
        self._leak_frame.grid_remove()
        self._tip_box.configure(state="normal")
        self._tip_box.delete("1.0", "end")
        self._tip_box.configure(state="disabled")

    # ── Export ────────────────────────────────────────────────────────────────

    def _export_txt(self):
        if not self._findings:
            self._set_status("No results to export — run an analysis first.", error=True)
            return
        letter, score, max_score = compute_grade(self._findings)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
            initialfile=f"cyberkit_headers_{ts}.txt",
            title="Export Header Analysis",
        )
        if not path:
            return
        try:
            url = self._url_entry.get().strip()
            with open(path, "w", encoding="utf-8") as f:
                f.write("CyberKit — HTTP Header Analysis Report\n")
                f.write(f"URL    : {url}\n")
                f.write(f"Grade  : {letter}  ({score} / {max_score} pts)\n")
                f.write(f"Date   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 70 + "\n\n")
                for fd in self._findings:
                    icon = STATUS_ICON.get(fd.status, "?")
                    val  = fd.raw_value if fd.raw_value is not None else "MISSING"
                    f.write(f"{icon} {fd.rule.display} [{fd.rule.severity.upper()}]\n")
                    f.write(f"   Value : {val}\n")
                    f.write(f"   Tip   : {fd.tip}\n\n")
            self._set_status("Export saved successfully.")
        except OSError as e:
            self._set_status(f"Export failed: {e}", error=True)
