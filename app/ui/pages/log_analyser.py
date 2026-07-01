"""
CyberKit — Log Analyser Page
"""

import queue
import threading
import tkinter as tk
from tkinter import filedialog, ttk

import customtkinter as ctk

from app.modules.log_analyser import analyse, LogSummary

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
CLR_BLUE     = "#58a6ff"

POLL_MS = 120

_STYLE_INIT = False


def _init_style():
    global _STYLE_INIT
    if _STYLE_INIT:
        return
    _STYLE_INIT = True
    style = ttk.Style()
    style.theme_use("clam")
    for name in ("Log", "Auth"):
        style.configure(f"{name}.Treeview",
                        background="#161b22", fieldbackground="#161b22",
                        foreground="#e6edf3", rowheight=24,
                        borderwidth=0, relief="flat",
                        font=("Segoe UI", 11))
        style.configure(f"{name}.Treeview.Heading",
                        background="#12171e", foreground="#8b949e",
                        borderwidth=0, relief="flat",
                        font=("Segoe UI", 10, "bold"))
        style.map(f"{name}.Treeview",
                  background=[("selected", "#1a2332")],
                  foreground=[("selected", "#00d4ff")])


def _card(parent, title: str, **kwargs) -> ctk.CTkFrame:
    wrap = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=10, **kwargs)
    ctk.CTkLabel(wrap, text=title, font=("Segoe UI", 12, "bold"),
                 text_color=TEXT_MUTED).pack(anchor="w", padx=14, pady=(10, 4))
    return wrap


class LogAnalyserPage(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, corner_radius=0, **kwargs)
        _init_style()
        self._q          = queue.Queue()
        self._stop_event = threading.Event()
        self._running    = False
        self._poll_id    = None
        self._file_path  = ""
        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        self.grid_columnconfigure(0, weight=1)

        # Header
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=30, pady=(28, 0))
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(hdr, text="📋  Log Analyser",
                     font=("Segoe UI", 22, "bold"), text_color=TEXT_PRIMARY).grid(
                     row=0, column=0, sticky="w")
        ctk.CTkLabel(hdr, text="Detect format · top IPs · error spikes · failed-auth",
                     font=("Segoe UI", 13), text_color=TEXT_MUTED).grid(
                     row=1, column=0, sticky="w", pady=(2, 0))

        # Input card
        input_card = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=10)
        input_card.grid(row=1, column=0, sticky="ew", padx=30, pady=(18, 0))
        input_card.grid_columnconfigure(1, weight=1)

        ctk.CTkButton(input_card, text="📂  Open Log File", width=160,
                      fg_color="#21262d", hover_color="#30363d",
                      text_color=TEXT_PRIMARY, font=("Segoe UI", 12),
                      command=self._pick_file).grid(
                      row=0, column=0, padx=(14, 8), pady=14)

        self._path_lbl = ctk.CTkLabel(input_card, text="No file selected",
                                      font=("Segoe UI", 12), text_color=TEXT_MUTED,
                                      anchor="w")
        self._path_lbl.grid(row=0, column=1, sticky="ew", padx=4)

        self._analyse_btn = ctk.CTkButton(input_card, text="Analyse",
                                          fg_color=ACCENT_CYAN, hover_color="#00b8d9",
                                          text_color="#0f1117", font=("Segoe UI", 12, "bold"),
                                          width=100, command=self._start)
        self._analyse_btn.grid(row=0, column=2, padx=8, pady=14)

        self._stop_btn = ctk.CTkButton(input_card, text="Stop",
                                       fg_color="#21262d", hover_color="#30363d",
                                       text_color=CLR_ERROR, font=("Segoe UI", 12),
                                       width=70, command=self._stop, state="disabled")
        self._stop_btn.grid(row=0, column=3, padx=(0, 14), pady=14)

        # Status bar
        self._status_lbl = ctk.CTkLabel(self, text="", font=("Segoe UI", 12),
                                        text_color=TEXT_MUTED, anchor="w")
        self._status_lbl.grid(row=2, column=0, sticky="ew", padx=30, pady=(10, 0))

        # Summary bar
        self._summary_frame = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=8)
        self._summary_frame.grid(row=3, column=0, sticky="ew", padx=30, pady=(10, 0))
        self._summary_frame.grid_columnconfigure((0, 1, 2), weight=1)

        self._fmt_lbl   = self._summary_chip("Format", "—", col=0)
        self._total_lbl = self._summary_chip("Total lines", "—", col=1)
        self._parsed_lbl = self._summary_chip("Parsed lines", "—", col=2)

        # Results grid: 2×2 cards
        results = ctk.CTkFrame(self, fg_color="transparent")
        results.grid(row=4, column=0, sticky="nsew", padx=30, pady=14)
        results.grid_columnconfigure((0, 1), weight=1)
        results.grid_rowconfigure((0, 1), weight=1)
        self.grid_rowconfigure(4, weight=1)

        # Top IPs
        ip_card = _card(results, "Top IPs")
        ip_card.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=(0, 6))
        ip_card.grid_rowconfigure(1, weight=1)
        ip_card.grid_columnconfigure(0, weight=1)

        self._copy_btn = ctk.CTkButton(ip_card, text="Copy TSV", width=80,
                                       fg_color="#21262d", hover_color="#30363d",
                                       text_color=TEXT_MUTED, font=("Segoe UI", 11),
                                       command=self._copy_ips)
        self._copy_btn.pack(anchor="e", padx=14, pady=(0, 4))

        ip_frame = tk.Frame(ip_card, bg=BG_CARD)
        ip_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self._ip_tree = ttk.Treeview(ip_frame, style="Log.Treeview",
                                     columns=("ip", "count", "pct"), show="headings",
                                     height=12)
        for col, txt, w in [("ip", "IP Address", 130), ("count", "Requests", 80), ("pct", "%", 60)]:
            self._ip_tree.heading(col, text=txt)
            self._ip_tree.column(col, width=w, anchor="w" if col == "ip" else "center")
        vsb = ttk.Scrollbar(ip_frame, orient="vertical", command=self._ip_tree.yview)
        self._ip_tree.configure(yscrollcommand=vsb.set)
        self._ip_tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        # Status codes
        sc_card = _card(results, "Status Code Breakdown")
        sc_card.grid(row=0, column=1, sticky="nsew", padx=(6, 0), pady=(0, 6))
        self._sc_frame = ctk.CTkFrame(sc_card, fg_color="transparent")
        self._sc_frame.pack(fill="both", expand=True, padx=14, pady=(0, 10))

        # Error spike
        err_card = _card(results, "Error Spike (Top 10 Hours)")
        err_card.grid(row=1, column=0, sticky="nsew", padx=(0, 6), pady=(6, 0))
        err_card.grid_rowconfigure(1, weight=1)
        err_card.grid_columnconfigure(0, weight=1)
        err_frame = tk.Frame(err_card, bg=BG_CARD)
        err_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self._err_tree = ttk.Treeview(err_frame, style="Log.Treeview",
                                      columns=("hour", "count"), show="headings", height=10)
        for col, txt, w in [("hour", "Hour", 160), ("count", "Errors", 80)]:
            self._err_tree.heading(col, text=txt)
            self._err_tree.column(col, width=w, anchor="w" if col == "hour" else "center")
        vsb2 = ttk.Scrollbar(err_frame, orient="vertical", command=self._err_tree.yview)
        self._err_tree.configure(yscrollcommand=vsb2.set)
        self._err_tree.pack(side="left", fill="both", expand=True)
        vsb2.pack(side="right", fill="y")

        # Failed auth
        auth_card = _card(results, "Failed Auth (auth.log)")
        auth_card.grid(row=1, column=1, sticky="nsew", padx=(6, 0), pady=(6, 0))
        auth_frame = tk.Frame(auth_card, bg=BG_CARD)
        auth_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self._auth_tree = ttk.Treeview(auth_frame, style="Auth.Treeview",
                                       columns=("type", "value", "count"), show="headings",
                                       height=10)
        for col, txt, w in [("type", "Type", 80), ("value", "Username / IP", 140), ("count", "Attempts", 80)]:
            self._auth_tree.heading(col, text=txt)
            self._auth_tree.column(col, width=w, anchor="w" if col == "value" else "center")
        vsb3 = ttk.Scrollbar(auth_frame, orient="vertical", command=self._auth_tree.yview)
        self._auth_tree.configure(yscrollcommand=vsb3.set)
        self._auth_tree.pack(side="left", fill="both", expand=True)
        vsb3.pack(side="right", fill="y")

    def _summary_chip(self, label: str, value: str, col: int):
        f = ctk.CTkFrame(self._summary_frame, fg_color="transparent")
        f.grid(row=0, column=col, padx=14, pady=10, sticky="w")
        ctk.CTkLabel(f, text=label, font=("Segoe UI", 11), text_color=TEXT_DIM).pack(anchor="w")
        lbl = ctk.CTkLabel(f, text=value, font=("Segoe UI", 14, "bold"), text_color=TEXT_PRIMARY)
        lbl.pack(anchor="w")
        return lbl

    # ── Interactions ──────────────────────────────────────────────────────────

    def _pick_file(self):
        path = filedialog.askopenfilename(
            title="Select a log file",
            filetypes=[("Log files", "*.log *.txt *.gz"), ("All files", "*.*")],
        )
        if path:
            self._file_path = path
            self._path_lbl.configure(text=path, text_color=TEXT_PRIMARY)

    def _start(self):
        if self._running or not self._file_path:
            return
        self._clear_results()
        self._running = True
        self._stop_event.clear()
        self._analyse_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._status_lbl.configure(text="Analysing…", text_color=TEXT_MUTED)
        threading.Thread(target=self._worker, daemon=True).start()
        self._poll_id = self.after(POLL_MS, self._poll)

    def _stop(self):
        self._stop_event.set()

    def _worker(self):
        result = analyse(self._file_path, self._stop_event)
        self._q.put(("done", result))

    def _poll(self):
        try:
            while True:
                tag, data = self._q.get_nowait()
                if tag == "done":
                    self._populate(data)
                    self._running = False
                    self._analyse_btn.configure(state="normal")
                    self._stop_btn.configure(state="disabled")
                    self._status_lbl.configure(text="Analysis complete.", text_color=CLR_OK)
                    return
        except queue.Empty:
            pass
        if self._running:
            self._poll_id = self.after(POLL_MS, self._poll)

    def _clear_results(self):
        for tree in (self._ip_tree, self._err_tree, self._auth_tree):
            tree.delete(*tree.get_children())
        for w in self._sc_frame.winfo_children():
            w.destroy()
        self._fmt_lbl.configure(text="—")
        self._total_lbl.configure(text="—")
        self._parsed_lbl.configure(text="—")

    def _populate(self, s: LogSummary):
        self._fmt_lbl.configure(text=s.format.capitalize())
        self._total_lbl.configure(text=f"{s.total_lines:,}")
        self._parsed_lbl.configure(text=f"{s.parsed_lines:,}")

        total_req = sum(c for _, c in s.top_ips) or 1
        for ip, count in s.top_ips:
            pct = f"{count / total_req * 100:.1f}%"
            self._ip_tree.insert("", "end", values=(ip, count, pct))

        sc_colours = {"2xx": CLR_OK, "3xx": CLR_BLUE, "4xx": CLR_WARN, "5xx": CLR_ERROR}
        for code in ["2xx", "3xx", "4xx", "5xx"]:
            count = s.status_counts.get(code, 0)
            row = ctk.CTkFrame(self._sc_frame, fg_color="transparent")
            row.pack(fill="x", pady=3)
            ctk.CTkLabel(row, text=code, width=40, font=("Segoe UI", 13, "bold"),
                         text_color=sc_colours.get(code, TEXT_MUTED)).pack(side="left")
            ctk.CTkLabel(row, text=f"{count:,}", font=("Segoe UI", 13),
                         text_color=TEXT_PRIMARY).pack(side="left", padx=8)

        for hour, count in s.error_by_hour:
            self._err_tree.insert("", "end", values=(hour, count))

        for user, count in s.failed_auth:
            self._auth_tree.insert("", "end", values=("user", user, count))
        for ip, count in s.failed_auth_ips:
            self._auth_tree.insert("", "end", values=("ip", ip, count))

    def _copy_ips(self):
        rows = ["\t".join(str(v) for v in self._ip_tree.item(iid)["values"])
                for iid in self._ip_tree.get_children()]
        if rows:
            self.clipboard_clear()
            self.clipboard_append("IP\tRequests\t%\n" + "\n".join(rows))
