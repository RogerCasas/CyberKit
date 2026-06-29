"""
CyberKit — Open Redirect Detector Page (detection only)
"""

import queue
import threading
import tkinter as tk
from tkinter import ttk
from urllib.parse import urlparse, parse_qs

import customtkinter as ctk
from app.ui.scrollable import autohide_vsb

from app.modules.open_redirect import RedirectResult, scan as redirect_scan, SENTINEL

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
CLR_ERROR      = "#ef4444"
WARNING_BG     = "#1a1500"
WARNING_BORDER = "#f0a500"
WARNING_TEXT   = "#f0a500"

POLL_MS = 100


class OpenRedirectPage(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, corner_radius=0, **kwargs)
        self._result_queue: queue.Queue = queue.Queue()
        self._stop_event: threading.Event = threading.Event()
        self._running = False
        self._poll_id = None
        self._row_count = 0
        self._params: list[str] = []
        self._param_row_frames: dict = {}
        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._scroll = ctk.CTkFrame(self, fg_color=BG_MAIN, corner_radius=0)
        self._scroll.grid(row=0, column=0, sticky="nsew")
        self._scroll.grid_columnconfigure(0, weight=1)
        self._scroll.grid_rowconfigure(4, weight=1)  # results table fills leftover space

        hdr = ctk.CTkFrame(self._scroll, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=30, pady=(28, 0))
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            hdr, text="↪  Open Redirect Detector",
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            hdr,
            text="Detect unvalidated redirects  •  External-host payloads, Location header inspection",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        banner = ctk.CTkFrame(self._scroll, fg_color=WARNING_BG, corner_radius=8,
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
        self._build_params()
        self._build_table()

    def _build_controls(self):
        ctrl = ctk.CTkFrame(self._scroll, fg_color=BG_CARD, corner_radius=12,
                            border_width=1, border_color=BORDER_COLOR)
        ctrl.grid(row=2, column=0, sticky="ew", padx=30, pady=(14, 0))
        ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            ctrl, text="Target URL",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED,
        ).grid(row=0, column=0, padx=(18, 10), pady=(14, 4), sticky="w")

        self._inline_error = ctk.CTkLabel(
            ctrl, text="",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=CLR_ERROR, anchor="w",
        )
        self._inline_error.grid(row=0, column=1, sticky="w", padx=(0, 18), pady=(14, 4))

        self._url_entry = ctk.CTkEntry(
            ctrl,
            placeholder_text="http://localhost/login?next=/home",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, height=38,
        )
        self._url_entry.grid(row=1, column=0, columnspan=2, sticky="ew",
                             padx=18, pady=(0, 8))

        btn_row = ctk.CTkFrame(ctrl, fg_color="transparent")
        btn_row.grid(row=2, column=0, columnspan=2, sticky="w", padx=18, pady=(0, 14))

        self._method = "GET"
        self._get_btn = ctk.CTkButton(
            btn_row, text="GET",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            width=60, height=32, corner_radius=6,
            fg_color=ACCENT_CYAN, hover_color="#00aacc", text_color="#0f1117",
            command=lambda: self._set_method("GET"),
        )
        self._get_btn.grid(row=0, column=0, padx=(0, 4))

        self._post_btn = ctk.CTkButton(
            btn_row, text="POST",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            width=60, height=32, corner_radius=6,
            fg_color=BG_INPUT, hover_color=BG_CARD,
            border_width=1, border_color=BORDER_COLOR, text_color=TEXT_MUTED,
            command=lambda: self._set_method("POST"),
        )
        self._post_btn.grid(row=0, column=1, padx=(0, 12))

        self._scan_btn = ctk.CTkButton(
            btn_row, text="▶  Scan",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color="#0f1117", height=36, width=110, corner_radius=8,
            command=self._start_scan,
        )
        self._scan_btn.grid(row=0, column=2, padx=(0, 8))

        self._stop_btn = ctk.CTkButton(
            btn_row, text="■  Stop",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=BG_INPUT, hover_color=BG_CARD,
            border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, height=36, width=110, corner_radius=8,
            state="disabled", command=self._stop_scan,
        )
        self._stop_btn.grid(row=0, column=3, padx=(0, 12))

        self._status_lbl = ctk.CTkLabel(
            btn_row, text="Configure target and parameters, then click Scan.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_MUTED, anchor="w",
        )
        self._status_lbl.grid(row=0, column=4)

    def _build_params(self):
        card = ctk.CTkFrame(self._scroll, fg_color=BG_CARD, corner_radius=12,
                            border_width=1, border_color=BORDER_COLOR)
        card.grid(row=3, column=0, sticky="ew", padx=30, pady=(10, 0))
        card.grid_columnconfigure(0, weight=1)

        top = ctk.CTkFrame(card, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=12, pady=(10, 4))
        top.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            top, text="Parameters to test",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=0, column=0, sticky="w")

        self._parse_error = ctk.CTkLabel(
            top, text="",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=CLR_ERROR, anchor="w",
        )
        self._parse_error.grid(row=0, column=1, sticky="w", padx=(8, 0))

        ctk.CTkButton(
            top, text="Parse from URL",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            fg_color="transparent", hover_color=BG_INPUT,
            border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, height=28, corner_radius=6,
            command=self._parse_params_from_url,
        ).grid(row=0, column=2)

        # Plain frame (not CTkScrollableFrame, which ignores `height` and balloons
        # its requested size, starving the results table below). Params are few;
        # the outer page scrolls if the list ever grows tall.
        self._params_scroll = ctk.CTkFrame(card, fg_color="transparent", corner_radius=0)
        self._params_scroll.grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 4))

        self._params_placeholder = ctk.CTkLabel(
            self._params_scroll,
            text="No parameters — parse from URL or add manually.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_DIM,
        )
        self._params_placeholder.pack(pady=8)

        add_row = ctk.CTkFrame(card, fg_color="transparent")
        add_row.grid(row=2, column=0, sticky="w", padx=12, pady=(0, 10))

        self._add_param_entry = ctk.CTkEntry(
            add_row, width=180, height=28,
            placeholder_text="param_name",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
        )
        self._add_param_entry.grid(row=0, column=0, padx=(0, 6))
        self._add_param_entry.bind("<Return>", lambda e: self._add_param_from_entry())

        ctk.CTkButton(
            add_row, text="+ Add",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            fg_color="transparent", hover_color=BG_INPUT,
            border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, height=28, width=60, corner_radius=6,
            command=self._add_param_from_entry,
        ).grid(row=0, column=1)

        ctk.CTkLabel(
            card,
            text=f"Payloads target the sentinel host '{SENTINEL}' "
                 "(scheme-relative, absolute, backslash, and suffix-bypass variants). "
                 "A 3xx Location pointing at the sentinel is flagged vulnerable.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_DIM, anchor="w", justify="left", wraplength=900,
        ).grid(row=3, column=0, sticky="w", padx=14, pady=(0, 12))

    def _build_table(self):
        wrapper = ctk.CTkFrame(self._scroll, fg_color=BG_CARD, corner_radius=12,
                               border_width=1, border_color=BORDER_COLOR)
        wrapper.grid(row=4, column=0, sticky="nsew", padx=30, pady=(10, 30))
        wrapper.grid_columnconfigure(0, weight=1)
        wrapper.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            wrapper, text="Redirect Results",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(12, 8))

        style = ttk.Style()
        style.configure("Redir.Treeview",
            background=BG_TABLE_ROW, foreground=TEXT_PRIMARY,
            fieldbackground=BG_TABLE_ROW, rowheight=34,
            borderwidth=0, relief="flat", font=("Segoe UI", 11))
        style.configure("Redir.Treeview.Heading",
            background=BG_INPUT, foreground=TEXT_MUTED,
            borderwidth=0, relief="flat", font=("Segoe UI", 11, "bold"))
        style.map("Redir.Treeview",
            background=[("selected", "#1a2332")],
            foreground=[("selected", TEXT_PRIMARY)])
        style.map("Redir.Treeview.Heading",
            background=[("active", BG_CARD), ("pressed", BG_INPUT)],
            relief=[("active", "flat"), ("pressed", "flat")])
        style.configure("Redir.Vertical.TScrollbar",
            background=BORDER_COLOR, troughcolor=BG_CARD,
            arrowcolor=TEXT_MUTED, borderwidth=0, relief="flat")
        style.map("Redir.Vertical.TScrollbar", background=[("active", TEXT_MUTED)])

        tree_frame = tk.Frame(wrapper, bg=BG_CARD)
        tree_frame.grid(row=1, column=0, sticky="nsew")
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical",
                            style="Redir.Vertical.TScrollbar")
        vsb.grid(row=0, column=1, sticky="ns")

        self._tree = ttk.Treeview(
            tree_frame,
            columns=("param", "payload", "status", "location", "verdict"),
            show="headings", style="Redir.Treeview",
            yscrollcommand=autohide_vsb(vsb), height=6,
        )
        vsb.configure(command=self._tree.yview)
        self._tree.grid(row=0, column=0, sticky="nsew")

        for col, head, w, anc, stretch, mw in [
            ("param",    "Parameter", 100, "w",      False, 70),
            ("payload",  "Payload",   200, "w",      False, 120),
            ("status",   "Status",    70,  "center", False, 60),
            ("location", "Location",  280, "w",      True,  140),
            ("verdict",  "Verdict",   100, "center", False, 80),
        ]:
            self._tree.heading(col, text=head, anchor=anc)
            self._tree.column(col, width=w, anchor=anc, stretch=stretch, minwidth=mw)

        self._tree.tag_configure("vulnerable", foreground=CLR_ERROR)
        self._tree.tag_configure("clean",      foreground=CLR_OK)
        self._tree.tag_configure("row_even",   background=BG_TABLE_ROW)
        self._tree.tag_configure("row_odd",    background=BG_TABLE_ALT)

        self._empty_label = ctk.CTkLabel(
            tree_frame, text="Run a scan to see results.",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=TEXT_DIM, fg_color="transparent",
        )
        self._empty_label.place(relx=0.5, rely=0.5, anchor="center")

    # ── Method toggle ─────────────────────────────────────────────────────────

    def _set_method(self, method: str):
        self._method = method
        if method == "GET":
            self._get_btn.configure(fg_color=ACCENT_CYAN, hover_color="#00aacc", text_color="#0f1117")
            self._post_btn.configure(fg_color=BG_INPUT, hover_color=BG_CARD,
                                     border_color=BORDER_COLOR, text_color=TEXT_MUTED)
        else:
            self._post_btn.configure(fg_color=ACCENT_CYAN, hover_color="#00aacc", text_color="#0f1117")
            self._get_btn.configure(fg_color=BG_INPUT, hover_color=BG_CARD,
                                    border_color=BORDER_COLOR, text_color=TEXT_MUTED)

    # ── Parameters management ─────────────────────────────────────────────────

    def _parse_params_from_url(self):
        self._parse_error.configure(text="")
        url = self._url_entry.get().strip()
        if not url:
            self._parse_error.configure(text="Enter a URL first.")
            return
        parsed = urlparse(url if "://" in url else "http://" + url)
        found = list(parse_qs(parsed.query).keys())
        if not found:
            self._parse_error.configure(text="No query parameters found.")
            return
        for w in self._params_scroll.winfo_children():
            w.destroy()
        self._params.clear()
        self._param_row_frames.clear()
        for p in found:
            self._add_param(p)

    def _add_param_from_entry(self):
        name = self._add_param_entry.get().strip()
        if not name:
            return
        self._add_param(name)
        self._add_param_entry.delete(0, "end")

    def _add_param(self, name: str):
        if name in self._params:
            return
        self._params.append(name)

        row = ctk.CTkFrame(self._params_scroll, fg_color="transparent")
        row.pack(fill="x", pady=1)
        ctk.CTkLabel(
            row, text=f"  {name}",
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color=TEXT_PRIMARY, anchor="w",
        ).pack(side="left")

        def remove(n=name, r=row):
            r.destroy()
            if n in self._params:
                self._params.remove(n)
            if n in self._param_row_frames:
                del self._param_row_frames[n]

        ctk.CTkButton(
            row, text="×", width=26, height=22, corner_radius=4,
            fg_color="transparent", hover_color=BG_INPUT,
            border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, font=ctk.CTkFont(size=11),
            command=remove,
        ).pack(side="right", padx=(0, 4))

        self._param_row_frames[name] = row
        if hasattr(self, "_params_placeholder"):
            try:
                self._params_placeholder.pack_forget()
            except Exception:
                pass

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
        if not self._params:
            self._inline_error.configure(text="Add at least one parameter to test.")
            return

        self._running = True
        self._stop_event = threading.Event()
        self._result_queue = queue.Queue()
        self._row_count = 0
        self._tree.delete(*self._tree.get_children())
        self._empty_label.place_forget()

        self._scan_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._status_lbl.configure(
            text=f"Scanning {len(self._params)} parameter(s)…", text_color=TEXT_MUTED)

        threading.Thread(
            target=self._run_scan,
            args=(url, self._method, list(self._params)),
            daemon=True,
        ).start()
        self._poll_id = self.after(POLL_MS, self._poll)

    def _stop_scan(self):
        self._stop_event.set()
        self._stop_btn.configure(state="disabled")
        self._status_lbl.configure(text="Stopping…")

    def _run_scan(self, url, method, params):
        try:
            redirect_scan(
                url, method, params, timeout=10,
                progress_cb=lambda c, t: self._result_queue.put(("progress", c, t)),
                result_cb=lambda r: self._result_queue.put(("result", r)),
                stop_event=self._stop_event,
            )
            self._result_queue.put(("done",))
        except Exception as exc:
            self._result_queue.put(("error", str(exc)))

    def _poll(self):
        drained = 0
        while drained < 20:
            try:
                msg = self._result_queue.get_nowait()
            except queue.Empty:
                break
            drained += 1
            kind = msg[0]
            if kind == "progress":
                _, current, total = msg
                self._status_lbl.configure(
                    text=f"Scanning parameter {current}/{total}…", text_color=TEXT_MUTED)
            elif kind == "result":
                self._insert_row(msg[1])
            elif kind == "done":
                self._finish_scan(stopped=False)
                return
            elif kind == "error":
                self._inline_error.configure(text=f"Error: {msg[1]}")
                self._finish_scan(stopped=True)
                return
        self._poll_id = self.after(POLL_MS, self._poll)

    def _insert_row(self, r: RedirectResult):
        tag = "vulnerable" if r.is_vulnerable else "clean"
        alt = "row_even" if self._row_count % 2 == 0 else "row_odd"
        verdict = "VULNERABLE" if r.is_vulnerable else "Clean"
        status = str(r.status_code) if r.status_code else "—"
        self._tree.insert(
            "", "end",
            values=(r.parameter, r.payload, status, r.location or "—", verdict),
            tags=(tag, alt),
        )
        self._row_count += 1

    def _finish_scan(self, stopped: bool):
        self._running = False
        self._scan_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")
        vuln = sum(
            1 for iid in self._tree.get_children()
            if "vulnerable" in self._tree.item(iid, "tags")
        )
        suffix = " (stopped)" if stopped else ""
        self._status_lbl.configure(
            text=f"Done{suffix}  —  {vuln} open redirect(s) across {self._row_count} parameter(s)",
            text_color=CLR_ERROR if vuln else CLR_OK,
        )
