"""
CyberKit — Credential Tester Page

Two tabs: HTTP (Basic / POST form) and SSH.
"""

import csv
import queue
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, ttk

import customtkinter as ctk
from app.ui.scrollable import autohide_vsb

from app.data.wordlists import DEFAULT_USERNAMES, DEFAULT_PASSWORDS
from app.modules.credential_http_scanner import (
    CredentialHTTPScanner, CredResult,
    STATUS_SUCCESS as HTTP_SUCCESS,
    STATUS_FAILED  as HTTP_FAILED,
    STATUS_ERROR   as HTTP_ERROR,
)
from app.modules.credential_ssh_scanner import (
    CredentialSSHScanner, SSHCredResult,
    STATUS_SUCCESS as SSH_SUCCESS,
    STATUS_FAILED  as SSH_FAILED,
    STATUS_ERROR   as SSH_ERROR,
)
from app.utils.file_helpers import load_wordlist_file

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
CLR_SUCCESS   = "#22c55e"
CLR_FAILED    = "#6b7280"
CLR_ERROR     = "#ef4444"

POLL_MS     = 100
BATCH_LIMIT = 40


class CredentialTesterPage(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, corner_radius=0, **kwargs)

        # ── HTTP state ────────────────────────────────────────────────────────
        self._http_engine: CredentialHTTPScanner | None = None
        self._http_queue:  queue.Queue[CredResult] = queue.Queue()
        self._http_results: list[CredResult] = []
        self._http_running = False
        self._http_poll_id = None
        self._http_user_list: list[str] = list(DEFAULT_USERNAMES)
        self._http_pass_list: list[str] = list(DEFAULT_PASSWORDS)
        self._http_n_success = tk.IntVar(value=0)
        self._http_n_failed  = tk.IntVar(value=0)
        self._http_n_error   = tk.IntVar(value=0)
        self._http_filter    = tk.StringVar(value="All")
        self._http_filter.trace_add("write", lambda *_: self._http_apply_filter())

        # ── SSH state ─────────────────────────────────────────────────────────
        self._ssh_engine: CredentialSSHScanner | None = None
        self._ssh_queue:  queue.Queue[SSHCredResult] = queue.Queue()
        self._ssh_results: list[SSHCredResult] = []
        self._ssh_running = False
        self._ssh_poll_id = None
        self._ssh_user_list: list[str] = list(DEFAULT_USERNAMES)
        self._ssh_pass_list: list[str] = list(DEFAULT_PASSWORDS)

        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # Header
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=30, pady=(28, 0))
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            hdr, text="🔑  Credential Tester",
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            hdr,
            text="Dictionary attack against HTTP Basic / form login and SSH endpoints",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        # Tab bar
        tab_bar = ctk.CTkFrame(self, fg_color="transparent")
        tab_bar.grid(row=1, column=0, sticky="ew", padx=30, pady=(18, 0))

        self._tab_var = tk.StringVar(value="http")

        self._tab_http_btn = ctk.CTkButton(
            tab_bar, text="HTTP",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            width=100, height=34, corner_radius=8,
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color="#0f1117",
            command=lambda: self._switch_tab("http"),
        )
        self._tab_http_btn.grid(row=0, column=0, padx=(0, 6))

        self._tab_ssh_btn = ctk.CTkButton(
            tab_bar, text="SSH",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            width=100, height=34, corner_radius=8,
            fg_color=BG_CARD, hover_color=BG_INPUT,
            text_color=TEXT_MUTED,
            command=lambda: self._switch_tab("ssh"),
        )
        self._tab_ssh_btn.grid(row=0, column=1)

        # Tab content frames (stacked)
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.grid(row=2, column=0, sticky="nsew", padx=30, pady=(12, 30))
        container.grid_columnconfigure(0, weight=1)
        container.grid_rowconfigure(0, weight=1)

        self._http_frame = self._build_http_tab(container)
        self._ssh_frame  = self._build_ssh_tab(container)

        self._http_frame.grid(row=0, column=0, sticky="nsew")
        self._ssh_frame.grid(row=0, column=0, sticky="nsew")
        self._http_frame.tkraise()

    def _switch_tab(self, tab: str):
        self._tab_var.set(tab)
        if tab == "http":
            self._http_frame.tkraise()
            self._tab_http_btn.configure(fg_color=ACCENT_CYAN, hover_color="#00aacc", text_color="#0f1117")
            self._tab_ssh_btn.configure(fg_color=BG_CARD, hover_color=BG_INPUT, text_color=TEXT_MUTED)
        else:
            self._ssh_frame.tkraise()
            self._tab_ssh_btn.configure(fg_color=ACCENT_CYAN, hover_color="#00aacc", text_color="#0f1117")
            self._tab_http_btn.configure(fg_color=BG_CARD, hover_color=BG_INPUT, text_color=TEXT_MUTED)

    # ── HTTP Tab ──────────────────────────────────────────────────────────────

    def _build_http_tab(self, parent) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

        ctrl = ctk.CTkFrame(frame, fg_color=BG_CARD, corner_radius=12,
                            border_width=1, border_color=BORDER_COLOR)
        ctrl.grid(row=0, column=0, sticky="ew")
        ctrl.grid_columnconfigure(1, weight=1)

        # Disclaimer
        ctk.CTkLabel(
            ctrl,
            text="⚠  Only test systems you own or have explicit written permission to test.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color="#f0a500", anchor="w",
        ).grid(row=0, column=0, columnspan=4, sticky="w", padx=18, pady=(14, 6))

        # URL
        ctk.CTkLabel(ctrl, text="Target URL",
                     font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                     text_color=TEXT_MUTED, anchor="w",
                     ).grid(row=1, column=0, sticky="w", padx=(18, 10), pady=(4, 2))

        self._http_error = ctk.CTkLabel(
            ctrl, text="",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=CLR_ERROR, anchor="w",
        )
        self._http_error.grid(row=1, column=1, columnspan=3, sticky="w", pady=(4, 2))

        self._http_url_entry = ctk.CTkEntry(
            ctrl, placeholder_text="http://target/login",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, height=36,
        )
        self._http_url_entry.grid(row=2, column=0, columnspan=4, sticky="ew",
                                  padx=18, pady=(0, 8))

        # Auth mode
        mode_row = ctk.CTkFrame(ctrl, fg_color="transparent")
        mode_row.grid(row=3, column=0, columnspan=4, sticky="w", padx=18, pady=(0, 6))
        ctk.CTkLabel(mode_row, text="Auth Mode:",
                     font=ctk.CTkFont(family="Segoe UI", size=12),
                     text_color=TEXT_MUTED).grid(row=0, column=0, padx=(0, 10))
        self._http_mode = tk.StringVar(value="Basic")
        ctk.CTkSegmentedButton(
            mode_row, values=["Basic", "POST Form"],
            variable=self._http_mode,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            selected_color=ACCENT_CYAN, selected_hover_color="#00aacc",
            unselected_color=BG_INPUT, unselected_hover_color=BG_CARD,
            text_color="#0f1117", fg_color=BG_INPUT,
            command=lambda v: None,
        ).grid(row=0, column=1)

        # Username list
        ctk.CTkLabel(ctrl, text="Username List",
                     font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                     text_color=TEXT_MUTED, anchor="w",
                     ).grid(row=4, column=0, sticky="w", padx=(18, 10), pady=(4, 2))
        self._http_user_label = ctk.CTkLabel(
            ctrl,
            text=f"Default ({len(self._http_user_list)} entries)",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_DIM, anchor="w",
        )
        self._http_user_label.grid(row=4, column=1, sticky="w", pady=(4, 2))
        ctk.CTkButton(
            ctrl, text="Browse…", width=90, height=30, corner_radius=6,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, hover_color=BG_INPUT,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            command=self._http_browse_users,
        ).grid(row=4, column=2, padx=(0, 18), pady=(4, 2))

        # Password list
        ctk.CTkLabel(ctrl, text="Password List",
                     font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                     text_color=TEXT_MUTED, anchor="w",
                     ).grid(row=5, column=0, sticky="w", padx=(18, 10), pady=(0, 4))
        self._http_pass_label = ctk.CTkLabel(
            ctrl,
            text=f"Default ({len(self._http_pass_list)} entries)",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_DIM, anchor="w",
        )
        self._http_pass_label.grid(row=5, column=1, sticky="w", pady=(0, 4))
        ctk.CTkButton(
            ctrl, text="Browse…", width=90, height=30, corner_radius=6,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, hover_color=BG_INPUT,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            command=self._http_browse_passwords,
        ).grid(row=5, column=2, padx=(0, 18), pady=(0, 4))

        # Delay + start
        opts = ctk.CTkFrame(ctrl, fg_color="transparent")
        opts.grid(row=6, column=0, columnspan=4, sticky="ew", padx=18, pady=(4, 8))

        ctk.CTkLabel(opts, text="Threads:",
                     font=ctk.CTkFont(family="Segoe UI", size=12),
                     text_color=TEXT_MUTED).grid(row=0, column=0, padx=(0, 6))
        self._http_thread_val = ctk.CTkLabel(
            opts, text="1",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=ACCENT_CYAN, width=28,
        )
        self._http_thread_val.grid(row=0, column=1, padx=(0, 4))
        self._http_thread_slider = ctk.CTkSlider(
            opts, from_=1, to=10, number_of_steps=9, width=100,
            button_color=ACCENT_CYAN, progress_color=ACCENT_CYAN,
            command=self._on_http_threads,
        )
        self._http_thread_slider.set(1)
        self._http_thread_slider.grid(row=0, column=2, padx=(0, 20))

        ctk.CTkLabel(opts, text="Delay:",
                     font=ctk.CTkFont(family="Segoe UI", size=12),
                     text_color=TEXT_MUTED).grid(row=0, column=3, padx=(0, 6))
        self._http_delay_val = ctk.CTkLabel(
            opts, text="0.5 s",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=ACCENT_CYAN, width=44,
        )
        self._http_delay_val.grid(row=0, column=4, padx=(0, 4))
        self._http_delay_slider = ctk.CTkSlider(
            opts, from_=0.0, to=5.0, number_of_steps=50, width=130,
            button_color=ACCENT_CYAN, progress_color=ACCENT_CYAN,
            command=self._on_http_delay,
        )
        self._http_delay_slider.set(0.5)
        self._http_delay_slider.grid(row=0, column=5, padx=(0, 20))

        self._http_start_btn = ctk.CTkButton(
            opts, text="▶  Start",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color="#0f1117", height=36, width=120, corner_radius=8,
            command=self._toggle_http,
        )
        self._http_start_btn.grid(row=0, column=6)

        # Status / error
        self._http_status = ctk.CTkLabel(
            ctrl, text="Ready",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_MUTED, anchor="w",
        )
        self._http_status.grid(row=7, column=0, columnspan=4, sticky="w",
                               padx=18, pady=(0, 12))

        # ── Summary cards ─────────────────────────────────────────────────────
        summary = ctk.CTkFrame(frame, fg_color="transparent")
        summary.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        for i in range(3):
            summary.grid_columnconfigure(i, weight=1)

        for col, (title, var, color, icon) in enumerate([
            ("Successful",  self._http_n_success, CLR_SUCCESS, "✓"),
            ("Failed",      self._http_n_failed,  CLR_FAILED,  "✕"),
            ("Errors",      self._http_n_error,   CLR_ERROR,   "⚠"),
        ]):
            card = ctk.CTkFrame(summary, fg_color=BG_CARD, corner_radius=10,
                                border_width=1, border_color=BORDER_COLOR)
            card.grid(row=0, column=col, sticky="ew", padx=5)
            card.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(card, text=f"{icon}  {title}",
                         font=ctk.CTkFont(family="Segoe UI", size=11),
                         text_color=TEXT_MUTED).grid(row=0, column=0, pady=(10, 2))
            ctk.CTkLabel(card, textvariable=var,
                         font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
                         text_color=color).grid(row=1, column=0, pady=(0, 10))

        # ── Results table ─────────────────────────────────────────────────────
        wrapper = ctk.CTkFrame(
            frame, fg_color=BG_CARD, corner_radius=12,
            border_width=1, border_color=BORDER_COLOR,
        )
        wrapper.grid(row=2, column=0, sticky="nsew", pady=(10, 0))
        wrapper.grid_columnconfigure(0, weight=1)
        wrapper.grid_rowconfigure(1, weight=1)

        fbar = ctk.CTkFrame(wrapper, fg_color="transparent")
        fbar.grid(row=0, column=0, sticky="ew", padx=16, pady=(10, 6))
        fbar.grid_columnconfigure(0, weight=1)

        self._http_search_entry = ctk.CTkEntry(
            fbar,
            placeholder_text="🔍  Search username, password…",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, height=30,
        )
        self._http_search_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self._http_search_entry.bind("<KeyRelease>", lambda e: self._http_apply_filter())

        ctk.CTkOptionMenu(
            fbar,
            values=["All", "Success", "Failed", "Error"],
            variable=self._http_filter,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color=BG_INPUT, button_color=BORDER_COLOR,
            button_hover_color=BG_CARD, text_color=TEXT_PRIMARY,
            dropdown_fg_color=BG_CARD, dropdown_text_color=TEXT_PRIMARY,
            dropdown_hover_color=BG_INPUT, width=110, height=30, corner_radius=6,
        ).grid(row=0, column=1, padx=(0, 10))

        ctk.CTkButton(
            fbar, text="⬇ CSV", width=70, height=30, corner_radius=6,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, hover_color=BG_INPUT,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            command=lambda: self._export_http("csv"),
        ).grid(row=0, column=2, padx=(0, 6))
        ctk.CTkButton(
            fbar, text="⬇ TXT", width=70, height=30, corner_radius=6,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, hover_color=BG_INPUT,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            command=lambda: self._export_http("txt"),
        ).grid(row=0, column=3)

        style = ttk.Style()
        style.configure("Cred.Treeview",
            background=BG_TABLE_ROW, foreground=TEXT_PRIMARY,
            fieldbackground=BG_TABLE_ROW, rowheight=32, borderwidth=0,
            relief="flat", font=("Segoe UI", 11),
        )
        style.configure("Cred.Treeview.Heading",
            background=BG_INPUT, foreground=TEXT_MUTED,
            borderwidth=0, relief="flat", font=("Segoe UI", 11, "bold"),
        )
        style.map("Cred.Treeview",
            background=[("selected", "#1a2332")],
            foreground=[("selected", TEXT_PRIMARY)],
        )
        style.map("Cred.Treeview.Heading",
            background=[("active", BG_CARD), ("pressed", BG_INPUT)],
            relief=[("active", "flat"), ("pressed", "flat")],
        )
        style.configure("Cred.Vertical.TScrollbar",
            background=BORDER_COLOR, troughcolor=BG_CARD,
            arrowcolor=TEXT_MUTED, borderwidth=0, relief="flat",
        )
        style.map("Cred.Vertical.TScrollbar",
            background=[("active", TEXT_MUTED)],
        )

        tf = tk.Frame(wrapper, bg=BG_CARD)
        tf.grid(row=1, column=0, sticky="nsew")
        tf.grid_columnconfigure(0, weight=1)
        tf.grid_rowconfigure(0, weight=1)

        vsb = ttk.Scrollbar(tf, orient="vertical", style="Cred.Vertical.TScrollbar")
        vsb.grid(row=0, column=1, sticky="ns")

        self._http_tree = ttk.Treeview(
            tf,
            columns=("idx", "username", "password", "status", "code"),
            show="headings",
            height=1,
            style="Cred.Treeview",
            yscrollcommand=autohide_vsb(vsb),
        )
        vsb.configure(command=self._http_tree.yview)
        self._http_tree.grid(row=0, column=0, sticky="nsew")

        for col, heading, width in zip(
            ("idx", "username", "password", "status", "code"),
            ("#", "Username", "Password", "Status", "HTTP Code"),
            (50, 180, 180, 100, 100),
        ):
            self._http_tree.heading(col, text=heading, anchor="w")
            self._http_tree.column(col, width=width, anchor="w",
                                   stretch=(col == "code"), minwidth=40)

        self._http_tree.tag_configure("row_even",  background=BG_TABLE_ROW)
        self._http_tree.tag_configure("row_odd",   background=BG_TABLE_ALT)
        self._http_tree.tag_configure("st_success", foreground=CLR_SUCCESS)
        self._http_tree.tag_configure("st_failed",  foreground=CLR_FAILED)
        self._http_tree.tag_configure("st_error",   foreground=CLR_ERROR)

        self._http_empty = ctk.CTkLabel(
            tf, text="Start a scan to see results here.",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=TEXT_DIM, fg_color="transparent",
        )
        self._http_empty.place(relx=0.5, rely=0.5, anchor="center")

        self._http_result_count = ctk.CTkLabel(
            wrapper, text="0 results shown",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_DIM, anchor="e",
        )
        self._http_result_count.grid(row=2, column=0, sticky="e", padx=16, pady=(4, 10))

        return frame

    def _on_http_threads(self, val):
        self._http_thread_val.configure(text=str(int(val)))

    def _on_http_delay(self, val):
        self._http_delay_val.configure(text=f"{val:.1f} s")

    def _http_browse_users(self):
        entries = load_wordlist_file("Select Username List")
        if entries:
            self._http_user_list = entries
            self._http_user_label.configure(text=f"Custom ({len(entries)} entries)")

    def _http_browse_passwords(self):
        entries = load_wordlist_file("Select Password List")
        if entries:
            self._http_pass_list = entries
            self._http_pass_label.configure(text=f"Custom ({len(entries)} entries)")

    def _toggle_http(self):
        if self._http_running:
            self._stop_http()
        else:
            self._start_http()

    def _start_http(self):
        url = self._http_url_entry.get().strip()
        if not url:
            self._http_error.configure(text="⚠ Please enter a target URL.")
            return
        if not self._http_user_list or not self._http_pass_list:
            self._http_error.configure(text="⚠ Username or password list is empty.")
            return

        self._http_error.configure(text="")
        self._http_results.clear()
        self._http_n_success.set(0)
        self._http_n_failed.set(0)
        self._http_n_error.set(0)
        self._http_result_count.configure(text="0 results shown")
        self._http_queue = queue.Queue()
        self._http_tree.delete(*self._http_tree.get_children())
        self._http_empty.place_forget()
        self._http_status.configure(
            text=f"Testing {len(self._http_user_list)} users × "
                 f"{len(self._http_pass_list)} passwords…",
            text_color=TEXT_MUTED,
        )

        mode = "basic" if self._http_mode.get() == "Basic" else "post"
        delay = self._http_delay_slider.get()
        threads = int(self._http_thread_slider.get())

        self._http_engine = CredentialHTTPScanner(
            url=url,
            usernames=self._http_user_list,
            passwords=self._http_pass_list,
            auth_mode=mode,
            delay_s=delay,
            threads=threads,
        )
        self._http_engine.start(
            on_result=self._on_http_result,
            on_done=lambda: self._http_queue.put(None),
        )
        self._http_running = True
        self._http_start_btn.configure(
            text="⏹  Stop", fg_color="#ef4444",
            hover_color="#cc0000", text_color=TEXT_PRIMARY)
        self._http_url_entry.configure(state="disabled")
        self._poll_http()

    def _stop_http(self):
        if self._http_engine:
            self._http_engine.stop()
        self._finalize_http(aborted=True)

    def _finalize_http(self, aborted=False):
        self._http_running = False
        if self._http_poll_id:
            self.after_cancel(self._http_poll_id)
            self._http_poll_id = None
        self._drain_http_queue()
        self._http_start_btn.configure(
            text="▶  Start", fg_color=ACCENT_CYAN,
            hover_color="#00aacc", text_color="#0f1117")
        self._http_url_entry.configure(state="normal")
        found = sum(1 for r in self._http_results if r.status == HTTP_SUCCESS)
        suffix = " (stopped)" if aborted else " — complete ✓"
        self._http_status.configure(
            text=f"{len(self._http_results)} attempts{suffix}  •  {found} successful",
            text_color=CLR_SUCCESS if found else TEXT_MUTED,
        )

    def _on_http_result(self, result: CredResult):
        self._http_queue.put(result)

    def _poll_http(self):
        done = self._drain_http_queue()
        if done:
            self._finalize_http()
            return
        if self._http_running:
            self._http_poll_id = self.after(POLL_MS, self._poll_http)

    def _drain_http_queue(self) -> bool:
        """Drain up to BATCH_LIMIT results. Returns True when done sentinel received."""
        count = 0
        inserted = 0
        while not self._http_queue.empty() and count < BATCH_LIMIT:
            item = self._http_queue.get_nowait()
            if item is None:
                self._http_result_count.configure(
                    text=f"{len(self._http_tree.get_children())} results shown")
                return True
            r: CredResult = item
            self._http_results.append(r)
            if r.status == HTTP_SUCCESS:
                self._http_n_success.set(self._http_n_success.get() + 1)
            elif r.status == HTTP_FAILED:
                self._http_n_failed.set(self._http_n_failed.get() + 1)
            else:
                self._http_n_error.set(self._http_n_error.get() + 1)
            if self._http_match(r):
                idx = len(self._http_results)
                tag_row = "row_even" if idx % 2 == 0 else "row_odd"
                tag_st = ("st_success" if r.status == HTTP_SUCCESS
                          else "st_failed" if r.status == HTTP_FAILED else "st_error")
                self._http_tree.insert(
                    "", "end",
                    values=(idx, r.username, r.password, r.status, r.code or "—"),
                    tags=(tag_row, tag_st),
                )
                inserted += 1
            count += 1
        if inserted:
            self._http_tree.yview_moveto(1.0)
        if count:
            self._http_result_count.configure(
                text=f"{len(self._http_tree.get_children())} results shown")
        return False

    def _http_match(self, r: CredResult) -> bool:
        filt = self._http_filter.get()
        if filt == "Success" and r.status != HTTP_SUCCESS:
            return False
        if filt == "Failed" and r.status != HTTP_FAILED:
            return False
        if filt == "Error" and r.status != HTTP_ERROR:
            return False
        query = self._http_search_entry.get().strip().lower()
        if query and query not in r.username.lower() and query not in r.password.lower():
            return False
        return True

    def _http_apply_filter(self):
        self._http_tree.delete(*self._http_tree.get_children())
        displayed = 0
        for i, r in enumerate(self._http_results, 1):
            if not self._http_match(r):
                continue
            tag_row = "row_even" if displayed % 2 == 0 else "row_odd"
            tag_st = ("st_success" if r.status == HTTP_SUCCESS
                      else "st_failed" if r.status == HTTP_FAILED else "st_error")
            self._http_tree.insert(
                "", "end",
                values=(i, r.username, r.password, r.status, r.code or "—"),
                tags=(tag_row, tag_st),
            )
            displayed += 1
        self._http_result_count.configure(text=f"{displayed} results shown")

    def _export_http(self, fmt: str):
        if not self._http_results:
            self._http_status.configure(
                text="⚠ No results to export.", text_color=CLR_ERROR)
            return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            defaultextension=f".{fmt}",
            filetypes=[("CSV", "*.csv")] if fmt == "csv" else [("Text", "*.txt")],
            initialfile=f"cyberkit_http_creds_{ts}.{fmt}",
            title="Export Results",
        )
        if not path:
            return
        try:
            if fmt == "csv":
                with open(path, "w", newline="", encoding="utf-8") as f:
                    w = csv.writer(f)
                    w.writerow(["#", "Username", "Password", "Status", "HTTP Code"])
                    for i, r in enumerate(self._http_results, 1):
                        w.writerow([i, r.username, r.password, r.status, r.code])
            else:
                with open(path, "w", encoding="utf-8") as f:
                    f.write("CyberKit — HTTP Credential Tester Results\n")
                    f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 60 + "\n")
                    for i, r in enumerate(self._http_results, 1):
                        f.write(f"{i:<5} {r.username:<20} {r.password:<20} {r.status}\n")
            self._http_status.configure(
                text="Export saved.", text_color=TEXT_MUTED)
        except OSError as e:
            self._http_status.configure(
                text=f"Export failed: {e}", text_color=CLR_ERROR)

    # ── SSH Tab ───────────────────────────────────────────────────────────────

    def _build_ssh_tab(self, parent) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        ctrl = ctk.CTkFrame(frame, fg_color=BG_CARD, corner_radius=12,
                            border_width=1, border_color=BORDER_COLOR)
        ctrl.grid(row=0, column=0, sticky="ew")
        ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            ctrl,
            text="⚠  Only test systems you own or have explicit written permission to test.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color="#f0a500", anchor="w",
        ).grid(row=0, column=0, columnspan=4, sticky="w", padx=18, pady=(14, 6))

        # Host label row (with inline error)
        ctk.CTkLabel(ctrl, text="Host",
                     font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                     text_color=TEXT_MUTED, anchor="w",
                     ).grid(row=1, column=0, sticky="w", padx=(18, 10), pady=(4, 2))

        self._ssh_error = ctk.CTkLabel(
            ctrl, text="",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=CLR_ERROR, anchor="w",
        )
        self._ssh_error.grid(row=1, column=1, columnspan=3, sticky="w", pady=(4, 2))

        # Host + port
        host_row = ctk.CTkFrame(ctrl, fg_color="transparent")
        host_row.grid(row=2, column=0, columnspan=4, sticky="ew",
                      padx=18, pady=(0, 8))
        host_row.grid_columnconfigure(0, weight=1)

        self._ssh_host_entry = ctk.CTkEntry(
            host_row, placeholder_text="192.168.1.10 or hostname",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, height=36,
        )
        self._ssh_host_entry.grid(row=0, column=0, sticky="ew", padx=(0, 12))

        ctk.CTkLabel(host_row, text="Port",
                     font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                     text_color=TEXT_MUTED).grid(row=0, column=1, padx=(0, 8))
        self._ssh_port_entry = ctk.CTkEntry(
            host_row, placeholder_text="22", width=70, height=36,
            font=ctk.CTkFont(family="Segoe UI", size=13),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
        )
        self._ssh_port_entry.insert(0, "22")
        self._ssh_port_entry.grid(row=0, column=2)

        # Username list
        ctk.CTkLabel(ctrl, text="Username List",
                     font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                     text_color=TEXT_MUTED, anchor="w",
                     ).grid(row=3, column=0, sticky="w", padx=(18, 10), pady=(0, 2))
        self._ssh_user_label = ctk.CTkLabel(
            ctrl,
            text=f"Default ({len(self._ssh_user_list)} entries)",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_DIM, anchor="w",
        )
        self._ssh_user_label.grid(row=3, column=1, sticky="w", pady=(0, 2))
        ctk.CTkButton(
            ctrl, text="Browse…", width=90, height=30, corner_radius=6,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, hover_color=BG_INPUT,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            command=self._ssh_browse_users,
        ).grid(row=3, column=2, padx=(0, 18), pady=(0, 2))

        # Password list
        ctk.CTkLabel(ctrl, text="Password List",
                     font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                     text_color=TEXT_MUTED, anchor="w",
                     ).grid(row=4, column=0, sticky="w", padx=(18, 10), pady=(0, 4))
        self._ssh_pass_label = ctk.CTkLabel(
            ctrl,
            text=f"Default ({len(self._ssh_pass_list)} entries)",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_DIM, anchor="w",
        )
        self._ssh_pass_label.grid(row=4, column=1, sticky="w", pady=(0, 4))
        ctk.CTkButton(
            ctrl, text="Browse…", width=90, height=30, corner_radius=6,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, hover_color=BG_INPUT,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            command=self._ssh_browse_passwords,
        ).grid(row=4, column=2, padx=(0, 18), pady=(0, 4))

        # Delay + start
        opts = ctk.CTkFrame(ctrl, fg_color="transparent")
        opts.grid(row=5, column=0, columnspan=4, sticky="ew", padx=18, pady=(4, 8))

        ctk.CTkLabel(opts, text="Delay between attempts:",
                     font=ctk.CTkFont(family="Segoe UI", size=12),
                     text_color=TEXT_MUTED).grid(row=0, column=0, padx=(0, 8))
        self._ssh_delay_val = ctk.CTkLabel(
            opts, text="0.5 s",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=ACCENT_CYAN, width=44,
        )
        self._ssh_delay_val.grid(row=0, column=1, padx=(0, 6))
        self._ssh_delay_slider = ctk.CTkSlider(
            opts, from_=0.0, to=5.0, number_of_steps=50, width=160,
            button_color=ACCENT_CYAN, progress_color=ACCENT_CYAN,
            command=self._on_ssh_delay,
        )
        self._ssh_delay_slider.set(0.5)
        self._ssh_delay_slider.grid(row=0, column=2, padx=(0, 24))

        self._ssh_start_btn = ctk.CTkButton(
            opts, text="▶  Start",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color="#0f1117", height=36, width=120, corner_radius=8,
            command=self._toggle_ssh,
        )
        self._ssh_start_btn.grid(row=0, column=3)

        self._ssh_status = ctk.CTkLabel(
            ctrl, text="Ready",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_MUTED, anchor="w",
        )
        self._ssh_status.grid(row=6, column=0, columnspan=4, sticky="w",
                              padx=18, pady=(0, 12))

        # Results table
        self._ssh_tree, self._ssh_empty = self._build_table(
            frame, row=1,
            columns=("idx", "username", "password", "status", "detail"),
            headings=("#", "Username", "Password", "Status", "Detail"),
            widths=(50, 180, 180, 100, 200),
            style_name="SSH.Treeview",
            export_cmd_csv=lambda: self._export_ssh("csv"),
            export_cmd_txt=lambda: self._export_ssh("txt"),
            empty_text="Start a scan to see results here.",
        )
        return frame

    def _on_ssh_delay(self, val):
        self._ssh_delay_val.configure(text=f"{val:.1f} s")

    def _ssh_browse_users(self):
        entries = load_wordlist_file("Select Username List")
        if entries:
            self._ssh_user_list = entries
            self._ssh_user_label.configure(text=f"Custom ({len(entries)} entries)")

    def _ssh_browse_passwords(self):
        entries = load_wordlist_file("Select Password List")
        if entries:
            self._ssh_pass_list = entries
            self._ssh_pass_label.configure(text=f"Custom ({len(entries)} entries)")

    def _toggle_ssh(self):
        if self._ssh_running:
            self._stop_ssh()
        else:
            self._start_ssh()

    def _start_ssh(self):
        host = self._ssh_host_entry.get().strip()
        if not host:
            self._ssh_error.configure(text="⚠ Please enter a target host.")
            return
        try:
            port = int(self._ssh_port_entry.get().strip() or "22")
        except ValueError:
            self._ssh_error.configure(text="⚠ Port must be an integer.")
            return
        if not self._ssh_user_list or not self._ssh_pass_list:
            self._ssh_error.configure(text="⚠ Username or password list is empty.")
            return
        self._ssh_error.configure(text="")

        self._ssh_results.clear()
        self._ssh_queue = queue.Queue()
        self._ssh_tree.delete(*self._ssh_tree.get_children())
        self._ssh_empty.place_forget()
        self._ssh_status.configure(
            text=f"Testing {len(self._ssh_user_list)} users × "
                 f"{len(self._ssh_pass_list)} passwords against {host}:{port}…",
            text_color=TEXT_MUTED,
        )

        delay = self._ssh_delay_slider.get()
        self._ssh_engine = CredentialSSHScanner(
            host=host, port=port,
            usernames=self._ssh_user_list,
            passwords=self._ssh_pass_list,
            delay_s=delay,
            threads=1,
        )
        self._ssh_engine.start(
            on_result=self._on_ssh_result,
            on_done=lambda: self._ssh_queue.put(None),
        )
        self._ssh_running = True
        self._ssh_start_btn.configure(
            text="⏹  Stop", fg_color="#ef4444",
            hover_color="#cc0000", text_color=TEXT_PRIMARY)
        self._ssh_host_entry.configure(state="disabled")
        self._poll_ssh()

    def _stop_ssh(self):
        if self._ssh_engine:
            self._ssh_engine.stop()
        self._finalize_ssh(aborted=True)

    def _finalize_ssh(self, aborted=False):
        self._ssh_running = False
        if self._ssh_poll_id:
            self.after_cancel(self._ssh_poll_id)
            self._ssh_poll_id = None
        self._drain_ssh_queue()
        self._ssh_start_btn.configure(
            text="▶  Start", fg_color=ACCENT_CYAN,
            hover_color="#00aacc", text_color="#0f1117")
        self._ssh_host_entry.configure(state="normal")
        found = sum(1 for r in self._ssh_results if r.status == SSH_SUCCESS)
        suffix = " (stopped)" if aborted else " — complete ✓"
        self._ssh_status.configure(
            text=f"{len(self._ssh_results)} attempts{suffix}  •  {found} successful",
            text_color=CLR_SUCCESS if found else TEXT_MUTED,
        )

    def _on_ssh_result(self, result: SSHCredResult):
        self._ssh_queue.put(result)

    def _poll_ssh(self):
        done = self._drain_ssh_queue()
        if done:
            self._finalize_ssh()
            return
        if self._ssh_running:
            self._ssh_poll_id = self.after(POLL_MS, self._poll_ssh)

    def _drain_ssh_queue(self) -> bool:
        """Drain up to BATCH_LIMIT results. Returns True when done sentinel received."""
        count = 0
        while not self._ssh_queue.empty() and count < BATCH_LIMIT:
            item = self._ssh_queue.get_nowait()
            if item is None:
                return True
            r: SSHCredResult = item
            self._ssh_results.append(r)
            idx = len(self._ssh_results)
            tag_row = "row_even" if idx % 2 == 0 else "row_odd"
            if r.status == SSH_SUCCESS:
                tag_st = "st_success"
            elif r.status == SSH_FAILED:
                tag_st = "st_failed"
            else:
                tag_st = "st_error"
            self._ssh_tree.insert(
                "", "end",
                values=(idx, r.username, r.password, r.status, r.detail or "—"),
                tags=(tag_row, tag_st),
            )
            count += 1
        if count:
            self._ssh_tree.yview_moveto(1.0)
        return False

    def _export_ssh(self, fmt: str):
        if not self._ssh_results:
            self._ssh_status.configure(
                text="⚠ No results to export.", text_color=CLR_ERROR)
            return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            defaultextension=f".{fmt}",
            filetypes=[("CSV", "*.csv")] if fmt == "csv" else [("Text", "*.txt")],
            initialfile=f"cyberkit_ssh_creds_{ts}.{fmt}",
            title="Export Results",
        )
        if not path:
            return
        try:
            if fmt == "csv":
                with open(path, "w", newline="", encoding="utf-8") as f:
                    w = csv.writer(f)
                    w.writerow(["#", "Username", "Password", "Status", "Detail"])
                    for i, r in enumerate(self._ssh_results, 1):
                        w.writerow([i, r.username, r.password, r.status, r.detail])
            else:
                with open(path, "w", encoding="utf-8") as f:
                    f.write("CyberKit — SSH Credential Tester Results\n")
                    f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 60 + "\n")
                    for i, r in enumerate(self._ssh_results, 1):
                        f.write(f"{i:<5} {r.username:<20} {r.password:<20} {r.status}\n")
            self._ssh_status.configure(text="Export saved.", text_color=TEXT_MUTED)
        except OSError as e:
            self._ssh_status.configure(
                text=f"Export failed: {e}", text_color=CLR_ERROR)

    # ── Shared table builder ──────────────────────────────────────────────────

    def _build_table(
        self, parent, row: int,
        columns: tuple, headings: tuple, widths: tuple,
        style_name: str,
        export_cmd_csv, export_cmd_txt,
        empty_text: str,
    ) -> tuple:
        wrapper = ctk.CTkFrame(
            parent, fg_color=BG_CARD, corner_radius=12,
            border_width=1, border_color=BORDER_COLOR,
        )
        wrapper.grid(row=row, column=0, sticky="nsew", pady=(12, 0))
        wrapper.grid_columnconfigure(0, weight=1)
        wrapper.grid_rowconfigure(1, weight=1)

        # Export buttons
        fbar = ctk.CTkFrame(wrapper, fg_color="transparent")
        fbar.grid(row=0, column=0, sticky="e", padx=16, pady=(10, 6))
        ctk.CTkButton(
            fbar, text="⬇ CSV", width=70, height=30, corner_radius=6,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, hover_color=BG_INPUT,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            command=export_cmd_csv,
        ).grid(row=0, column=0, padx=(0, 6))
        ctk.CTkButton(
            fbar, text="⬇ TXT", width=70, height=30, corner_radius=6,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, hover_color=BG_INPUT,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            command=export_cmd_txt,
        ).grid(row=0, column=1)

        # Style
        style = ttk.Style()
        style.configure(style_name,
            background=BG_TABLE_ROW, foreground=TEXT_PRIMARY,
            fieldbackground=BG_TABLE_ROW, rowheight=32, borderwidth=0,
            relief="flat", font=("Segoe UI", 11),
        )
        style.configure(f"{style_name}.Heading",
            background=BG_INPUT, foreground=TEXT_MUTED,
            borderwidth=0, relief="flat", font=("Segoe UI", 11, "bold"),
        )
        style.map(style_name,
            background=[("selected", "#1a2332")],
            foreground=[("selected", TEXT_PRIMARY)],
        )
        style.map(f"{style_name}.Heading",
            background=[("active", BG_CARD), ("pressed", BG_INPUT)],
            relief=[("active", "flat"), ("pressed", "flat")],
        )
        scroll_style = style_name.replace(".Treeview", "") + ".Vertical.TScrollbar"
        style.configure(scroll_style,
            background=BORDER_COLOR, troughcolor=BG_CARD,
            arrowcolor=TEXT_MUTED, borderwidth=0, relief="flat",
        )
        style.map(scroll_style, background=[("active", TEXT_MUTED)])

        tree_frame = tk.Frame(wrapper, bg=BG_CARD)
        tree_frame.grid(row=1, column=0, sticky="nsew")
        tree_frame.grid_columnconfigure(0, weight=1)
        tree_frame.grid_rowconfigure(0, weight=1)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", style=scroll_style)
        vsb.grid(row=0, column=1, sticky="ns")

        tree = ttk.Treeview(
            tree_frame, columns=columns, show="headings",
            height=1, style=style_name, yscrollcommand=autohide_vsb(vsb),
        )
        vsb.configure(command=tree.yview)
        tree.grid(row=0, column=0, sticky="nsew")

        for col, heading, width in zip(columns, headings, widths):
            tree.heading(col, text=heading, anchor="w")
            tree.column(col, width=width, anchor="w", stretch=col == columns[-1], minwidth=40)

        tree.tag_configure("row_even",  background=BG_TABLE_ROW)
        tree.tag_configure("row_odd",   background=BG_TABLE_ALT)
        tree.tag_configure("st_success", foreground=CLR_SUCCESS)
        tree.tag_configure("st_failed",  foreground=CLR_FAILED)
        tree.tag_configure("st_error",   foreground=CLR_ERROR)

        empty_lbl = ctk.CTkLabel(
            tree_frame, text=empty_text,
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=TEXT_DIM, fg_color="transparent",
        )
        empty_lbl.place(relx=0.5, rely=0.5, anchor="center")

        tree.bind("<<TreeviewSelect>>", lambda e: empty_lbl.place_forget()
                  if tree.get_children() else None)

        return tree, empty_lbl
