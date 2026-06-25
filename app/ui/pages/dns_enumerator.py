"""
CyberKit — DNS & Subdomain Enumerator Page

Two tabs: Record Lookup and Subdomain Brute-Force.
"""

import csv
import queue
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, ttk

import customtkinter as ctk

from app.data.wordlists import SUBDOMAIN_WORDLIST
from app.modules.dns_lookup_scanner import resolve_records, DNSRecord, SUPPORTED_TYPES
from app.modules.subdomain_scanner import (
    SubdomainScanner, SubdomainResult,
    STATUS_FOUND, STATUS_NOT_FOUND, STATUS_ERROR,
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
CLR_FOUND     = "#22c55e"
CLR_NOT_FOUND = "#6b7280"
CLR_ERROR     = "#ef4444"

POLL_MS     = 100
BATCH_LIMIT = 60


class DNSEnumeratorPage(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, corner_radius=0, **kwargs)

        # Subdomain brute-force state
        self._sub_engine: SubdomainScanner | None = None
        self._sub_queue:  queue.Queue[SubdomainResult] = queue.Queue()
        self._sub_results: list[SubdomainResult] = []
        self._sub_running  = False
        self._sub_poll_id  = None
        self._sub_wordlist: list[str] = list(SUBDOMAIN_WORDLIST)
        self._sub_use_custom = False

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
            hdr, text="🌐  DNS & Subdomain Enumerator",
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            hdr,
            text="Resolve DNS records and brute-force subdomains using a wordlist",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        # Tab bar
        tab_bar = ctk.CTkFrame(self, fg_color="transparent")
        tab_bar.grid(row=1, column=0, sticky="ew", padx=30, pady=(18, 0))

        self._tab_lookup_btn = ctk.CTkButton(
            tab_bar, text="Record Lookup",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            width=140, height=34, corner_radius=8,
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color="#0f1117",
            command=lambda: self._switch_tab("lookup"),
        )
        self._tab_lookup_btn.grid(row=0, column=0, padx=(0, 6))

        self._tab_brute_btn = ctk.CTkButton(
            tab_bar, text="Subdomain Brute-Force",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            width=180, height=34, corner_radius=8,
            fg_color=BG_CARD, hover_color=BG_INPUT,
            text_color=TEXT_MUTED,
            command=lambda: self._switch_tab("brute"),
        )
        self._tab_brute_btn.grid(row=0, column=1)

        # Stacked tab frames
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.grid(row=2, column=0, sticky="nsew", padx=30, pady=(12, 30))
        container.grid_columnconfigure(0, weight=1)
        container.grid_rowconfigure(0, weight=1)

        self._lookup_frame = self._build_lookup_tab(container)
        self._brute_frame  = self._build_brute_tab(container)

        self._lookup_frame.grid(row=0, column=0, sticky="nsew")
        self._brute_frame.grid(row=0, column=0, sticky="nsew")
        self._lookup_frame.tkraise()

    def _switch_tab(self, tab: str):
        if tab == "lookup":
            self._lookup_frame.tkraise()
            self._tab_lookup_btn.configure(fg_color=ACCENT_CYAN, hover_color="#00aacc", text_color="#0f1117")
            self._tab_brute_btn.configure(fg_color=BG_CARD, hover_color=BG_INPUT, text_color=TEXT_MUTED)
        else:
            self._brute_frame.tkraise()
            self._tab_brute_btn.configure(fg_color=ACCENT_CYAN, hover_color="#00aacc", text_color="#0f1117")
            self._tab_lookup_btn.configure(fg_color=BG_CARD, hover_color=BG_INPUT, text_color=TEXT_MUTED)

    # ── Record Lookup Tab ─────────────────────────────────────────────────────

    def _build_lookup_tab(self, parent) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        ctrl = ctk.CTkFrame(frame, fg_color=BG_CARD, corner_radius=12,
                            border_width=1, border_color=BORDER_COLOR)
        ctrl.grid(row=0, column=0, sticky="ew")
        ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            ctrl,
            text="⚠  Only enumerate domains you own or have explicit permission to query.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color="#f0a500", anchor="w",
        ).grid(row=0, column=0, columnspan=3, sticky="w", padx=18, pady=(14, 6))

        # Domain entry + resolve button
        input_row = ctk.CTkFrame(ctrl, fg_color="transparent")
        input_row.grid(row=1, column=0, columnspan=3, sticky="ew",
                       padx=18, pady=(4, 8))
        input_row.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(input_row, text="Domain",
                     font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                     text_color=TEXT_MUTED).grid(row=0, column=0, padx=(0, 10))

        self._lookup_error = ctk.CTkLabel(
            input_row, text="",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=CLR_ERROR, anchor="w",
        )
        self._lookup_error.grid(row=1, column=0, columnspan=3, sticky="w", pady=(2, 0))

        self._lookup_domain_entry = ctk.CTkEntry(
            input_row, placeholder_text="example.com",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, height=36,
        )
        self._lookup_domain_entry.grid(row=0, column=1, sticky="ew", padx=(0, 12))
        self._resolve_btn = ctk.CTkButton(
            input_row, text="Resolve",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color="#0f1117", height=36, width=100, corner_radius=8,
            command=self._run_lookup,
        )
        self._resolve_btn.grid(row=0, column=2)

        # Record type checkboxes
        types_row = ctk.CTkFrame(ctrl, fg_color="transparent")
        types_row.grid(row=2, column=0, columnspan=3, sticky="w",
                       padx=18, pady=(0, 10))
        ctk.CTkLabel(types_row, text="Record types:",
                     font=ctk.CTkFont(family="Segoe UI", size=12),
                     text_color=TEXT_MUTED).grid(row=0, column=0, padx=(0, 12))
        self._lookup_type_vars: dict[str, tk.BooleanVar] = {}
        for i, rtype in enumerate(SUPPORTED_TYPES):
            var = tk.BooleanVar(value=True)
            self._lookup_type_vars[rtype] = var
            ctk.CTkCheckBox(
                types_row, text=rtype, variable=var,
                font=ctk.CTkFont(family="Segoe UI", size=12),
                text_color=TEXT_MUTED,
                checkmark_color="#0f1117",
                fg_color=ACCENT_CYAN, hover_color="#00aacc",
                width=60,
            ).grid(row=0, column=i + 1, padx=(0, 8))

        # Status
        self._lookup_status = ctk.CTkLabel(
            ctrl, text="",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_MUTED, anchor="w",
        )
        self._lookup_status.grid(row=3, column=0, columnspan=3, sticky="w",
                                 padx=18, pady=(0, 12))

        # Results table
        wrapper = ctk.CTkFrame(
            frame, fg_color=BG_CARD, corner_radius=12,
            border_width=1, border_color=BORDER_COLOR,
        )
        wrapper.grid(row=1, column=0, sticky="nsew", pady=(12, 0))
        wrapper.grid_columnconfigure(0, weight=1)
        wrapper.grid_rowconfigure(1, weight=1)

        # Export button
        fbar = ctk.CTkFrame(wrapper, fg_color="transparent")
        fbar.grid(row=0, column=0, sticky="e", padx=16, pady=(10, 6))
        ctk.CTkButton(
            fbar, text="⬇ TXT", width=70, height=30, corner_radius=6,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, hover_color=BG_INPUT,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            command=self._export_lookup,
        ).grid(row=0, column=0)

        style = ttk.Style()
        style.configure("DNS.Treeview",
            background=BG_TABLE_ROW, foreground=TEXT_PRIMARY,
            fieldbackground=BG_TABLE_ROW, rowheight=32, borderwidth=0,
            relief="flat", font=("Segoe UI", 11),
        )
        style.configure("DNS.Treeview.Heading",
            background=BG_INPUT, foreground=TEXT_MUTED,
            borderwidth=0, relief="flat", font=("Segoe UI", 11, "bold"),
        )
        style.map("DNS.Treeview",
            background=[("selected", "#1a2332")],
            foreground=[("selected", TEXT_PRIMARY)],
        )
        style.map("DNS.Treeview.Heading",
            background=[("active", BG_CARD), ("pressed", BG_INPUT)],
            relief=[("active", "flat"), ("pressed", "flat")],
        )
        style.configure("DNS.Vertical.TScrollbar",
            background=BORDER_COLOR, troughcolor=BG_CARD,
            arrowcolor=TEXT_MUTED, borderwidth=0, relief="flat",
        )
        style.map("DNS.Vertical.TScrollbar",
            background=[("active", TEXT_MUTED)],
        )

        tf = tk.Frame(wrapper, bg=BG_CARD)
        tf.grid(row=1, column=0, sticky="nsew")
        tf.grid_columnconfigure(0, weight=1)
        tf.grid_rowconfigure(0, weight=1)

        vsb = ttk.Scrollbar(tf, orient="vertical", style="DNS.Vertical.TScrollbar")
        vsb.grid(row=0, column=1, sticky="ns")

        self._lookup_tree = ttk.Treeview(
            tf,
            columns=("rtype", "value", "ttl"),
            show="headings",
            style="DNS.Treeview",
            yscrollcommand=vsb.set,
        )
        vsb.configure(command=self._lookup_tree.yview)
        self._lookup_tree.grid(row=0, column=0, sticky="nsew")

        self._lookup_tree.heading("rtype", text="Type",  anchor="w")
        self._lookup_tree.heading("value", text="Value", anchor="w")
        self._lookup_tree.heading("ttl",   text="TTL",   anchor="center")
        self._lookup_tree.column("rtype", width=80,  anchor="w",      stretch=False, minwidth=60)
        self._lookup_tree.column("value", width=500, anchor="w",      stretch=True,  minwidth=200)
        self._lookup_tree.column("ttl",   width=80,  anchor="center", stretch=False, minwidth=60)

        self._lookup_tree.tag_configure("row_even", background=BG_TABLE_ROW)
        self._lookup_tree.tag_configure("row_odd",  background=BG_TABLE_ALT)
        self._lookup_tree.tag_configure("t_a",    foreground=ACCENT_CYAN)
        self._lookup_tree.tag_configure("t_mx",   foreground="#f59e0b")
        self._lookup_tree.tag_configure("t_ns",   foreground="#7c3aed")
        self._lookup_tree.tag_configure("t_txt",  foreground="#8b949e")
        self._lookup_tree.tag_configure("t_aaaa", foreground="#00d4ff")

        self._lookup_empty = ctk.CTkLabel(
            tf, text="Enter a domain and click Resolve.",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=TEXT_DIM, fg_color="transparent",
        )
        self._lookup_empty.place(relx=0.5, rely=0.5, anchor="center")

        # Store lookup records for export
        self._lookup_records: list[DNSRecord] = []
        self._lookup_domain_used = ""

        return frame

    def _run_lookup(self):
        domain = self._lookup_domain_entry.get().strip()
        if not domain:
            self._lookup_error.configure(text="⚠ Please enter a domain.")
            return

        selected = [t for t, v in self._lookup_type_vars.items() if v.get()]
        if not selected:
            self._lookup_error.configure(text="⚠ Select at least one record type.")
            return

        self._lookup_error.configure(text="")
        self._lookup_status.configure(text=f"Resolving {domain}…", text_color=TEXT_MUTED)
        self._resolve_btn.configure(state="disabled")
        self._lookup_tree.delete(*self._lookup_tree.get_children())
        self._lookup_empty.place_forget()
        self.update_idletasks()

        records, errors = resolve_records(domain, selected)
        self._lookup_records = records
        self._lookup_domain_used = domain

        if not records:
            msg = "No records found."
            if errors:
                msg += "  " + "; ".join(errors)
            self._lookup_empty.configure(text=msg)
            self._lookup_empty.place(relx=0.5, rely=0.5, anchor="center")
            self._lookup_status.configure(text="Done — no records returned.", text_color=TEXT_MUTED)
        else:
            for i, r in enumerate(records):
                tag_row = "row_even" if i % 2 == 0 else "row_odd"
                tag_t   = f"t_{r.record_type.lower()}"
                self._lookup_tree.insert(
                    "", "end",
                    values=(r.record_type, r.value, r.ttl),
                    tags=(tag_row, tag_t),
                )
            err_note = f"  ({'; '.join(errors)})" if errors else ""
            self._lookup_status.configure(
                text=f"{len(records)} record(s) found.{err_note}",
                text_color=CLR_FOUND,
            )

        self._resolve_btn.configure(state="normal")

    def _export_lookup(self):
        if not self._lookup_records:
            self._lookup_status.configure(
                text="⚠ No records to export.", text_color=CLR_ERROR)
            return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
            initialfile=f"cyberkit_dns_{ts}.txt",
            title="Export DNS Records",
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(f"CyberKit — DNS Record Lookup\n")
                f.write(f"Domain : {self._lookup_domain_used}\n")
                f.write(f"Date   : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 60 + "\n")
                for r in self._lookup_records:
                    f.write(f"{r.record_type:<8} TTL={r.ttl:<8} {r.value}\n")
            self._lookup_status.configure(text="Export saved.", text_color=TEXT_MUTED)
        except OSError as e:
            self._lookup_status.configure(
                text=f"Export failed: {e}", text_color=CLR_ERROR)

    # ── Subdomain Brute-Force Tab ─────────────────────────────────────────────

    def _build_brute_tab(self, parent) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        ctrl = ctk.CTkFrame(frame, fg_color=BG_CARD, corner_radius=12,
                            border_width=1, border_color=BORDER_COLOR)
        ctrl.grid(row=0, column=0, sticky="ew")
        ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            ctrl,
            text="⚠  Only enumerate domains you own or have explicit permission to query.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color="#f0a500", anchor="w",
        ).grid(row=0, column=0, columnspan=4, sticky="w", padx=18, pady=(14, 6))

        # Domain
        ctk.CTkLabel(ctrl, text="Domain",
                     font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                     text_color=TEXT_MUTED, anchor="w",
                     ).grid(row=1, column=0, sticky="w", padx=(18, 10), pady=(4, 2))

        self._brute_error = ctk.CTkLabel(
            ctrl, text="",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=CLR_ERROR, anchor="w",
        )
        self._brute_error.grid(row=1, column=1, columnspan=3, sticky="w", pady=(4, 2))

        self._brute_domain_entry = ctk.CTkEntry(
            ctrl, placeholder_text="example.com",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, height=36,
        )
        self._brute_domain_entry.grid(row=2, column=0, columnspan=4, sticky="ew",
                                       padx=18, pady=(0, 8))

        # Wordlist row
        wl_row = ctk.CTkFrame(ctrl, fg_color="transparent")
        wl_row.grid(row=3, column=0, columnspan=4, sticky="w", padx=18, pady=(0, 8))

        ctk.CTkLabel(wl_row, text="Wordlist:",
                     font=ctk.CTkFont(family="Segoe UI", size=12),
                     text_color=TEXT_MUTED).grid(row=0, column=0, padx=(0, 10))
        self._wl_var = tk.StringVar(value="Bundled")
        ctk.CTkSegmentedButton(
            wl_row, values=["Bundled", "Custom"],
            variable=self._wl_var,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            selected_color=ACCENT_CYAN, selected_hover_color="#00aacc",
            unselected_color=BG_INPUT, unselected_hover_color=BG_CARD,
            text_color="#0f1117", fg_color=BG_INPUT,
            command=self._on_wl_mode_change,
        ).grid(row=0, column=1, padx=(0, 12))
        self._wl_info_label = ctk.CTkLabel(
            wl_row,
            text=f"{len(SUBDOMAIN_WORDLIST)} entries",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_DIM,
        )
        self._wl_info_label.grid(row=0, column=2, padx=(0, 10))
        self._wl_browse_btn = ctk.CTkButton(
            wl_row, text="Browse…", width=90, height=30, corner_radius=6,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, hover_color=BG_INPUT,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            state="disabled",
            command=self._brute_browse_wordlist,
        )
        self._wl_browse_btn.grid(row=0, column=3)

        # Threads + start
        opts = ctk.CTkFrame(ctrl, fg_color="transparent")
        opts.grid(row=4, column=0, columnspan=4, sticky="ew", padx=18, pady=(0, 8))

        ctk.CTkLabel(opts, text="Threads:",
                     font=ctk.CTkFont(family="Segoe UI", size=12),
                     text_color=TEXT_MUTED).grid(row=0, column=0, padx=(0, 8))
        self._brute_thread_val = ctk.CTkLabel(
            opts, text="20",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=ACCENT_CYAN, width=36,
        )
        self._brute_thread_val.grid(row=0, column=1, padx=(0, 6))
        self._brute_thread_slider = ctk.CTkSlider(
            opts, from_=5, to=100, number_of_steps=19, width=140,
            button_color=ACCENT_CYAN, progress_color=ACCENT_CYAN,
            command=self._on_brute_threads,
        )
        self._brute_thread_slider.set(20)
        self._brute_thread_slider.grid(row=0, column=2, padx=(0, 24))

        self._brute_start_btn = ctk.CTkButton(
            opts, text="▶  Start",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color="#0f1117", height=36, width=120, corner_radius=8,
            command=self._toggle_brute,
        )
        self._brute_start_btn.grid(row=0, column=3)

        # Progress bar + status
        self._brute_progress = ctk.CTkProgressBar(
            ctrl, fg_color=BG_INPUT, progress_color=ACCENT_CYAN, height=6,
        )
        self._brute_progress.set(0)
        self._brute_progress.grid(row=5, column=0, columnspan=4, sticky="ew",
                                   padx=18, pady=(0, 6))

        self._brute_status = ctk.CTkLabel(
            ctrl, text="Ready",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_MUTED, anchor="w",
        )
        self._brute_status.grid(row=6, column=0, columnspan=4, sticky="w",
                                 padx=18, pady=(0, 12))

        # Results table
        wrapper = ctk.CTkFrame(
            frame, fg_color=BG_CARD, corner_radius=12,
            border_width=1, border_color=BORDER_COLOR,
        )
        wrapper.grid(row=1, column=0, sticky="nsew", pady=(12, 0))
        wrapper.grid_columnconfigure(0, weight=1)
        wrapper.grid_rowconfigure(1, weight=1)

        fbar = ctk.CTkFrame(wrapper, fg_color="transparent")
        fbar.grid(row=0, column=0, sticky="e", padx=16, pady=(10, 6))
        ctk.CTkButton(
            fbar, text="⬇ CSV", width=70, height=30, corner_radius=6,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, hover_color=BG_INPUT,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            command=lambda: self._export_brute("csv"),
        ).grid(row=0, column=0, padx=(0, 6))
        ctk.CTkButton(
            fbar, text="⬇ TXT", width=70, height=30, corner_radius=6,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, hover_color=BG_INPUT,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            command=lambda: self._export_brute("txt"),
        ).grid(row=0, column=1)

        style = ttk.Style()
        style.configure("Sub.Treeview",
            background=BG_TABLE_ROW, foreground=TEXT_PRIMARY,
            fieldbackground=BG_TABLE_ROW, rowheight=32, borderwidth=0,
            relief="flat", font=("Segoe UI", 11),
        )
        style.configure("Sub.Treeview.Heading",
            background=BG_INPUT, foreground=TEXT_MUTED,
            borderwidth=0, relief="flat", font=("Segoe UI", 11, "bold"),
        )
        style.map("Sub.Treeview",
            background=[("selected", "#1a2332")],
            foreground=[("selected", TEXT_PRIMARY)],
        )
        style.map("Sub.Treeview.Heading",
            background=[("active", BG_CARD), ("pressed", BG_INPUT)],
            relief=[("active", "flat"), ("pressed", "flat")],
        )
        style.configure("Sub.Vertical.TScrollbar",
            background=BORDER_COLOR, troughcolor=BG_CARD,
            arrowcolor=TEXT_MUTED, borderwidth=0, relief="flat",
        )
        style.map("Sub.Vertical.TScrollbar",
            background=[("active", TEXT_MUTED)],
        )

        tf = tk.Frame(wrapper, bg=BG_CARD)
        tf.grid(row=1, column=0, sticky="nsew")
        tf.grid_columnconfigure(0, weight=1)
        tf.grid_rowconfigure(0, weight=1)

        vsb = ttk.Scrollbar(tf, orient="vertical", style="Sub.Vertical.TScrollbar")
        vsb.grid(row=0, column=1, sticky="ns")

        self._sub_tree = ttk.Treeview(
            tf,
            columns=("idx", "subdomain", "ip", "status"),
            show="headings",
            style="Sub.Treeview",
            yscrollcommand=vsb.set,
        )
        vsb.configure(command=self._sub_tree.yview)
        self._sub_tree.grid(row=0, column=0, sticky="nsew")

        self._sub_tree.heading("idx",      text="#",          anchor="w")
        self._sub_tree.heading("subdomain", text="Subdomain", anchor="w")
        self._sub_tree.heading("ip",       text="IP Address", anchor="w")
        self._sub_tree.heading("status",   text="Status",     anchor="center")
        self._sub_tree.column("idx",       width=50,  anchor="w",      stretch=False, minwidth=40)
        self._sub_tree.column("subdomain", width=300, anchor="w",      stretch=True,  minwidth=150)
        self._sub_tree.column("ip",        width=160, anchor="w",      stretch=False, minwidth=100)
        self._sub_tree.column("status",    width=100, anchor="center", stretch=False, minwidth=80)

        self._sub_tree.tag_configure("row_even",  background=BG_TABLE_ROW)
        self._sub_tree.tag_configure("row_odd",   background=BG_TABLE_ALT)
        self._sub_tree.tag_configure("st_found",     foreground=CLR_FOUND)
        self._sub_tree.tag_configure("st_not_found", foreground=CLR_NOT_FOUND)
        self._sub_tree.tag_configure("st_error",     foreground=CLR_ERROR)

        self._sub_empty = ctk.CTkLabel(
            tf, text="Start a scan to see results here.",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=TEXT_DIM, fg_color="transparent",
        )
        self._sub_empty.place(relx=0.5, rely=0.5, anchor="center")

        self._sub_result_count = ctk.CTkLabel(
            wrapper, text="0 results shown",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_DIM, anchor="e",
        )
        self._sub_result_count.grid(row=2, column=0, sticky="e", padx=16, pady=(4, 10))

        return frame

    def _on_wl_mode_change(self, val: str):
        if val == "Custom":
            self._wl_browse_btn.configure(state="normal")
        else:
            self._wl_browse_btn.configure(state="disabled")
            self._sub_wordlist = list(SUBDOMAIN_WORDLIST)
            self._sub_use_custom = False
            self._wl_info_label.configure(text=f"{len(SUBDOMAIN_WORDLIST)} entries")

    def _brute_browse_wordlist(self):
        entries = load_wordlist_file("Select Subdomain Wordlist")
        if entries:
            self._sub_wordlist = entries
            self._sub_use_custom = True
            self._wl_info_label.configure(text=f"Custom ({len(entries)} entries)")

    def _on_brute_threads(self, val):
        self._brute_thread_val.configure(text=str(int(val)))

    def _toggle_brute(self):
        if self._sub_running:
            self._stop_brute()
        else:
            self._start_brute()

    def _start_brute(self):
        domain = self._brute_domain_entry.get().strip()
        if not domain:
            self._brute_error.configure(text="⚠ Please enter a target domain.")
            return
        if not self._sub_wordlist:
            self._brute_error.configure(text="⚠ Wordlist is empty.")
            return
        self._brute_error.configure(text="")

        self._sub_results.clear()
        self._sub_queue = queue.Queue()
        self._sub_tree.delete(*self._sub_tree.get_children())
        self._sub_empty.configure(text="Scanning…")
        self._sub_empty.place(relx=0.5, rely=0.5, anchor="center")
        self._sub_result_count.configure(text="0 results shown")
        self._brute_progress.set(0)
        self._brute_status.configure(
            text=f"Brute-forcing {len(self._sub_wordlist)} subdomains on {domain}…",
            text_color=TEXT_MUTED,
        )

        threads = int(self._brute_thread_slider.get())
        self._sub_engine = SubdomainScanner(domain, self._sub_wordlist, threads=threads)
        self._sub_engine.start(
            on_result=self._on_sub_result,
            on_done=lambda: self.after(0, self._finalize_brute),
        )
        self._sub_running = True
        self._brute_start_btn.configure(
            text="⏹  Stop", fg_color="#ef4444",
            hover_color="#cc0000", text_color=TEXT_PRIMARY)
        self._brute_domain_entry.configure(state="disabled")
        self._poll_brute()

    def _stop_brute(self):
        if self._sub_engine:
            self._sub_engine.stop()
        self._finalize_brute(aborted=True)

    def _finalize_brute(self, aborted=False):
        self._sub_running = False
        if self._sub_poll_id:
            self.after_cancel(self._sub_poll_id)
            self._sub_poll_id = None
        self._drain_sub_queue()
        self._brute_start_btn.configure(
            text="▶  Start", fg_color=ACCENT_CYAN,
            hover_color="#00aacc", text_color="#0f1117")
        self._brute_domain_entry.configure(state="normal")
        found = sum(1 for r in self._sub_results if r.status == STATUS_FOUND)
        suffix = " (stopped)" if aborted else " — complete ✓"
        self._brute_status.configure(
            text=f"{len(self._sub_results)} probed{suffix}  •  {found} found",
            text_color=CLR_FOUND if found else TEXT_MUTED,
        )
        self._brute_progress.set(1.0 if not aborted else
                                 len(self._sub_results) / len(self._sub_wordlist)
                                 if self._sub_wordlist else 0)

    def _on_sub_result(self, result: SubdomainResult):
        self._sub_queue.put(result)

    def _poll_brute(self):
        self._drain_sub_queue()
        total = len(self._sub_wordlist)
        done  = len(self._sub_results)
        if total > 0:
            self._brute_progress.set(done / total)
        if self._sub_running:
            self._sub_poll_id = self.after(POLL_MS, self._poll_brute)

    def _drain_sub_queue(self):
        count = 0
        while not self._sub_queue.empty() and count < BATCH_LIMIT:
            r: SubdomainResult = self._sub_queue.get_nowait()
            self._sub_results.append(r)
            idx = len(self._sub_results)

            if r.status == STATUS_NOT_FOUND:
                count += 1
                continue

            tag_row = "row_even" if idx % 2 == 0 else "row_odd"
            if r.status == STATUS_FOUND:
                tag_st = "st_found"
            elif r.status == STATUS_ERROR:
                tag_st = "st_error"
            else:
                tag_st = "st_not_found"

            if self._sub_empty.winfo_ismapped():
                self._sub_empty.place_forget()

            self._sub_tree.insert(
                "", "end",
                values=(idx, r.subdomain, r.ip or "—", r.status),
                tags=(tag_row, tag_st),
            )
            count += 1

        shown = len(self._sub_tree.get_children())
        self._sub_result_count.configure(
            text=f"{shown} result{'s' if shown != 1 else ''} shown"
        )

    def _export_brute(self, fmt: str):
        visible = [r for r in self._sub_results if r.status != STATUS_NOT_FOUND]
        if not visible:
            self._brute_status.configure(
                text="⚠ No results to export.", text_color=CLR_ERROR)
            return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            defaultextension=f".{fmt}",
            filetypes=[("CSV", "*.csv")] if fmt == "csv" else [("Text", "*.txt")],
            initialfile=f"cyberkit_subdomains_{ts}.{fmt}",
            title="Export Results",
        )
        if not path:
            return
        try:
            if fmt == "csv":
                with open(path, "w", newline="", encoding="utf-8") as f:
                    w = csv.writer(f)
                    w.writerow(["#", "Subdomain", "IP Address", "Status"])
                    for i, r in enumerate(visible, 1):
                        w.writerow([i, r.subdomain, r.ip, r.status])
            else:
                with open(path, "w", encoding="utf-8") as f:
                    f.write("CyberKit — Subdomain Brute-Force Results\n")
                    f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 60 + "\n")
                    for r in visible:
                        f.write(f"{r.subdomain:<50} {r.ip or '':>16}  {r.status}\n")
            self._brute_status.configure(text="Export saved.", text_color=TEXT_MUTED)
        except OSError as e:
            self._brute_status.configure(
                text=f"Export failed: {e}", text_color=CLR_ERROR)
