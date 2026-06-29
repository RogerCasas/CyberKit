"""
CyberKit — ARP Scanner Page

Broadcasts ARP requests on a subnet and displays discovered hosts
(IP, MAC, Vendor, Hostname) in a live Treeview.

⚠ Requires administrator / root privileges at runtime.
"""

import csv
import queue
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, ttk

import customtkinter as ctk
from app.ui.scrollable import autohide_vsb

from app.modules.arp_scanner import (
    ARPScanner, ARPResult,
    check_privileges, auto_detect_subnet,
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
CLR_SUCCESS   = "#22c55e"
CLR_ERROR     = "#ef4444"
CLR_WARNING   = "#f0a500"

POLL_MS     = 150
BATCH_LIMIT = 20


class ARPScannerPage(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, corner_radius=0, **kwargs)
        self._engine: ARPScanner | None = None
        self._queue:  queue.Queue[ARPResult] = queue.Queue()
        self._results: list[ARPResult] = []
        self._running  = False
        self._poll_id  = None
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
            hdr, text="📡  ARP Scanner",
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            hdr,
            text="Discover live hosts on a local subnet via layer-2 ARP broadcast",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        # Admin warning banner
        banner = ctk.CTkFrame(
            self, fg_color="#1a1200", corner_radius=8,
            border_width=1, border_color=CLR_WARNING,
        )
        banner.grid(row=1, column=0, sticky="ew", padx=30, pady=(14, 0))
        ctk.CTkLabel(
            banner,
            text="⚠  This module requires administrator / root privileges. "
                 "Re-launch CyberKit as administrator if the scan returns no results.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=CLR_WARNING, anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=16, pady=10)

        # Content area
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.grid(row=2, column=0, sticky="nsew", padx=30, pady=(14, 30))
        content.grid_columnconfigure(0, weight=1)
        content.grid_rowconfigure(1, weight=1)

        # ── Ctrl card ─────────────────────────────────────────────────────────
        ctrl = ctk.CTkFrame(content, fg_color=BG_CARD, corner_radius=12,
                            border_width=1, border_color=BORDER_COLOR)
        ctrl.grid(row=0, column=0, sticky="ew")
        ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(ctrl, text="Subnet (CIDR)",
                     font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                     text_color=TEXT_MUTED, anchor="w",
                     ).grid(row=0, column=0, sticky="w", padx=(18, 10), pady=(16, 4))

        self._subnet_entry = ctk.CTkEntry(
            ctrl, placeholder_text="192.168.1.0/24",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, height=36,
        )
        self._subnet_entry.grid(row=0, column=1, sticky="ew", padx=(0, 8), pady=(16, 4))

        ctk.CTkButton(
            ctrl, text="Auto-detect", width=100, height=36, corner_radius=8,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, hover_color=BG_INPUT,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            command=self._auto_detect,
        ).grid(row=0, column=2, padx=(0, 18), pady=(16, 4))

        # Timeout slider
        opts = ctk.CTkFrame(ctrl, fg_color="transparent")
        opts.grid(row=1, column=0, columnspan=3, sticky="ew", padx=18, pady=(4, 10))

        ctk.CTkLabel(opts, text="Timeout:",
                     font=ctk.CTkFont(family="Segoe UI", size=12),
                     text_color=TEXT_MUTED).grid(row=0, column=0, padx=(0, 6))
        self._timeout_val = ctk.CTkLabel(
            opts, text="3 s",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=ACCENT_CYAN, width=36,
        )
        self._timeout_val.grid(row=0, column=1, padx=(0, 4))
        self._timeout_slider = ctk.CTkSlider(
            opts, from_=1, to=10, number_of_steps=9, width=130,
            button_color=ACCENT_CYAN, progress_color=ACCENT_CYAN,
            command=self._on_timeout,
        )
        self._timeout_slider.set(3)
        self._timeout_slider.grid(row=0, column=2, padx=(0, 24))

        self._start_btn = ctk.CTkButton(
            opts, text="▶  Start",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color="#0f1117", height=36, width=120, corner_radius=8,
            command=self._toggle,
        )
        self._start_btn.grid(row=0, column=3)

        self._status_lbl = ctk.CTkLabel(
            ctrl, text="Ready",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_MUTED, anchor="w",
        )
        self._status_lbl.grid(row=2, column=0, columnspan=3, sticky="w",
                              padx=18, pady=(0, 12))

        # ── Results table ─────────────────────────────────────────────────────
        wrapper = ctk.CTkFrame(
            content, fg_color=BG_CARD, corner_radius=12,
            border_width=1, border_color=BORDER_COLOR,
        )
        wrapper.grid(row=1, column=0, sticky="nsew", pady=(12, 0))
        wrapper.grid_columnconfigure(0, weight=1)
        wrapper.grid_rowconfigure(1, weight=1)

        fbar = ctk.CTkFrame(wrapper, fg_color="transparent")
        fbar.grid(row=0, column=0, sticky="e", padx=16, pady=(10, 6))

        for text, fmt in [("⬇ CSV", "csv"), ("⬇ TXT", "txt")]:
            ctk.CTkButton(
                fbar, text=text, width=70, height=30, corner_radius=6,
                fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
                text_color=TEXT_MUTED, hover_color=BG_INPUT,
                font=ctk.CTkFont(family="Segoe UI", size=12),
                command=lambda f=fmt: self._export(f),
            ).pack(side="left", padx=(0, 6))

        style = ttk.Style()
        style.configure("ARP.Treeview",
            background=BG_TABLE_ROW, foreground=TEXT_PRIMARY,
            fieldbackground=BG_TABLE_ROW, rowheight=32, borderwidth=0,
            relief="flat", font=("Segoe UI", 11),
        )
        style.configure("ARP.Treeview.Heading",
            background=BG_INPUT, foreground=TEXT_MUTED,
            borderwidth=0, relief="flat", font=("Segoe UI", 11, "bold"),
        )
        style.map("ARP.Treeview",
            background=[("selected", "#1a2332")],
            foreground=[("selected", TEXT_PRIMARY)],
        )
        style.map("ARP.Treeview.Heading",
            background=[("active", BG_CARD), ("pressed", BG_INPUT)],
            relief=[("active", "flat"), ("pressed", "flat")],
        )
        style.configure("ARP.Vertical.TScrollbar",
            background=BORDER_COLOR, troughcolor=BG_CARD,
            arrowcolor=TEXT_MUTED, borderwidth=0, relief="flat",
        )
        style.map("ARP.Vertical.TScrollbar",
            background=[("active", TEXT_MUTED)],
        )

        tf = tk.Frame(wrapper, bg=BG_CARD)
        tf.grid(row=1, column=0, sticky="nsew")
        tf.grid_columnconfigure(0, weight=1)
        tf.grid_rowconfigure(0, weight=1)

        vsb = ttk.Scrollbar(tf, orient="vertical", style="ARP.Vertical.TScrollbar")
        vsb.grid(row=0, column=1, sticky="ns")

        self._tree = ttk.Treeview(
            tf,
            columns=("idx", "ip", "mac", "vendor", "hostname"),
            show="headings",
            height=1,
            style="ARP.Treeview",
            yscrollcommand=autohide_vsb(vsb),
        )
        vsb.configure(command=self._tree.yview)
        self._tree.grid(row=0, column=0, sticky="nsew")

        for col, heading, width, stretch in [
            ("idx",      "#",        40,  False),
            ("ip",       "IP",       130, False),
            ("mac",      "MAC",      150, False),
            ("vendor",   "Vendor",   200, False),
            ("hostname", "Hostname", 200, True),
        ]:
            self._tree.heading(col, text=heading, anchor="w")
            self._tree.column(col, width=width, anchor="w",
                              stretch=stretch, minwidth=40)

        self._tree.tag_configure("row_even", background=BG_TABLE_ROW)
        self._tree.tag_configure("row_odd",  background=BG_TABLE_ALT)

        self._empty_lbl = ctk.CTkLabel(
            tf, text="Start a scan to discover hosts on your local network.",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=TEXT_DIM, fg_color="transparent",
        )
        self._empty_lbl.place(relx=0.5, rely=0.5, anchor="center")

    # ── Controls ──────────────────────────────────────────────────────────────

    def _auto_detect(self):
        subnet = auto_detect_subnet()
        self._subnet_entry.delete(0, "end")
        self._subnet_entry.insert(0, subnet)

    def _on_timeout(self, val):
        self._timeout_val.configure(text=f"{int(val)} s")

    def _toggle(self):
        if self._running:
            self._stop()
        else:
            self._start()

    def _start(self):
        subnet = self._subnet_entry.get().strip()
        if not subnet:
            self._status_lbl.configure(
                text="⚠ Enter a subnet (e.g. 192.168.1.0/24).", text_color=CLR_ERROR)
            return
        if not check_privileges():
            self._status_lbl.configure(
                text="⚠ Administrator privileges required. Re-launch CyberKit as administrator.",
                text_color=CLR_ERROR,
            )
            return

        self._results.clear()
        self._queue = queue.Queue()
        self._tree.delete(*self._tree.get_children())
        self._empty_lbl.place_forget()
        timeout = int(self._timeout_slider.get())
        self._status_lbl.configure(
            text=f"Scanning {subnet} (timeout {timeout} s)…", text_color=TEXT_MUTED)
        self._engine = ARPScanner(subnet=subnet, timeout_s=timeout)
        self._engine.start(
            on_result=lambda r: self._queue.put(r),
            on_done=lambda: self._queue.put(None),
        )
        self._running = True
        self._start_btn.configure(
            text="⏹  Stop", fg_color=CLR_ERROR, hover_color="#cc0000",
            text_color=TEXT_PRIMARY)
        self._subnet_entry.configure(state="disabled")
        self._poll()

    def _stop(self):
        if self._engine:
            self._engine.stop()
        self._finalize(aborted=True)

    def _finalize(self, aborted=False):
        self._running = False
        if self._poll_id:
            self.after_cancel(self._poll_id)
            self._poll_id = None
        self._drain_queue()
        self._start_btn.configure(
            text="▶  Start", fg_color=ACCENT_CYAN,
            hover_color="#00aacc", text_color="#0f1117")
        self._subnet_entry.configure(state="normal")
        suffix = " (stopped)" if aborted else " — complete ✓"
        self._status_lbl.configure(
            text=f"{len(self._results)} host(s) found{suffix}",
            text_color=CLR_SUCCESS if self._results else TEXT_MUTED,
        )

    def _poll(self):
        done = self._drain_queue()
        if done:
            self._finalize()
            return
        if self._running:
            self._poll_id = self.after(POLL_MS, self._poll)

    def _drain_queue(self) -> bool:
        count = 0
        while not self._queue.empty() and count < BATCH_LIMIT:
            item = self._queue.get_nowait()
            if item is None:
                return True
            r: ARPResult = item
            self._results.append(r)
            idx = len(self._results)
            tag = "row_even" if idx % 2 == 0 else "row_odd"
            self._tree.insert(
                "", "end",
                values=(idx, r.ip, r.mac, r.vendor, r.hostname),
                tags=(tag,),
            )
            count += 1
        if count:
            self._tree.yview_moveto(1.0)
        return False

    def _export(self, fmt: str):
        if not self._results:
            self._status_lbl.configure(
                text="⚠ No results to export.", text_color=CLR_ERROR)
            return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            defaultextension=f".{fmt}",
            filetypes=[("CSV", "*.csv")] if fmt == "csv" else [("Text", "*.txt")],
            initialfile=f"cyberkit_arp_{ts}.{fmt}",
            title="Export ARP Results",
        )
        if not path:
            return
        try:
            if fmt == "csv":
                with open(path, "w", newline="", encoding="utf-8") as f:
                    w = csv.writer(f)
                    w.writerow(["#", "IP", "MAC", "Vendor", "Hostname"])
                    for i, r in enumerate(self._results, 1):
                        w.writerow([i, r.ip, r.mac, r.vendor, r.hostname])
            else:
                with open(path, "w", encoding="utf-8") as f:
                    f.write("CyberKit — ARP Scanner Results\n")
                    f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("=" * 70 + "\n")
                    for r in self._results:
                        f.write(
                            f"{r.index:<4} {r.ip:<17} {r.mac:<19} "
                            f"{r.vendor:<30} {r.hostname}\n"
                        )
            self._status_lbl.configure(text="Export saved.", text_color=TEXT_MUTED)
        except OSError as e:
            self._status_lbl.configure(
                text=f"Export failed: {e}", text_color=CLR_ERROR)
