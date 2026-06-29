"""
CyberKit — Traceroute Page

TTL-escalating probes via Scapy. Live hop-by-hop table.
Requires administrator / root privileges.
"""

import queue
import threading
import tkinter as tk
from tkinter import ttk

import customtkinter as ctk
from app.ui.scrollable import autohide_vsb

from app.modules.traceroute import TraceHop, scan as trace_scan, check_privileges

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
CLR_OK        = "#22c55e"
CLR_ERROR     = "#ef4444"
CLR_WARN      = "#f0a500"

POLL_MS = 100


class TraceRoutePage(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, corner_radius=0, **kwargs)
        self._q:       queue.Queue = queue.Queue()
        self._stop_ev: threading.Event = threading.Event()
        self._running  = False
        self._poll_id  = None
        self._row_cnt  = 0
        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._scroll = ctk.CTkFrame(self, fg_color=BG_MAIN, corner_radius=0)
        self._scroll.grid(row=0, column=0, sticky="nsew")
        self._scroll.grid_columnconfigure(0, weight=1)
        self._scroll.grid_rowconfigure(3, weight=1)  # table fills remaining space

        # Header
        hdr = ctk.CTkFrame(self._scroll, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=30, pady=(28, 0))
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            hdr, text="🗺  Traceroute",
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            hdr,
            text="TTL-escalating probes — visualise the hop-by-hop path to a target",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        # Admin warning banner
        warn = ctk.CTkFrame(self._scroll, fg_color="#1a1200", corner_radius=8,
                            border_width=1, border_color=CLR_WARN)
        warn.grid(row=1, column=0, sticky="ew", padx=30, pady=(14, 0))
        ctk.CTkLabel(
            warn,
            text="⚠  Traceroute requires administrator / root privileges (raw sockets via Scapy). "
                 "Re-launch CyberKit as administrator if hops appear empty.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=CLR_WARN, anchor="w", wraplength=900,
        ).grid(row=0, column=0, sticky="w", padx=16, pady=10)

        self._build_controls()
        self._build_table()

    def _build_controls(self):
        ctrl = ctk.CTkFrame(self._scroll, fg_color=BG_CARD, corner_radius=12,
                            border_width=1, border_color=BORDER_COLOR)
        ctrl.grid(row=2, column=0, sticky="ew", padx=30, pady=(14, 0))
        ctrl.grid_columnconfigure(1, weight=1)

        # Row 0: Target label + inline error
        ctk.CTkLabel(ctrl, text="Target Host / IP",
                     font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                     text_color=TEXT_MUTED,
                     ).grid(row=0, column=0, padx=(18, 10), pady=(14, 4), sticky="w")
        self._inline_err = ctk.CTkLabel(ctrl, text="",
                                        font=ctk.CTkFont(family="Segoe UI", size=11),
                                        text_color=CLR_ERROR, anchor="w")
        self._inline_err.grid(row=0, column=1, sticky="w", pady=(14, 4))

        # Row 1: URL entry
        self._host_entry = ctk.CTkEntry(
            ctrl, placeholder_text="example.com  or  1.2.3.4",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, height=38,
        )
        self._host_entry.grid(row=1, column=0, columnspan=2, sticky="ew",
                              padx=18, pady=(0, 8))

        # Row 2: Options + buttons
        opts = ctk.CTkFrame(ctrl, fg_color="transparent")
        opts.grid(row=2, column=0, columnspan=2, sticky="w", padx=18, pady=(0, 14))

        ctk.CTkLabel(opts, text="Method:",
                     font=ctk.CTkFont(family="Segoe UI", size=12),
                     text_color=TEXT_MUTED).grid(row=0, column=0, padx=(0, 6))
        self._method_var = ctk.StringVar(value="ICMP")
        self._method_menu = ctk.CTkOptionMenu(
            opts, values=["ICMP", "UDP"],
            variable=self._method_var,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color=BG_INPUT, button_color=BORDER_COLOR,
            button_hover_color=BG_CARD, text_color=TEXT_PRIMARY,
            dropdown_fg_color=BG_CARD, dropdown_text_color=TEXT_PRIMARY,
            width=90, height=32,
        )
        self._method_menu.grid(row=0, column=1, padx=(0, 14))

        ctk.CTkLabel(opts, text="Max hops:",
                     font=ctk.CTkFont(family="Segoe UI", size=12),
                     text_color=TEXT_MUTED).grid(row=0, column=2, padx=(0, 6))
        self._hops_entry = ctk.CTkEntry(
            opts, width=60, height=32,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
        )
        self._hops_entry.insert(0, "30")
        self._hops_entry.grid(row=0, column=3, padx=(0, 14))

        ctk.CTkLabel(opts, text="Timeout (s):",
                     font=ctk.CTkFont(family="Segoe UI", size=12),
                     text_color=TEXT_MUTED).grid(row=0, column=4, padx=(0, 6))
        self._timeout_entry = ctk.CTkEntry(
            opts, width=60, height=32,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
        )
        self._timeout_entry.insert(0, "2")
        self._timeout_entry.grid(row=0, column=5, padx=(0, 14))

        self._scan_btn = ctk.CTkButton(
            opts, text="▶  Trace",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color="#0f1117", height=36, width=110, corner_radius=8,
            command=self._start,
        )
        self._scan_btn.grid(row=0, column=6, padx=(0, 8))

        self._stop_btn = ctk.CTkButton(
            opts, text="■  Stop",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=BG_INPUT, hover_color=BG_CARD,
            border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, height=36, width=110, corner_radius=8,
            state="disabled", command=self._stop,
        )
        self._stop_btn.grid(row=0, column=7)

        self._status_lbl = ctk.CTkLabel(
            ctrl, text="Enter a target host and click Trace.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_MUTED, anchor="w",
        )
        self._status_lbl.grid(row=3, column=0, columnspan=2, sticky="w",
                              padx=18, pady=(0, 12))

    def _build_table(self):
        wrapper = ctk.CTkFrame(self._scroll, fg_color=BG_CARD, corner_radius=12,
                               border_width=1, border_color=BORDER_COLOR)
        wrapper.grid(row=3, column=0, sticky="nsew", padx=30, pady=(10, 30))
        wrapper.grid_columnconfigure(0, weight=1)
        wrapper.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(wrapper, text="Hop Results",
                     font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                     text_color=TEXT_MUTED, anchor="w",
                     ).grid(row=0, column=0, sticky="w", padx=16, pady=(12, 8))

        style = ttk.Style()
        style.configure("TR.Treeview",
            background=BG_TABLE_ROW, foreground=TEXT_PRIMARY,
            fieldbackground=BG_TABLE_ROW, rowheight=34,
            borderwidth=0, relief="flat", font=("Segoe UI", 11))
        style.configure("TR.Treeview.Heading",
            background=BG_INPUT, foreground=TEXT_MUTED,
            borderwidth=0, relief="flat", font=("Segoe UI", 11, "bold"))
        style.map("TR.Treeview",
            background=[("selected", "#1a2332")],
            foreground=[("selected", TEXT_PRIMARY)])
        style.map("TR.Treeview.Heading",
            background=[("active", BG_CARD), ("pressed", BG_INPUT)],
            relief=[("active", "flat"), ("pressed", "flat")])
        style.configure("TR.Vertical.TScrollbar",
            background=BORDER_COLOR, troughcolor=BG_CARD,
            arrowcolor=TEXT_MUTED, borderwidth=0, relief="flat")
        style.map("TR.Vertical.TScrollbar", background=[("active", TEXT_MUTED)])

        tf = tk.Frame(wrapper, bg=BG_CARD)
        tf.grid(row=1, column=0, sticky="nsew")
        tf.grid_columnconfigure(0, weight=1)
        tf.grid_rowconfigure(0, weight=1)

        vsb = ttk.Scrollbar(tf, orient="vertical", style="TR.Vertical.TScrollbar")
        vsb.grid(row=0, column=1, sticky="ns")

        self._tree = ttk.Treeview(
            tf,
            columns=("hop", "ip", "hostname", "rtt", "status"),
            show="headings", style="TR.Treeview",
            yscrollcommand=autohide_vsb(vsb), height=6,
        )
        vsb.configure(command=self._tree.yview)
        self._tree.grid(row=0, column=0, sticky="nsew")

        for col, head, w, anc, stretch, mw in [
            ("hop",      "Hop",      50,  "center", False, 40),
            ("ip",       "IP",       140, "w",      False, 80),
            ("hostname", "Hostname", 240, "w",      True,  100),
            ("rtt",      "RTT (ms)", 90,  "center", False, 70),
            ("status",   "Status",   90,  "center", False, 70),
        ]:
            self._tree.heading(col, text=head, anchor=anc)
            self._tree.column(col, width=w, anchor=anc, stretch=stretch, minwidth=mw)

        self._tree.tag_configure("timeout",  foreground=TEXT_DIM)
        self._tree.tag_configure("reached",  foreground=CLR_OK)
        self._tree.tag_configure("hop",      foreground=TEXT_PRIMARY)
        self._tree.tag_configure("row_even", background=BG_TABLE_ROW)
        self._tree.tag_configure("row_odd",  background=BG_TABLE_ALT)

        self._empty_lbl = ctk.CTkLabel(
            tf, text="Enter a target and click Trace to begin.",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=TEXT_DIM, fg_color="transparent",
        )
        self._empty_lbl.place(relx=0.5, rely=0.5, anchor="center")

    # ── Actions ───────────────────────────────────────────────────────────────

    def _start(self):
        if self._running:
            return
        self._inline_err.configure(text="")
        host = self._host_entry.get().strip()
        if not host:
            self._inline_err.configure(text="Enter a target.")
            return

        try:
            max_hops = int(self._hops_entry.get().strip() or 30)
            timeout  = float(self._timeout_entry.get().strip() or 2.0)
        except ValueError:
            self._inline_err.configure(text="Max hops and timeout must be numbers.")
            return

        if not check_privileges():
            self._status_lbl.configure(
                text="⚠ Administrator privileges required — re-launch CyberKit as administrator.",
                text_color=CLR_ERROR)
            return

        self._running = True
        self._stop_ev = threading.Event()
        self._q       = queue.Queue()
        self._row_cnt = 0
        self._tree.delete(*self._tree.get_children())
        self._empty_lbl.place_forget()

        self._scan_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._status_lbl.configure(
            text=f"Tracing route to {host}…", text_color=TEXT_MUTED)

        method = self._method_var.get()
        threading.Thread(
            target=self._run_trace,
            args=(host, max_hops, timeout, method),
            daemon=True,
        ).start()
        self._poll_id = self.after(POLL_MS, self._poll)

    def _stop(self):
        self._stop_ev.set()
        self._stop_btn.configure(state="disabled")
        self._status_lbl.configure(text="Stopping…", text_color=TEXT_MUTED)

    def _run_trace(self, host, max_hops, timeout, method):
        try:
            trace_scan(
                host, max_hops=max_hops, timeout=timeout, method=method,
                stop_event=self._stop_ev,
                on_hop=lambda h: self._q.put(("hop", h)),
            )
            self._q.put(("done",))
        except Exception as exc:
            self._q.put(("error", str(exc)))

    def _poll(self):
        drained = 0
        while drained < 20:
            try:
                msg = self._q.get_nowait()
            except queue.Empty:
                break
            drained += 1
            kind = msg[0]
            if kind == "hop":
                self._insert_hop(msg[1])
            elif kind == "done":
                self._finish(stopped=False)
                return
            elif kind == "error":
                self._inline_err.configure(text=f"Error: {msg[1]}")
                self._finish(stopped=True)
                return
        self._poll_id = self.after(POLL_MS, self._poll)

    def _insert_hop(self, h: TraceHop):
        alt = "row_even" if self._row_cnt % 2 == 0 else "row_odd"
        if h.timed_out:
            values = (h.hop, "*", "*", "*", "Timeout")
            tags   = ("timeout", alt)
        else:
            rtt_str = f"{h.rtt_ms:.1f}" if h.rtt_ms is not None else "?"
            values  = (h.hop, h.ip or "", h.hostname or "", rtt_str, "Reached")
            tags    = ("reached" if h.ip else "hop", alt)
        self._tree.insert("", "end", values=values, tags=tags)
        self._tree.yview_moveto(1.0)
        self._row_cnt += 1

    def _finish(self, stopped: bool):
        self._running = False
        self._scan_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")
        suffix = " (stopped)" if stopped else " — complete"
        hops = self._row_cnt
        self._status_lbl.configure(
            text=f"{hops} hop(s) recorded{suffix}",
            text_color=TEXT_MUTED,
        )
