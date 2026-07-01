"""
CyberKit — Packet Sniffer Page

Passive Scapy capture on a selected interface. Live Treeview of packets.
Read-only — no packet injection.
Requires administrator / root privileges.
"""

import queue
import threading
import tkinter as tk
from tkinter import ttk

import customtkinter as ctk
from app.ui.scrollable import autohide_vsb

from app.modules.packet_sniffer import (
    PacketRow, capture, list_interfaces,
)
from app.modules.arp_scanner import check_privileges

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
CLR_OK       = "#22c55e"
CLR_ERROR    = "#ef4444"
CLR_WARN     = "#f0a500"

POLL_MS     = 100
BATCH_LIMIT = 25
ROW_LIMIT   = 500


class PacketSnifferPage(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, corner_radius=0, **kwargs)
        self._q:       queue.Queue = queue.Queue()
        self._stop_ev: threading.Event = threading.Event()
        self._running  = False
        self._poll_id  = None
        self._row_cnt  = 0
        self._ifaces   = list_interfaces()
        self._packet_details: dict[str, str] = {}   # treeview iid → full packet dump
        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._scroll = ctk.CTkFrame(self, fg_color=BG_MAIN, corner_radius=0)
        self._scroll.grid(row=0, column=0, sticky="nsew")
        self._scroll.grid_columnconfigure(0, weight=1)
        self._scroll.grid_rowconfigure(3, weight=2)
        self._scroll.grid_rowconfigure(4, weight=1, minsize=180)

        # Header
        hdr = ctk.CTkFrame(self._scroll, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=30, pady=(28, 0))
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            hdr, text="🔬  Packet Sniffer",
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            hdr,
            text="Passive capture on a selected interface  •  Read-only, no injection",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        # Admin warning
        warn = ctk.CTkFrame(self._scroll, fg_color="#1a1200", corner_radius=8,
                            border_width=1, border_color=CLR_WARN)
        warn.grid(row=1, column=0, sticky="ew", padx=30, pady=(14, 0))
        ctk.CTkLabel(
            warn,
            text="⚠  Packet capture requires administrator / root privileges and Npcap (Windows). "
                 "Re-launch CyberKit as administrator if capture returns no packets.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=CLR_WARN, anchor="w", wraplength=900,
        ).grid(row=0, column=0, sticky="w", padx=16, pady=10)

        self._build_controls()
        self._build_table()
        self._build_details()

    def _build_controls(self):
        ctrl = ctk.CTkFrame(self._scroll, fg_color=BG_CARD, corner_radius=12,
                            border_width=1, border_color=BORDER_COLOR)
        ctrl.grid(row=2, column=0, sticky="ew", padx=30, pady=(14, 0))
        ctrl.grid_columnconfigure(0, weight=1)

        opts = ctk.CTkFrame(ctrl, fg_color="transparent")
        opts.grid(row=0, column=0, sticky="w", padx=18, pady=(14, 14))

        # Interface dropdown
        ctk.CTkLabel(opts, text="Interface:",
                     font=ctk.CTkFont(family="Segoe UI", size=12),
                     text_color=TEXT_MUTED).grid(row=0, column=0, padx=(0, 6))
        self._iface_var = ctk.StringVar(
            value=self._ifaces[0] if self._ifaces else "(none)")
        self._iface_menu = ctk.CTkOptionMenu(
            opts,
            values=self._ifaces or ["(none)"],
            variable=self._iface_var,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color=BG_INPUT, button_color=BORDER_COLOR,
            button_hover_color=BG_CARD, text_color=TEXT_PRIMARY,
            dropdown_fg_color=BG_CARD, dropdown_text_color=TEXT_PRIMARY,
            width=220, height=32,
        )
        self._iface_menu.grid(row=0, column=1, padx=(0, 16))

        # Protocol filter
        ctk.CTkLabel(opts, text="Filter:",
                     font=ctk.CTkFont(family="Segoe UI", size=12),
                     text_color=TEXT_MUTED).grid(row=0, column=2, padx=(0, 6))
        self._filter_var = ctk.StringVar(value="All")
        self._filter_menu = ctk.CTkOptionMenu(
            opts,
            values=["All", "TCP", "UDP", "ICMP", "ARP"],
            variable=self._filter_var,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color=BG_INPUT, button_color=BORDER_COLOR,
            button_hover_color=BG_CARD, text_color=TEXT_PRIMARY,
            dropdown_fg_color=BG_CARD, dropdown_text_color=TEXT_PRIMARY,
            width=100, height=32,
        )
        self._filter_menu.grid(row=0, column=3, padx=(0, 16))

        # Row limit
        ctk.CTkLabel(opts, text="Limit:",
                     font=ctk.CTkFont(family="Segoe UI", size=12),
                     text_color=TEXT_MUTED).grid(row=0, column=4, padx=(0, 6))
        self._limit_entry = ctk.CTkEntry(
            opts, width=70, height=32,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
        )
        self._limit_entry.insert(0, str(ROW_LIMIT))
        self._limit_entry.grid(row=0, column=5, padx=(0, 16))

        # Start / Stop
        self._start_btn = ctk.CTkButton(
            opts, text="▶  Start Capture",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color="#0f1117", height=36, width=150, corner_radius=8,
            command=self._start,
        )
        self._start_btn.grid(row=0, column=6, padx=(0, 8))

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
            ctrl, text="Select interface and click Start Capture.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_MUTED, anchor="w",
        )
        self._status_lbl.grid(row=1, column=0, sticky="w", padx=18, pady=(0, 12))

        # Disable capture if no real interfaces are available (e.g. Npcap missing)
        if self._ifaces and self._ifaces[0].startswith("("):
            self._start_btn.configure(state="disabled")
            label = self._ifaces[0].strip("()")
            self._status_lbl.configure(
                text=f"⚠  {label}. Download and install Npcap from npcap.com, then restart CyberKit.",
                text_color=CLR_WARN,
            )

    def _build_table(self):
        wrapper = ctk.CTkFrame(self._scroll, fg_color=BG_CARD, corner_radius=12,
                               border_width=1, border_color=BORDER_COLOR)
        wrapper.grid(row=3, column=0, sticky="nsew", padx=30, pady=(10, 30))
        wrapper.grid_columnconfigure(0, weight=1)
        wrapper.grid_rowconfigure(1, weight=1)

        top = ctk.CTkFrame(wrapper, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 8))
        top.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(top, text="Captured Packets",
                     font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                     text_color=TEXT_MUTED, anchor="w",
                     ).grid(row=0, column=0, sticky="w")
        ctk.CTkButton(
            top, text="Clear", width=70, height=28, corner_radius=6,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, hover_color=BG_INPUT,
            font=ctk.CTkFont(family="Segoe UI", size=11),
            command=self._clear,
        ).grid(row=0, column=1)

        style = ttk.Style()
        style.configure("PS.Treeview",
            background=BG_TABLE_ROW, foreground=TEXT_PRIMARY,
            fieldbackground=BG_TABLE_ROW, rowheight=30,
            borderwidth=0, relief="flat", font=("Segoe UI", 11))
        style.configure("PS.Treeview.Heading",
            background=BG_INPUT, foreground=TEXT_MUTED,
            borderwidth=0, relief="flat", font=("Segoe UI", 11, "bold"))
        style.map("PS.Treeview",
            background=[("selected", "#1a2332")],
            foreground=[("selected", TEXT_PRIMARY)])
        style.map("PS.Treeview.Heading",
            background=[("active", BG_CARD), ("pressed", BG_INPUT)],
            relief=[("active", "flat"), ("pressed", "flat")])
        style.configure("PS.Vertical.TScrollbar",
            background=BORDER_COLOR, troughcolor=BG_CARD,
            arrowcolor=TEXT_MUTED, borderwidth=0, relief="flat")
        style.map("PS.Vertical.TScrollbar", background=[("active", TEXT_MUTED)])

        tf = tk.Frame(wrapper, bg=BG_CARD)
        tf.grid(row=1, column=0, sticky="nsew")
        tf.grid_columnconfigure(0, weight=1)
        tf.grid_rowconfigure(0, weight=1)

        vsb = ttk.Scrollbar(tf, orient="vertical", style="PS.Vertical.TScrollbar")
        vsb.grid(row=0, column=1, sticky="ns")

        self._tree = ttk.Treeview(
            tf,
            columns=("num", "src", "dst", "proto", "sport", "dport", "preview"),
            show="headings", style="PS.Treeview",
            yscrollcommand=autohide_vsb(vsb), height=6,
        )
        vsb.configure(command=self._tree.yview)
        self._tree.grid(row=0, column=0, sticky="nsew")

        for col, head, w, anc, stretch, mw in [
            ("num",     "#",          45,  "center", False, 35),
            ("src",     "Source IP",  140, "w",      False, 80),
            ("dst",     "Dest IP",    140, "w",      False, 80),
            ("proto",   "Protocol",   70,  "center", False, 55),
            ("sport",   "Src Port",   70,  "center", False, 55),
            ("dport",   "Dst Port",   70,  "center", False, 55),
            ("preview", "Payload",    200, "w",      True,  80),
        ]:
            self._tree.heading(col, text=head, anchor=anc)
            self._tree.column(col, width=w, anchor=anc, stretch=stretch, minwidth=mw)

        # Per-protocol colours
        self._tree.tag_configure("TCP",      foreground="#60a5fa")
        self._tree.tag_configure("UDP",      foreground="#a78bfa")
        self._tree.tag_configure("ICMP",     foreground="#34d399")
        self._tree.tag_configure("ARP",      foreground="#fbbf24")
        self._tree.tag_configure("OTHER",    foreground=TEXT_MUTED)
        self._tree.tag_configure("row_even", background=BG_TABLE_ROW)
        self._tree.tag_configure("row_odd",  background=BG_TABLE_ALT)

        self._empty_lbl = ctk.CTkLabel(
            tf, text="Start capture to see packets.",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=TEXT_DIM, fg_color="transparent",
        )
        self._empty_lbl.place(relx=0.5, rely=0.5, anchor="center")

        self._tree.bind("<<TreeviewSelect>>", self._on_packet_select)

    def _build_details(self):
        wrapper = ctk.CTkFrame(self._scroll, fg_color=BG_CARD, corner_radius=12,
                               border_width=1, border_color=BORDER_COLOR)
        wrapper.grid(row=4, column=0, sticky="nsew", padx=30, pady=(0, 30))
        wrapper.grid_columnconfigure(0, weight=1)
        wrapper.grid_rowconfigure(1, weight=1)

        top = ctk.CTkFrame(wrapper, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 4))
        top.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            top, text="Packet Details",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=0, column=0, sticky="w")

        self._detail_box = ctk.CTkTextbox(
            wrapper,
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=BG_INPUT,
            text_color=TEXT_PRIMARY,
            border_width=0,
            wrap="none",
            state="disabled",
        )
        self._detail_box.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 12))
        self._detail_box.configure(state="normal")
        self._detail_box.insert("1.0", "Select a packet to see its details.")
        self._detail_box.configure(state="disabled")

    # ── Actions ───────────────────────────────────────────────────────────────

    def _start(self):
        if self._running:
            return
        if not check_privileges():
            self._status_lbl.configure(
                text="⚠ Administrator privileges required — re-launch CyberKit as administrator.",
                text_color=CLR_ERROR)
            return

        try:
            limit = int(self._limit_entry.get().strip() or ROW_LIMIT)
            limit = max(1, min(limit, 5000))
        except ValueError:
            limit = ROW_LIMIT

        iface  = self._iface_var.get()
        filt   = self._filter_var.get()

        self._running = True
        self._stop_ev = threading.Event()
        self._q       = queue.Queue()
        self._row_cnt = 0
        self._tree.delete(*self._tree.get_children())
        self._empty_lbl.place_forget()

        self._start_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._status_lbl.configure(
            text=f"Capturing on {iface}  [{filt}]  — limit {limit} packets…",
            text_color=TEXT_MUTED)

        threading.Thread(
            target=capture,
            kwargs=dict(
                display_iface=iface,
                proto_filter=filt,
                row_limit=limit,
                stop_event=self._stop_ev,
                on_packet=lambda r: self._q.put(r),
            ),
            daemon=True,
        ).start()

        # Signal the thread done by watching stop + queue
        threading.Thread(target=self._wait_done, args=(limit,), daemon=True).start()
        self._poll_id = self.after(POLL_MS, self._poll)

    def _wait_done(self, limit: int):
        """Block until capture() returns, then post a sentinel."""
        # capture() returns when stop_event set or row_limit reached;
        # the sentinel lets the UI know.
        self._stop_ev.wait()           # wait for stop
        self._q.put(None)              # sentinel

    def _stop(self):
        self._stop_ev.set()
        self._stop_btn.configure(state="disabled")
        self._status_lbl.configure(text="Stopping…", text_color=TEXT_MUTED)

    def _poll(self):
        drained = 0
        done = False
        while drained < BATCH_LIMIT:
            try:
                item = self._q.get_nowait()
            except queue.Empty:
                break
            if item is None:
                done = True
                break
            self._insert_row(item)
            drained += 1

        if not done:
            self._poll_id = self.after(POLL_MS, self._poll)
        else:
            self._finish()

    def _insert_row(self, r: PacketRow):
        alt = "row_even" if self._row_cnt % 2 == 0 else "row_odd"
        iid = self._tree.insert(
            "", "end",
            values=(
                self._row_cnt + 1,
                r.src, r.dst, r.proto,
                r.sport if r.sport is not None else "",
                r.dport if r.dport is not None else "",
                r.preview,
            ),
            tags=(r.proto, alt),
        )
        if r.details:
            self._packet_details[iid] = r.details
        self._tree.yview_moveto(1.0)
        self._row_cnt += 1

    def _on_packet_select(self, _event):
        sel = self._tree.selection()
        if not sel:
            return
        details = self._packet_details.get(sel[0], "No details captured for this packet.")
        self._detail_box.configure(state="normal")
        self._detail_box.delete("1.0", "end")
        self._detail_box.insert("1.0", details)
        self._detail_box.configure(state="disabled")

    def _finish(self):
        self._running = False
        self._start_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")
        self._status_lbl.configure(
            text=f"Capture complete — {self._row_cnt} packet(s) captured",
            text_color=CLR_OK if self._row_cnt else TEXT_MUTED,
        )

    def _clear(self):
        self._tree.delete(*self._tree.get_children())
        self._packet_details.clear()
        self._row_cnt = 0
        self._empty_lbl.place(relx=0.5, rely=0.5, anchor="center")
        self._status_lbl.configure(
            text="Select interface and click Start Capture.", text_color=TEXT_MUTED)
        self._detail_box.configure(state="normal")
        self._detail_box.delete("1.0", "end")
        self._detail_box.insert("1.0", "Select a packet to see its details.")
        self._detail_box.configure(state="disabled")
