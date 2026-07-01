"""
CyberKit — Banner Grabber Page

Raw TCP connect to a host:port; displays the service banner text.
Optionally wraps the connection in TLS.
"""

import queue
import threading
import tkinter as tk

import customtkinter as ctk

from app.modules.banner_grabber import grab, BannerResult

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

POLL_MS = 100


class BannerGrabberPage(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, corner_radius=0, **kwargs)
        self._q:       queue.Queue = queue.Queue()
        self._running  = False
        self._poll_id  = None
        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._scroll = ctk.CTkFrame(self, fg_color=BG_MAIN, corner_radius=0)
        self._scroll.grid(row=0, column=0, sticky="nsew")
        self._scroll.grid_columnconfigure(0, weight=1)
        self._scroll.grid_rowconfigure(2, weight=1)

        # Header
        hdr = ctk.CTkFrame(self._scroll, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=30, pady=(28, 0))
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            hdr, text="📡  Banner Grabber",
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            hdr,
            text="Raw TCP connect — capture service banners (SSH, FTP, SMTP, HTTP, …)",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        self._build_controls()
        self._build_output()

    def _build_controls(self):
        ctrl = ctk.CTkFrame(self._scroll, fg_color=BG_CARD, corner_radius=12,
                            border_width=1, border_color=BORDER_COLOR)
        ctrl.grid(row=1, column=0, sticky="ew", padx=30, pady=(20, 0))
        ctrl.grid_columnconfigure(1, weight=1)

        # Labels + inline error
        ctk.CTkLabel(ctrl, text="Host",
                     font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                     text_color=TEXT_MUTED,
                     ).grid(row=0, column=0, padx=(18, 10), pady=(14, 4), sticky="w")
        self._inline_err = ctk.CTkLabel(ctrl, text="",
                                        font=ctk.CTkFont(family="Segoe UI", size=11),
                                        text_color=CLR_ERROR, anchor="w")
        self._inline_err.grid(row=0, column=1, columnspan=3, sticky="w", pady=(14, 4))

        # Host / port inputs on the same row
        inputs = ctk.CTkFrame(ctrl, fg_color="transparent")
        inputs.grid(row=1, column=0, columnspan=4, sticky="ew", padx=18, pady=(0, 8))
        inputs.grid_columnconfigure(0, weight=1)

        self._host_entry = ctk.CTkEntry(
            inputs,
            placeholder_text="example.com  or  192.168.1.1",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, height=38,
        )
        self._host_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))

        ctk.CTkLabel(inputs, text="Port",
                     font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                     text_color=TEXT_MUTED,
                     ).grid(row=0, column=1, padx=(0, 6))
        self._port_entry = ctk.CTkEntry(
            inputs, width=80, height=38,
            font=ctk.CTkFont(family="Segoe UI", size=13),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
        )
        self._port_entry.insert(0, "22")
        self._port_entry.grid(row=0, column=2)

        # Options row
        opts = ctk.CTkFrame(ctrl, fg_color="transparent")
        opts.grid(row=2, column=0, columnspan=4, sticky="w", padx=18, pady=(0, 8))

        ctk.CTkLabel(opts, text="Probe:",
                     font=ctk.CTkFont(family="Segoe UI", size=12),
                     text_color=TEXT_MUTED).grid(row=0, column=0, padx=(0, 6))
        self._probe_entry = ctk.CTkEntry(
            opts, width=160, height=32,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
        )
        self._probe_entry.insert(0, r"\r\n")
        self._probe_entry.grid(row=0, column=1, padx=(0, 14))

        ctk.CTkLabel(opts, text="Timeout (s):",
                     font=ctk.CTkFont(family="Segoe UI", size=12),
                     text_color=TEXT_MUTED).grid(row=0, column=2, padx=(0, 6))
        self._timeout_entry = ctk.CTkEntry(
            opts, width=60, height=32,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
        )
        self._timeout_entry.insert(0, "5")
        self._timeout_entry.grid(row=0, column=3, padx=(0, 14))

        self._tls_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            opts, text="Use TLS",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED,
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            border_color=BORDER_COLOR, checkmark_color="#0f1117",
            variable=self._tls_var,
        ).grid(row=0, column=4, padx=(0, 14))

        self._grab_btn = ctk.CTkButton(
            opts, text="▶  Grab Banner",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color="#0f1117", height=36, width=140, corner_radius=8,
            command=self._start,
        )
        self._grab_btn.grid(row=0, column=5, padx=(0, 8))

        self._stop_btn = ctk.CTkButton(
            opts, text="■  Stop",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=BG_INPUT, hover_color=BG_CARD,
            border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, height=36, width=110, corner_radius=8,
            state="disabled", command=self._stop,
        )
        self._stop_btn.grid(row=0, column=6)

        self._status_lbl = ctk.CTkLabel(
            ctrl, text="Configure target and click Grab Banner.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_MUTED, anchor="w",
        )
        self._status_lbl.grid(row=3, column=0, columnspan=4, sticky="w",
                              padx=18, pady=(0, 12))

    def _build_output(self):
        wrapper = ctk.CTkFrame(self._scroll, fg_color=BG_CARD, corner_radius=12,
                               border_width=1, border_color=BORDER_COLOR)
        wrapper.grid(row=2, column=0, sticky="nsew", padx=30, pady=(10, 30))
        wrapper.grid_columnconfigure(0, weight=1)
        wrapper.grid_rowconfigure(1, weight=1)

        top = ctk.CTkFrame(wrapper, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=16, pady=(12, 8))
        top.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(top, text="Banner Output",
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

        self._textbox = ctk.CTkTextbox(
            wrapper,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=BG_INPUT, text_color=TEXT_PRIMARY,
            border_color=BORDER_COLOR, border_width=1,
            corner_radius=8, wrap="none",
        )
        self._textbox.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 16))
        self._textbox.configure(state="disabled")
        self._textbox.insert("end", "Banner output will appear here.\n")
        self._textbox.configure(state="disabled")

    # ── Actions ───────────────────────────────────────────────────────────────

    def _start(self):
        if self._running:
            return
        self._inline_err.configure(text="")
        host = self._host_entry.get().strip()
        port_str = self._port_entry.get().strip()
        if not host:
            self._inline_err.configure(text="Enter a host.")
            return
        try:
            port = int(port_str)
            if not (1 <= port <= 65535):
                raise ValueError
        except ValueError:
            self._inline_err.configure(text="Port must be 1–65535.")
            return
        try:
            timeout = float(self._timeout_entry.get().strip() or 5)
        except ValueError:
            self._inline_err.configure(text="Timeout must be a number.")
            return

        # Decode escape sequences in probe (e.g. \r\n → CR LF)
        raw_probe = self._probe_entry.get()
        probe = raw_probe.encode("raw_unicode_escape").decode("unicode_escape")

        use_tls = self._tls_var.get()
        self._running = True
        self._q = queue.Queue()
        self._grab_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._status_lbl.configure(
            text=f"Connecting to {host}:{port}{'  [TLS]' if use_tls else ''}…",
            text_color=TEXT_MUTED)

        threading.Thread(
            target=self._run_grab,
            args=(host, port, probe, use_tls, timeout),
            daemon=True,
        ).start()
        self._poll_id = self.after(POLL_MS, self._poll)

    def _stop(self):
        # Banner grab is a single blocking call; nothing to cancel mid-flight.
        # The Stop button disables itself; the poll will finish naturally.
        self._stop_btn.configure(state="disabled")

    def _run_grab(self, host, port, probe, use_tls, timeout):
        result = grab(host, port, probe=probe, use_tls=use_tls, timeout=timeout)
        self._q.put(result)

    def _poll(self):
        try:
            result: BannerResult = self._q.get_nowait()
        except queue.Empty:
            self._poll_id = self.after(POLL_MS, self._poll)
            return

        self._finish(result)

    def _finish(self, result: BannerResult):
        self._running = False
        self._grab_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")

        self._textbox.configure(state="normal")
        self._textbox.delete("1.0", "end")

        if result.error:
            self._textbox.insert("end", f"[Error]  {result.error}\n")
            self._status_lbl.configure(
                text=f"Connection failed: {result.error}", text_color=CLR_ERROR)
        else:
            tls_tag = "  [TLS]" if result.tls else ""
            self._textbox.insert("end", f"# {result.host}:{result.port}{tls_tag}\n\n")
            self._textbox.insert("end", result.banner if result.banner else "(empty banner)\n")
            self._status_lbl.configure(
                text=f"Banner captured — {len(result.banner)} char(s)",
                text_color=CLR_OK)

        self._textbox.configure(state="disabled")

    def _clear(self):
        self._textbox.configure(state="normal")
        self._textbox.delete("1.0", "end")
        self._textbox.configure(state="disabled")
        self._status_lbl.configure(
            text="Configure target and click Grab Banner.", text_color=TEXT_MUTED)
