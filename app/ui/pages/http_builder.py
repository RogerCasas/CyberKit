"""
CyberKit — HTTP Request Builder Page
"""

import queue
import threading

import customtkinter as ctk

from app.modules.http_builder import RequestResult, send

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
CLR_WARN     = "#f59e0b"
CLR_ERROR    = "#ef4444"

POLL_MS  = 100
METHODS  = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]


def _status_colors(code: int) -> tuple:
    """Return (text_color, bg_color) for an HTTP status code."""
    if 200 <= code < 300:
        return CLR_OK,    "#0d2818"
    if 300 <= code < 400:
        return ACCENT_CYAN, "#0a1820"
    if 400 <= code < 500:
        return CLR_WARN,  "#1a1500"
    if 500 <= code < 600:
        return CLR_ERROR, "#2a0a0a"
    return TEXT_MUTED, BG_INPUT


class HttpBuilderPage(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, corner_radius=0, **kwargs)
        self._result_queue: queue.Queue = queue.Queue()
        self._poll_id = None
        self._sending = False
        self._header_rows: list = []   # list of (frame, key_entry, val_entry)
        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        # Header
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=30, pady=(28, 0))
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            hdr, text="📡  HTTP Request Builder",
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            hdr,
            text="Craft custom HTTP requests and inspect the full raw response",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        self._build_controls()
        self._build_body_panel()
        self._build_response()

    def _build_controls(self):
        ctrl = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=12,
                            border_width=1, border_color=BORDER_COLOR)
        ctrl.grid(row=1, column=0, sticky="ew", padx=30, pady=(20, 0))
        ctrl.grid_columnconfigure(1, weight=1)
        ctrl.grid_columnconfigure(4, weight=1)

        self._method_menu = ctk.CTkOptionMenu(
            ctrl, values=METHODS, width=110, height=36,
            font=ctk.CTkFont(family="Segoe UI", size=13),
            fg_color=BG_INPUT, button_color=BORDER_COLOR,
            button_hover_color=TEXT_DIM, text_color=TEXT_PRIMARY,
            dropdown_fg_color=BG_CARD, dropdown_text_color=TEXT_PRIMARY,
            dropdown_hover_color=BG_INPUT,
        )
        self._method_menu.grid(row=0, column=0, padx=(12, 8), pady=12)

        self._url_entry = ctk.CTkEntry(
            ctrl,
            placeholder_text="https://httpbin.org/get",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, height=36,
        )
        self._url_entry.grid(row=0, column=1, sticky="ew", padx=(0, 8), pady=12)
        self._url_entry.bind("<Return>", lambda e: self._start_send())

        self._redirects_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            ctrl, text="Follow redirects",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED, variable=self._redirects_var,
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            border_color=BORDER_COLOR, checkmark_color=BG_MAIN,
            width=140,
        ).grid(row=0, column=2, padx=(0, 8), pady=12)

        self._send_btn = ctk.CTkButton(
            ctrl, text="▶  Send",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color="#0f1117", height=36, width=100, corner_radius=8,
            command=self._start_send,
        )
        self._send_btn.grid(row=0, column=3, padx=(0, 8), pady=12)

        self._status_lbl = ctk.CTkLabel(
            ctrl, text="Enter a URL and click Send.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_MUTED, anchor="w",
        )
        self._status_lbl.grid(row=0, column=4, sticky="ew", padx=(0, 12), pady=12)

    def _build_body_panel(self):
        panel = ctk.CTkFrame(self, fg_color="transparent")
        panel.grid(row=2, column=0, sticky="ew", padx=30, pady=(12, 0))
        panel.grid_columnconfigure(0, weight=2)
        panel.grid_columnconfigure(1, weight=3)

        # ── Headers editor (left) ─────────────────────────────────────────────
        hdr_card = ctk.CTkFrame(panel, fg_color=BG_CARD, corner_radius=12,
                                border_width=1, border_color=BORDER_COLOR)
        hdr_card.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        hdr_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            hdr_card, text="Request Headers",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=14, pady=(10, 4))

        self._headers_scroll = ctk.CTkScrollableFrame(
            hdr_card, height=110, fg_color="transparent", corner_radius=0,
            scrollbar_button_color=BORDER_COLOR,
            scrollbar_button_hover_color=TEXT_DIM,
        )
        self._headers_scroll.grid(row=1, column=0, sticky="ew", padx=8, pady=(0, 4))

        ctk.CTkButton(
            hdr_card, text="+ Add Header",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            fg_color="transparent", hover_color=BG_INPUT,
            border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, height=28, corner_radius=6,
            command=self._add_header_row,
        ).grid(row=2, column=0, sticky="w", padx=12, pady=(0, 10))

        # ── Request body (right) ──────────────────────────────────────────────
        body_card = ctk.CTkFrame(panel, fg_color=BG_CARD, corner_radius=12,
                                 border_width=1, border_color=BORDER_COLOR)
        body_card.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        body_card.grid_columnconfigure(0, weight=1)
        body_card.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            body_card, text="Request Body",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=14, pady=(10, 4))

        self._req_body_text = ctk.CTkTextbox(
            body_card, height=140,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=BG_INPUT, border_color=BORDER_COLOR, border_width=1,
            text_color=TEXT_PRIMARY, corner_radius=8,
            scrollbar_button_color=BORDER_COLOR,
        )
        self._req_body_text.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))

    def _build_response(self):
        card = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=12,
                            border_width=1, border_color=BORDER_COLOR)
        card.grid(row=3, column=0, sticky="nsew", padx=30, pady=(12, 30))
        card.grid_columnconfigure(0, weight=1)
        card.grid_rowconfigure(5, weight=1)

        # Status row
        status_row = ctk.CTkFrame(card, fg_color="transparent")
        status_row.grid(row=0, column=0, sticky="w", padx=12, pady=(12, 4))

        self._resp_badge = ctk.CTkLabel(
            status_row, text="Response",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED, fg_color="transparent",
            corner_radius=4, padx=8, pady=2,
        )
        self._resp_badge.grid(row=0, column=0)

        self._resp_elapsed = ctk.CTkLabel(
            status_row, text="",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_DIM,
        )
        self._resp_elapsed.grid(row=0, column=1, padx=(10, 0))

        ctk.CTkFrame(card, height=1, fg_color=BORDER_COLOR, corner_radius=0
                     ).grid(row=1, column=0, sticky="ew", padx=12, pady=2)

        # Response headers
        ctk.CTkLabel(
            card, text="Response Headers",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=TEXT_DIM, anchor="w",
        ).grid(row=2, column=0, sticky="w", padx=14, pady=(6, 2))

        self._resp_headers_text = ctk.CTkTextbox(
            card, height=90,
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=BG_INPUT, border_color=BORDER_COLOR, border_width=1,
            text_color=TEXT_MUTED, corner_radius=8, state="disabled",
            scrollbar_button_color=BORDER_COLOR,
        )
        self._resp_headers_text.grid(row=3, column=0, sticky="ew", padx=12, pady=(0, 4))

        # Response body
        ctk.CTkLabel(
            card, text="Response Body",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=TEXT_DIM, anchor="w",
        ).grid(row=4, column=0, sticky="w", padx=14, pady=(6, 2))

        self._resp_body_text = ctk.CTkTextbox(
            card,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=BG_INPUT, border_color=BORDER_COLOR, border_width=1,
            text_color=TEXT_PRIMARY, corner_radius=8, state="disabled",
            scrollbar_button_color=BORDER_COLOR,
        )
        self._resp_body_text.grid(row=5, column=0, sticky="nsew", padx=12, pady=(0, 12))

        self._resp_placeholder = ctk.CTkLabel(
            card, text="Enter a URL and click Send.",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=TEXT_DIM,
        )
        self._resp_placeholder.place(relx=0.5, rely=0.6, anchor="center")

    # ── Headers editor ────────────────────────────────────────────────────────

    def _add_header_row(self, key: str = "", value: str = ""):
        row = ctk.CTkFrame(self._headers_scroll, fg_color="transparent")
        row.pack(fill="x", pady=2)

        key_e = ctk.CTkEntry(
            row, width=130, height=28,
            placeholder_text="Header-Name",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
        )

        val_e = ctk.CTkEntry(
            row, height=28,
            placeholder_text="value",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
        )

        row_tuple = (row, key_e, val_e)
        self._header_rows.append(row_tuple)

        def remove(rt=row_tuple, f=row):
            f.destroy()
            if rt in self._header_rows:
                self._header_rows.remove(rt)

        rem_btn = ctk.CTkButton(
            row, text="×", width=26, height=26, corner_radius=4,
            fg_color="transparent", hover_color=BG_INPUT,
            border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED,
            font=ctk.CTkFont(size=12),
            command=remove,
        )
        rem_btn.pack(side="right", padx=(2, 0))
        key_e.pack(side="left", padx=(0, 4))
        val_e.pack(side="left", fill="x", expand=True, padx=(0, 4))

        if key:
            key_e.insert(0, key)
        if value:
            val_e.insert(0, value)

    def _collect_headers(self) -> dict:
        headers = {}
        for _, key_e, val_e in self._header_rows:
            try:
                k = key_e.get().strip()
                v = val_e.get().strip()
                if k:
                    headers[k] = v
            except Exception:
                pass
        return headers

    # ── Send ──────────────────────────────────────────────────────────────────

    def _start_send(self):
        if self._sending:
            return

        url = self._url_entry.get().strip()
        if not url:
            self._set_status("Please enter a URL.", error=True)
            return
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        method   = self._method_menu.get()
        headers  = self._collect_headers()
        body     = self._req_body_text.get("1.0", "end").rstrip("\n")
        redirect = self._redirects_var.get()

        self._sending = True
        self._send_btn.configure(state="disabled")
        self._set_status(f"Sending {method} {url[:60]}…")
        self._result_queue = queue.Queue()

        threading.Thread(
            target=self._run_send,
            args=(method, url, headers, body, redirect),
            daemon=True,
        ).start()
        self._poll_id = self.after(POLL_MS, self._poll)

    def _run_send(self, method, url, headers, body, follow_redirects):
        result = send(method, url, headers=headers, body=body,
                      follow_redirects=follow_redirects)
        self._result_queue.put(result)

    def _poll(self):
        try:
            result = self._result_queue.get_nowait()
        except queue.Empty:
            self._poll_id = self.after(POLL_MS, self._poll)
            return

        self._sending = False
        self._send_btn.configure(state="normal")

        if result.error:
            self._set_status(f"Error: {result.error}", error=True)
            self._resp_badge.configure(
                text="Error", text_color=CLR_ERROR, fg_color="#2a0a0a",
            )
        else:
            self._set_status(f"Done  —  {result.status_code} {result.reason}  —  {result.elapsed_ms}ms")
            self._show_response(result)

    def _show_response(self, result: RequestResult):
        self._resp_placeholder.place_forget()

        text_color, bg_color = _status_colors(result.status_code)
        self._resp_badge.configure(
            text=f"  {result.status_code}  {result.reason}  ",
            text_color=text_color, fg_color=bg_color,
        )
        self._resp_elapsed.configure(text=f"{result.elapsed_ms} ms")

        headers_text = "\n".join(f"{k}: {v}" for k, v in result.headers.items())
        self._set_textbox(self._resp_headers_text, headers_text)
        self._set_textbox(self._resp_body_text, result.body)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _set_status(self, msg: str, error: bool = False):
        self._status_lbl.configure(
            text=msg,
            text_color=CLR_ERROR if error else TEXT_MUTED,
        )

    @staticmethod
    def _set_textbox(tb: ctk.CTkTextbox, text: str):
        tb.configure(state="normal")
        tb.delete("1.0", "end")
        tb.insert("1.0", text)
        tb.configure(state="disabled")
