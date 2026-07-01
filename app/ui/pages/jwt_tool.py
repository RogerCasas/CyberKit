"""
CyberKit — JWT Forge & Verify Page
"""

import json
import queue
import threading
import tkinter as tk
from tkinter import filedialog

import customtkinter as ctk

from app.modules.jwt_tool import (
    BruteResult,
    JwtParts,
    brute_force,
    decode,
    forge_none_alg,
    verify_hs256,
)

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


class JwtToolPage(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, corner_radius=0, **kwargs)
        self._q:          queue.Queue      = queue.Queue()
        self._stop_event: threading.Event  = threading.Event()
        self._brute_running                = False
        self._wordlist_path                = ""
        self._current_token                = ""
        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._scroll = ctk.CTkFrame(self, fg_color=BG_MAIN, corner_radius=0)
        self._scroll.grid(row=0, column=0, sticky="nsew")
        self._scroll.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(self._scroll, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=30, pady=(28, 0))
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            hdr, text="🔑  JWT Forge & Verify",
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            hdr,
            text="Decode tokens, forge alg:none bypasses, and brute-force weak HS256 secrets.",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        self._build_token_input()
        self._build_decoded_view()
        self._build_attack_panels()

    def _section(self, row: int, title: str) -> ctk.CTkFrame:
        card = ctk.CTkFrame(
            self._scroll, fg_color=BG_CARD, corner_radius=12,
            border_width=1, border_color=BORDER_COLOR,
        )
        card.grid(row=row, column=0, sticky="ew", padx=30, pady=(16, 0))
        card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            card, text=title,
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(12, 6))
        return card

    def _build_token_input(self):
        card = self._section(1, "Token Input")

        self._token_box = ctk.CTkTextbox(
            card, height=90,
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=BG_INPUT, text_color=TEXT_PRIMARY,
            border_color=BORDER_COLOR, border_width=1,
            corner_radius=8, wrap="word",
        )
        self._token_box.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 8))

        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.grid(row=2, column=0, sticky="w", padx=16, pady=(0, 12))

        ctk.CTkButton(
            btn_row, text="▶  Decode",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color="#0f1117", height=36, width=130, corner_radius=8,
            command=self._decode,
        ).grid(row=0, column=0, padx=(0, 8))

        ctk.CTkButton(
            btn_row, text="Clear",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color="transparent", hover_color=BG_INPUT,
            border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, height=36, width=80, corner_radius=8,
            command=self._clear_all,
        ).grid(row=0, column=1)

        self._decode_err = ctk.CTkLabel(
            card, text="",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=CLR_ERROR, anchor="w",
        )
        self._decode_err.grid(row=3, column=0, sticky="w", padx=16, pady=(0, 8))

    def _build_decoded_view(self):
        card = self._section(2, "Decoded Token")

        # Key fields row
        fields_row = ctk.CTkFrame(card, fg_color="transparent")
        fields_row.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 8))
        for col in range(4):
            fields_row.grid_columnconfigure(col * 2 + 1, weight=1)

        labels = [("alg", "_alg_lbl"), ("exp", "_exp_lbl"), ("iat", "_iat_lbl"), ("sub", "_sub_lbl")]
        for i, (name, attr) in enumerate(labels):
            ctk.CTkLabel(
                fields_row, text=f"{name}:",
                font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
                text_color=TEXT_MUTED,
            ).grid(row=0, column=i * 2, padx=(0 if i == 0 else 16, 4), sticky="w")
            lbl = ctk.CTkLabel(
                fields_row, text="—",
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color=ACCENT_CYAN, anchor="w",
            )
            lbl.grid(row=0, column=i * 2 + 1, sticky="w")
            setattr(self, attr, lbl)

        # Header + Payload side by side
        panels = ctk.CTkFrame(card, fg_color="transparent")
        panels.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 12))
        panels.grid_columnconfigure(0, weight=1)
        panels.grid_columnconfigure(1, weight=1)

        for col, (label_text, attr) in enumerate([("Header", "_header_box"), ("Payload", "_payload_box")]):
            wrap = ctk.CTkFrame(panels, fg_color="transparent")
            wrap.grid(row=0, column=col, sticky="nsew", padx=(0 if col == 0 else 8, 0))
            wrap.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(
                wrap, text=label_text,
                font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
                text_color=TEXT_MUTED, anchor="w",
            ).grid(row=0, column=0, sticky="w", pady=(0, 4))
            box = ctk.CTkTextbox(
                wrap, height=120,
                font=ctk.CTkFont(family="Consolas", size=11),
                fg_color=BG_INPUT, text_color=TEXT_PRIMARY,
                border_color=BORDER_COLOR, border_width=1, corner_radius=8,
                wrap="word",
            )
            box.grid(row=1, column=0, sticky="ew")
            box.insert("1.0", "—")
            box.configure(state="disabled")
            setattr(self, attr, box)

    def _build_attack_panels(self):
        outer = ctk.CTkFrame(self._scroll, fg_color="transparent")
        outer.grid(row=3, column=0, sticky="ew", padx=30, pady=(16, 30))
        outer.grid_columnconfigure(0, weight=1)
        outer.grid_columnconfigure(1, weight=1)

        self._build_panel_a(outer)
        self._build_panel_b(outer)

    def _build_panel_a(self, parent):
        card = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=12,
                            border_width=1, border_color=BORDER_COLOR)
        card.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            card, text="alg:none Bypass",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(12, 6))

        ctk.CTkButton(
            card, text="Forge alg:none Token",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color=CLR_WARN, hover_color="#c88800",
            text_color="#0f1117", height=34, corner_radius=8,
            command=self._forge,
        ).grid(row=1, column=0, sticky="w", padx=16, pady=(0, 8))

        self._forged_box = ctk.CTkTextbox(
            card, height=80,
            font=ctk.CTkFont(family="Consolas", size=10),
            fg_color=BG_INPUT, text_color=TEXT_PRIMARY,
            border_color=BORDER_COLOR, border_width=1,
            corner_radius=8, wrap="word",
        )
        self._forged_box.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 8))
        self._forged_box.insert("1.0", "Decode a token first, then forge.")
        self._forged_box.configure(state="disabled")

        ctk.CTkButton(
            card, text="Copy Token",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            fg_color="transparent", hover_color=BG_INPUT,
            border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, height=30, corner_radius=6,
            command=self._copy_forged,
        ).grid(row=3, column=0, sticky="w", padx=16, pady=(0, 14))

    def _build_panel_b(self, parent):
        card = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=12,
                            border_width=1, border_color=BORDER_COLOR)
        card.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            card, text="HS256 Secret Brute-force",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=0, column=0, columnspan=2, sticky="w", padx=16, pady=(12, 6))

        # File picker row
        fp_row = ctk.CTkFrame(card, fg_color="transparent")
        fp_row.grid(row=1, column=0, columnspan=2, sticky="ew", padx=16, pady=(0, 6))
        fp_row.grid_columnconfigure(1, weight=1)

        ctk.CTkButton(
            fp_row, text="📂  Wordlist",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            fg_color="transparent", hover_color=BG_INPUT,
            border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, height=30, width=100, corner_radius=6,
            command=self._pick_wordlist,
        ).grid(row=0, column=0, padx=(0, 8))

        self._wordlist_lbl = ctk.CTkLabel(
            fp_row, text="No file selected.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_DIM, anchor="w",
        )
        self._wordlist_lbl.grid(row=0, column=1, sticky="w")

        # Start / Stop buttons
        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.grid(row=2, column=0, columnspan=2, sticky="w", padx=16, pady=(0, 6))

        self._bf_start_btn = ctk.CTkButton(
            btn_row, text="▶  Start",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color="#0f1117", height=34, width=100, corner_radius=8,
            command=self._start_brute,
        )
        self._bf_start_btn.grid(row=0, column=0, padx=(0, 8))

        self._bf_stop_btn = ctk.CTkButton(
            btn_row, text="■  Stop",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color=BG_INPUT, hover_color=BG_CARD,
            border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, height=34, width=100, corner_radius=8,
            state="disabled", command=self._stop_brute,
        )
        self._bf_stop_btn.grid(row=0, column=1)

        self._bf_status = ctk.CTkLabel(
            card, text="Load a wordlist and click Start.",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_MUTED, anchor="w",
        )
        self._bf_status.grid(row=3, column=0, columnspan=2, sticky="w", padx=16, pady=(0, 4))

        self._bf_result = ctk.CTkLabel(
            card, text="",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED, anchor="w",
            wraplength=320,
        )
        self._bf_result.grid(row=4, column=0, columnspan=2, sticky="w", padx=16, pady=(0, 14))

    # ── Actions ───────────────────────────────────────────────────────────────

    def _decode(self):
        raw = self._token_box.get("1.0", "end").strip()
        if not raw:
            self._decode_err.configure(text="Paste a JWT token first.")
            return
        try:
            parts = decode(raw)
        except ValueError as exc:
            self._decode_err.configure(text=f"Error: {exc}")
            return
        self._decode_err.configure(text="")
        self._current_token = raw

        # Key fields
        self._alg_lbl.configure(text=str(parts.header.get("alg", "—")))
        self._sub_lbl.configure(text=str(parts.payload.get("sub", "—"))[:40])
        import datetime
        for field, lbl in [("exp", self._exp_lbl), ("iat", self._iat_lbl)]:
            ts = parts.payload.get(field)
            if ts:
                try:
                    dt = datetime.datetime.utcfromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M UTC")
                    lbl.configure(text=dt)
                except Exception:
                    lbl.configure(text=str(ts))
            else:
                lbl.configure(text="—")

        # Header box
        self._header_box.configure(state="normal")
        self._header_box.delete("1.0", "end")
        self._header_box.insert("1.0", json.dumps(parts.header, indent=2))
        self._header_box.configure(state="disabled")

        # Payload box
        self._payload_box.configure(state="normal")
        self._payload_box.delete("1.0", "end")
        self._payload_box.insert("1.0", json.dumps(parts.payload, indent=2))
        self._payload_box.configure(state="disabled")

    def _forge(self):
        if not self._current_token:
            self._decode_err.configure(text="Decode a token before forging.")
            return
        try:
            forged = forge_none_alg(self._current_token)
        except ValueError as exc:
            self._decode_err.configure(text=f"Forge failed: {exc}")
            return
        self._forged_box.configure(state="normal")
        self._forged_box.delete("1.0", "end")
        self._forged_box.insert("1.0", forged)
        self._forged_box.configure(state="disabled")

    def _copy_forged(self):
        self._forged_box.configure(state="normal")
        text = self._forged_box.get("1.0", "end").strip()
        self._forged_box.configure(state="disabled")
        if text and text != "Decode a token first, then forge.":
            self.clipboard_clear()
            self.clipboard_append(text)

    def _pick_wordlist(self):
        path = filedialog.askopenfilename(
            title="Select Wordlist",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if path:
            self._wordlist_path = path
            short = path if len(path) <= 55 else "…" + path[-52:]
            self._wordlist_lbl.configure(text=short, text_color=TEXT_MUTED)

    def _start_brute(self):
        if self._brute_running:
            return
        if not self._current_token:
            self._bf_status.configure(text="Decode a token first.")
            return
        if not self._wordlist_path:
            self._bf_status.configure(text="Select a wordlist file first.")
            return
        self._stop_event.clear()
        self._q = queue.Queue()
        self._brute_running = True
        self._bf_start_btn.configure(state="disabled")
        self._bf_stop_btn.configure(state="normal")
        self._bf_result.configure(text="", text_color=TEXT_MUTED)
        self._bf_status.configure(text="Starting…", text_color=TEXT_MUTED)

        threading.Thread(
            target=self._run_brute,
            args=(self._current_token, self._wordlist_path),
            daemon=True,
        ).start()
        self.after(POLL_MS, self._poll_brute)

    def _stop_brute(self):
        self._stop_event.set()
        self._bf_stop_btn.configure(state="disabled")

    def _run_brute(self, token: str, wordlist: str):
        result = brute_force(token, wordlist, self._stop_event, self._q.put)
        self._q.put(("DONE", result))

    def _poll_brute(self):
        try:
            item = self._q.get_nowait()
        except queue.Empty:
            self.after(POLL_MS, self._poll_brute)
            return

        if isinstance(item, tuple) and item[0] == "DONE":
            self._finish_brute(item[1])
            return

        # Progress update
        r: BruteResult = item
        self._bf_status.configure(
            text=f"Tried {r.attempts:,} candidates  ({r.elapsed_s:.1f}s)  — last: {r.secret!r}"
        )
        self.after(POLL_MS, self._poll_brute)

    def _finish_brute(self, result: BruteResult):
        self._brute_running = False
        self._bf_start_btn.configure(state="normal")
        self._bf_stop_btn.configure(state="disabled")
        if result.found:
            self._bf_result.configure(
                text=f"Secret found: {result.secret!r}  ({result.attempts:,} attempts, {result.elapsed_s:.2f}s)",
                text_color=CLR_OK,
            )
            self._bf_status.configure(text="Brute-force complete.", text_color=TEXT_MUTED)
        elif self._stop_event.is_set():
            self._bf_status.configure(text="Stopped by user.", text_color=CLR_WARN)
        else:
            self._bf_result.configure(
                text=f"Secret not found after {result.attempts:,} attempts ({result.elapsed_s:.2f}s).",
                text_color=TEXT_MUTED,
            )
            self._bf_status.configure(text="Wordlist exhausted — no match.", text_color=TEXT_MUTED)

    def _clear_all(self):
        self._token_box.delete("1.0", "end")
        self._decode_err.configure(text="")
        self._current_token = ""
        for lbl in [self._alg_lbl, self._exp_lbl, self._iat_lbl, self._sub_lbl]:
            lbl.configure(text="—")
        for box in [self._header_box, self._payload_box]:
            box.configure(state="normal")
            box.delete("1.0", "end")
            box.insert("1.0", "—")
            box.configure(state="disabled")
        self._forged_box.configure(state="normal")
        self._forged_box.delete("1.0", "end")
        self._forged_box.insert("1.0", "Decode a token first, then forge.")
        self._forged_box.configure(state="disabled")
        self._bf_result.configure(text="")
        self._bf_status.configure(text="Load a wordlist and click Start.")
