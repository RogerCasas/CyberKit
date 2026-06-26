"""
CyberKit — Encoder / Decoder Page
"""

import json
import tkinter as tk

import customtkinter as ctk

from app.modules.encoder_decoder_ops import (
    url_encode, url_decode,
    base64_encode, base64_decode,
    base64url_encode, base64url_decode,
    html_encode, html_decode,
    hex_encode, hex_decode,
    rot13,
    jwt_inspect,
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
CLR_ERROR    = "#ef4444"
CLR_OK       = "#22c55e"

MODES = [
    "URL",
    "Base64",
    "Base64 URL-safe",
    "HTML Entities",
    "Hex",
    "ROT-13",
    "JWT Inspect",
]

# Modes that only have a single "transform" direction
_SYMMETRIC = {"ROT-13", "JWT Inspect"}


class EncoderDecoderPage(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, corner_radius=0, **kwargs)
        self._mode = tk.StringVar(value="Base64")
        self._mode.trace_add("write", self._on_mode_change)
        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # ── Header ────────────────────────────────────────────────────────────
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=30, pady=(28, 0))
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            hdr, text="🔤  Encoder / Decoder",
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            hdr,
            text="URL • Base64 • HTML Entities • Hex • ROT-13 • JWT inspection",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        # ── Controls card ─────────────────────────────────────────────────────
        ctrl = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=12,
                            border_width=1, border_color=BORDER_COLOR)
        ctrl.grid(row=1, column=0, sticky="ew", padx=30, pady=(20, 0))
        ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            ctrl, text="Mode",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED,
        ).grid(row=0, column=0, padx=(18, 10), pady=(14, 4), sticky="w")

        self._inline_error = ctk.CTkLabel(
            ctrl, text="",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=CLR_ERROR, anchor="w",
        )
        self._inline_error.grid(row=0, column=1, columnspan=3,
                                sticky="w", padx=(0, 18), pady=(14, 4))

        self._mode_menu = ctk.CTkOptionMenu(
            ctrl, variable=self._mode, values=MODES,
            fg_color=BG_INPUT, button_color=ACCENT_CYAN,
            button_hover_color="#00aacc", dropdown_fg_color=BG_CARD,
            text_color=TEXT_PRIMARY, dropdown_text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(family="Segoe UI", size=13),
            width=160,
        )
        self._mode_menu.grid(row=1, column=0, padx=(18, 10), pady=(0, 14), sticky="w")

        self._encode_btn = ctk.CTkButton(
            ctrl, text="▶  Encode",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color="#0f1117", height=36, width=120, corner_radius=8,
            command=self._do_encode,
        )
        self._encode_btn.grid(row=1, column=1, padx=(0, 8), pady=(0, 14), sticky="w")

        self._decode_btn = ctk.CTkButton(
            ctrl, text="◀  Decode",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=BG_INPUT, hover_color=BG_CARD,
            border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, height=36, width=120, corner_radius=8,
            command=self._do_decode,
        )
        self._decode_btn.grid(row=1, column=2, padx=(0, 8), pady=(0, 14), sticky="w")

        btn_frame = ctk.CTkFrame(ctrl, fg_color="transparent")
        btn_frame.grid(row=1, column=3, padx=(0, 18), pady=(0, 14), sticky="e")

        ctk.CTkButton(
            btn_frame, text="⇄  Swap",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, hover_color=BG_INPUT,
            height=36, width=90, corner_radius=8,
            command=self._swap,
        ).grid(row=0, column=0, padx=(0, 6))

        ctk.CTkButton(
            btn_frame, text="✕  Clear",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, hover_color=BG_INPUT,
            height=36, width=90, corner_radius=8,
            command=self._clear,
        ).grid(row=0, column=1)

        # ── I/O panels ────────────────────────────────────────────────────────
        io_frame = ctk.CTkFrame(self, fg_color="transparent")
        io_frame.grid(row=2, column=0, sticky="nsew", padx=30, pady=(16, 30))
        io_frame.grid_columnconfigure(0, weight=1)
        io_frame.grid_columnconfigure(1, weight=1)
        io_frame.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            io_frame, text="Input",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=0, column=0, sticky="w", pady=(0, 4))

        ctk.CTkLabel(
            io_frame, text="Output",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=0, column=1, sticky="w", padx=(12, 0), pady=(0, 4))

        self._input_box = ctk.CTkTextbox(
            io_frame,
            fg_color=BG_CARD, text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(family="Consolas", size=13),
            border_width=1, border_color=BORDER_COLOR, corner_radius=8,
            wrap="word",
        )
        self._input_box.grid(row=1, column=0, sticky="nsew")

        self._output_box = ctk.CTkTextbox(
            io_frame,
            fg_color=BG_INPUT, text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(family="Consolas", size=13),
            border_width=1, border_color=BORDER_COLOR, corner_radius=8,
            wrap="word", state="disabled",
        )
        self._output_box.grid(row=1, column=1, sticky="nsew", padx=(12, 0))

    # ── Mode change ───────────────────────────────────────────────────────────

    def _on_mode_change(self, *_):
        mode = self._mode.get()
        self._inline_error.configure(text="")
        if mode == "JWT Inspect":
            self._encode_btn.configure(text="🔍  Inspect")
            self._decode_btn.configure(state="disabled")
        elif mode == "ROT-13":
            self._encode_btn.configure(text="⇄  ROT-13")
            self._decode_btn.configure(state="disabled")
        else:
            self._encode_btn.configure(text="▶  Encode")
            self._decode_btn.configure(state="normal")

    # ── Actions ───────────────────────────────────────────────────────────────

    def _do_encode(self):
        self._inline_error.configure(text="")
        text = self._input_box.get("1.0", "end-1c")
        mode = self._mode.get()
        try:
            if mode == "URL":
                result = url_encode(text)
            elif mode == "Base64":
                result = base64_encode(text)
            elif mode == "Base64 URL-safe":
                result = base64url_encode(text)
            elif mode == "HTML Entities":
                result = html_encode(text)
            elif mode == "Hex":
                result = hex_encode(text)
            elif mode == "ROT-13":
                result = rot13(text)
            elif mode == "JWT Inspect":
                header, payload = jwt_inspect(text)
                result = (
                    "── Header ──\n"
                    + json.dumps(header, indent=2)
                    + "\n\n── Payload ──\n"
                    + json.dumps(payload, indent=2)
                )
            else:
                return
            self._set_output(result)
        except (ValueError, Exception) as e:
            self._inline_error.configure(text=str(e))

    def _do_decode(self):
        self._inline_error.configure(text="")
        text = self._input_box.get("1.0", "end-1c")
        mode = self._mode.get()
        try:
            if mode == "URL":
                result = url_decode(text)
            elif mode == "Base64":
                result = base64_decode(text)
            elif mode == "Base64 URL-safe":
                result = base64url_decode(text)
            elif mode == "HTML Entities":
                result = html_decode(text)
            elif mode == "Hex":
                result = hex_decode(text)
            else:
                return
            self._set_output(result)
        except (ValueError, Exception) as e:
            self._inline_error.configure(text=str(e))

    def _set_output(self, text: str):
        self._output_box.configure(state="normal")
        self._output_box.delete("1.0", "end")
        self._output_box.insert("1.0", text)
        self._output_box.configure(state="disabled")

    def _swap(self):
        self._inline_error.configure(text="")
        out = self._output_box.get("1.0", "end-1c")
        self._input_box.delete("1.0", "end")
        self._input_box.insert("1.0", out)
        self._output_box.configure(state="normal")
        self._output_box.delete("1.0", "end")
        self._output_box.configure(state="disabled")

    def _clear(self):
        self._inline_error.configure(text="")
        self._input_box.delete("1.0", "end")
        self._output_box.configure(state="normal")
        self._output_box.delete("1.0", "end")
        self._output_box.configure(state="disabled")
