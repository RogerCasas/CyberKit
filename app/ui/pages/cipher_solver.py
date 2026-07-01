"""
CyberKit — Cipher Identifier & Solver Page
"""

import tkinter as tk
from tkinter import ttk

import customtkinter as ctk

from app.modules.cipher_solver import (
    CipherCandidate,
    identify,
    solve_caesar,
    solve_railfence,
    solve_vigenere,
    solve_xor,
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

# ttk style names
TREE_STYLE = "CipherTree.Treeview"


class CipherSolverPage(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, corner_radius=0, **kwargs)
        self._candidates: list[CipherCandidate] = []
        self._selected_cipher = ""
        self._build()
        self._apply_tree_style()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _apply_tree_style(self):
        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            TREE_STYLE,
            background=BG_INPUT,
            foreground=TEXT_PRIMARY,
            fieldbackground=BG_INPUT,
            rowheight=28,
            font=("Segoe UI", 11),
            borderwidth=0,
        )
        style.configure(
            f"{TREE_STYLE}.Heading",
            background=BG_CARD,
            foreground=TEXT_MUTED,
            font=("Segoe UI", 10, "bold"),
            relief="flat",
        )
        style.map(TREE_STYLE, background=[("selected", "#1f3a5f")])

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
            hdr, text="🔐  Cipher Identifier & Solver",
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            hdr,
            text="Paste ciphertext to identify Caesar, Vigenère, XOR, or Rail Fence — then solve with one click.",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        self._build_input()
        self._build_candidates()
        self._build_solve_panel()

    def _card(self, row: int, title: str, pady_top: int = 16) -> ctk.CTkFrame:
        card = ctk.CTkFrame(
            self._scroll, fg_color=BG_CARD, corner_radius=12,
            border_width=1, border_color=BORDER_COLOR,
        )
        card.grid(row=row, column=0, sticky="ew", padx=30, pady=(pady_top, 0))
        card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            card, text=title,
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(12, 6))
        return card

    def _build_input(self):
        card = self._card(1, "Ciphertext Input")

        self._cipher_input = ctk.CTkTextbox(
            card, height=100,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=BG_INPUT, text_color=TEXT_PRIMARY,
            border_color=BORDER_COLOR, border_width=1,
            corner_radius=8, wrap="word",
        )
        self._cipher_input.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 8))

        btn_row = ctk.CTkFrame(card, fg_color="transparent")
        btn_row.grid(row=2, column=0, sticky="w", padx=16, pady=(0, 12))

        ctk.CTkButton(
            btn_row, text="🔍  Identify",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color="#0f1117", height=36, width=130, corner_radius=8,
            command=self._run_identify,
        ).grid(row=0, column=0, padx=(0, 8))

        ctk.CTkButton(
            btn_row, text="Clear",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color="transparent", hover_color=BG_INPUT,
            border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, height=36, width=80, corner_radius=8,
            command=self._clear,
        ).grid(row=0, column=1)

        self._input_err = ctk.CTkLabel(
            card, text="",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=CLR_ERROR, anchor="w",
        )
        self._input_err.grid(row=3, column=0, sticky="w", padx=16, pady=(0, 4))

    def _build_candidates(self):
        card = self._card(2, "Cipher Candidates  — click a row to solve")
        card.grid_rowconfigure(1, weight=1)

        tree_frame = tk.Frame(card, bg=BG_CARD)
        tree_frame.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 12))

        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        self._tree = ttk.Treeview(
            tree_frame,
            columns=("rank", "cipher", "confidence", "key"),
            show="headings",
            style=TREE_STYLE,
            height=6,
            yscrollcommand=vsb.set,
            selectmode="browse",
        )
        vsb.configure(command=self._tree.yview)
        vsb.pack(side="right", fill="y")
        self._tree.pack(side="left", fill="both", expand=True)

        self._tree.heading("rank",       text="#")
        self._tree.heading("cipher",     text="Cipher")
        self._tree.heading("confidence", text="Confidence %")
        self._tree.heading("key",        text="Auto-Key")
        self._tree.column("rank",       width=40,  anchor="center", stretch=False)
        self._tree.column("cipher",     width=120, anchor="w",      stretch=False)
        self._tree.column("confidence", width=120, anchor="center", stretch=False)
        self._tree.column("key",        width=200, anchor="w",      stretch=True)

        self._tree.bind("<<TreeviewSelect>>", self._on_row_select)

    def _build_solve_panel(self):
        card = self._card(3, "Solve", pady_top=16)
        card.grid(pady=(16, 30))
        card.grid_columnconfigure(1, weight=1)

        # Cipher label (read-only) + key entry + Solve button
        ctk.CTkLabel(
            card, text="Cipher:",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED,
        ).grid(row=1, column=0, padx=(16, 8), pady=(0, 8), sticky="w")
        self._cipher_name_lbl = ctk.CTkLabel(
            card, text="—",
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color=ACCENT_CYAN, anchor="w",
        )
        self._cipher_name_lbl.grid(row=1, column=1, sticky="w", pady=(0, 8))

        ctk.CTkLabel(
            card, text="Key:",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED,
        ).grid(row=2, column=0, padx=(16, 8), pady=(0, 8), sticky="w")
        self._key_entry = ctk.CTkEntry(
            card, width=200, height=34,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
        )
        self._key_entry.grid(row=2, column=1, sticky="w", padx=(0, 8), pady=(0, 8))

        ctk.CTkButton(
            card, text="Solve",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color="#0f1117", height=34, width=80, corner_radius=8,
            command=self._run_solve,
        ).grid(row=2, column=2, padx=(0, 16), pady=(0, 8))

        ctk.CTkLabel(
            card, text="Plaintext:",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=3, column=0, columnspan=3, sticky="w", padx=16, pady=(4, 4))

        self._plaintext_box = ctk.CTkTextbox(
            card, height=120,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=BG_INPUT, text_color=TEXT_PRIMARY,
            border_color=BORDER_COLOR, border_width=1,
            corner_radius=8, wrap="word",
        )
        self._plaintext_box.grid(row=4, column=0, columnspan=3, sticky="ew", padx=16, pady=(0, 16))
        self._plaintext_box.insert("1.0", "Select a candidate or click Solve to decrypt.")
        self._plaintext_box.configure(state="disabled")

    # ── Actions ───────────────────────────────────────────────────────────────

    def _run_identify(self):
        self._input_err.configure(text="")
        text = self._cipher_input.get("1.0", "end").strip()
        if not text:
            self._input_err.configure(text="Paste a ciphertext first.")
            return

        candidates = identify(text)
        self._candidates = candidates

        for row in self._tree.get_children():
            self._tree.delete(row)

        for i, c in enumerate(candidates, start=1):
            self._tree.insert(
                "", "end",
                values=(i, c.cipher, f"{c.confidence * 100:.1f}%", c.key),
            )

        if candidates:
            first = self._tree.get_children()[0]
            self._tree.selection_set(first)
            self._tree.focus(first)
            self._show_candidate(candidates[0])

    def _on_row_select(self, _event):
        sel = self._tree.selection()
        if not sel:
            return
        item = self._tree.item(sel[0])
        rank = item["values"][0]
        if not rank:
            return
        idx = int(rank) - 1
        if 0 <= idx < len(self._candidates):
            self._show_candidate(self._candidates[idx])

    def _show_candidate(self, c: CipherCandidate):
        self._selected_cipher = c.cipher
        self._cipher_name_lbl.configure(text=c.cipher)
        self._key_entry.delete(0, "end")
        self._key_entry.insert(0, c.key)
        self._show_plaintext(c.plaintext)

    def _run_solve(self):
        text = self._cipher_input.get("1.0", "end").strip()
        if not text:
            self._input_err.configure(text="No ciphertext to solve.")
            return
        cipher = self._selected_cipher
        key = self._key_entry.get().strip()
        if not cipher:
            self._input_err.configure(text="Select a cipher candidate first.")
            return
        try:
            plaintext = self._apply_solve(text, cipher, key)
        except Exception as exc:
            self._input_err.configure(text=f"Solve error: {exc}")
            return
        self._input_err.configure(text="")
        self._show_plaintext(plaintext)

    def _apply_solve(self, text: str, cipher: str, key: str) -> str:
        if cipher == "Caesar":
            try:
                shift = int(key)
            except ValueError:
                raise ValueError(f"Caesar key must be an integer shift (0–25), got {key!r}")
            return solve_caesar(text, shift)
        if cipher == "Vigenère":
            if not key:
                raise ValueError("Vigenère key cannot be empty.")
            return solve_vigenere(text, key)
        if cipher == "XOR":
            if not key:
                raise ValueError("XOR key cannot be empty (provide hex bytes, e.g. 2b).")
            return solve_xor(text, key)
        if cipher == "Rail Fence":
            try:
                rails = int(key)
            except ValueError:
                raise ValueError(f"Rail Fence key must be an integer number of rails, got {key!r}")
            return solve_railfence(text, rails)
        raise ValueError(f"Unknown cipher: {cipher!r}")

    def _show_plaintext(self, text: str):
        self._plaintext_box.configure(state="normal")
        self._plaintext_box.delete("1.0", "end")
        self._plaintext_box.insert("1.0", text)
        self._plaintext_box.configure(state="disabled")

    def _clear(self):
        self._cipher_input.delete("1.0", "end")
        self._input_err.configure(text="")
        self._candidates = []
        self._selected_cipher = ""
        for row in self._tree.get_children():
            self._tree.delete(row)
        self._cipher_name_lbl.configure(text="—")
        self._key_entry.delete(0, "end")
        self._show_plaintext("Select a candidate or click Solve to decrypt.")
