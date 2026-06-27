"""
CyberKit — Password / Wordlist Generator Page

Two tabs:
  Brute-Force  — charset × length (itertools.product)
  Mutation     — seed phrases with leet / caps / suffix rules

Both tabs show a live 20-entry preview that updates as options change.
"""

import queue
import threading
import tkinter as tk
from tkinter import filedialog, ttk

import customtkinter as ctk

from app.modules.wordlist_generator import (
    BruteforceGenerator, MutationGenerator,
    generate_to_file,
)

# ── Palette ───────────────────────────────────────────────────────────────────
BG_MAIN       = "#0f1117"
BG_CARD       = "#161b22"
BG_INPUT      = "#0d1117"
ACCENT_CYAN   = "#00d4ff"
TEXT_PRIMARY  = "#e6edf3"
TEXT_MUTED    = "#8b949e"
TEXT_DIM      = "#484f58"
BORDER_COLOR  = "#21262d"
CLR_SUCCESS   = "#22c55e"
CLR_ERROR     = "#ef4444"
CLR_WARNING   = "#f0a500"

CHARSET_LOWER   = "abcdefghijklmnopqrstuvwxyz"
CHARSET_UPPER   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CHARSET_DIGITS  = "0123456789"
CHARSET_SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?"

# Shared state: path of the most recently exported file, accessible by
# other pages via get_last_export_path() / set_last_export_path().
_last_export_path: str = ""


def get_last_export_path() -> str:
    return _last_export_path


def set_last_export_path(path: str) -> None:
    global _last_export_path
    _last_export_path = path


class WordlistGeneratorPage(ctk.CTkFrame):
    def __init__(self, parent, navigate_callback=None, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, corner_radius=0, **kwargs)
        self._navigate        = navigate_callback
        self._gen_thread: threading.Thread | None = None
        self._stop_event      = threading.Event()
        self._gen_running     = False
        self._exported_path   = ""
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
            hdr, text="📝  Password / Wordlist Generator",
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            hdr,
            text="Generate custom wordlists via charset brute-force or seed-phrase mutation",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        # Tab bar
        tab_bar = ctk.CTkFrame(self, fg_color="transparent")
        tab_bar.grid(row=1, column=0, sticky="ew", padx=30, pady=(18, 0))

        self._tab_bf_btn = ctk.CTkButton(
            tab_bar, text="Brute-Force",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            width=130, height=34, corner_radius=8,
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color="#0f1117",
            command=lambda: self._switch_tab("bf"),
        )
        self._tab_bf_btn.grid(row=0, column=0, padx=(0, 6))

        self._tab_mut_btn = ctk.CTkButton(
            tab_bar, text="Mutation",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            width=130, height=34, corner_radius=8,
            fg_color=BG_CARD, hover_color=BG_INPUT,
            text_color=TEXT_MUTED,
            command=lambda: self._switch_tab("mut"),
        )
        self._tab_mut_btn.grid(row=0, column=1)

        # Tab container
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.grid(row=2, column=0, sticky="nsew", padx=30, pady=(12, 30))
        container.grid_columnconfigure(0, weight=1)
        container.grid_rowconfigure(0, weight=1)

        self._bf_frame  = self._build_bf_tab(container)
        self._mut_frame = self._build_mut_tab(container)

        self._bf_frame.grid(row=0, column=0, sticky="nsew")
        self._mut_frame.grid(row=0, column=0, sticky="nsew")
        self._bf_frame.tkraise()
        self._active_tab = "bf"

    def _switch_tab(self, tab: str):
        self._active_tab = tab
        if tab == "bf":
            self._bf_frame.tkraise()
            self._tab_bf_btn.configure(fg_color=ACCENT_CYAN, hover_color="#00aacc", text_color="#0f1117")
            self._tab_mut_btn.configure(fg_color=BG_CARD, hover_color=BG_INPUT, text_color=TEXT_MUTED)
        else:
            self._mut_frame.tkraise()
            self._tab_mut_btn.configure(fg_color=ACCENT_CYAN, hover_color="#00aacc", text_color="#0f1117")
            self._tab_bf_btn.configure(fg_color=BG_CARD, hover_color=BG_INPUT, text_color=TEXT_MUTED)

    # ── Brute-Force Tab ───────────────────────────────────────────────────────

    def _build_bf_tab(self, parent) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)
        frame.grid_rowconfigure(0, weight=1)

        # ── Left: controls ──────────────────────────────────────────────────
        left = ctk.CTkFrame(frame, fg_color=BG_CARD, corner_radius=12,
                            border_width=1, border_color=BORDER_COLOR)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(left, text="Character Sets",
                     font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
                     text_color=TEXT_PRIMARY, anchor="w",
                     ).grid(row=0, column=0, sticky="w", padx=18, pady=(18, 6))

        self._bf_lower  = tk.BooleanVar(value=True)
        self._bf_upper  = tk.BooleanVar(value=False)
        self._bf_digits = tk.BooleanVar(value=False)
        self._bf_syms   = tk.BooleanVar(value=False)

        for var in (self._bf_lower, self._bf_upper, self._bf_digits, self._bf_syms):
            var.trace_add("write", lambda *_: self._bf_update())

        for row, (label, var) in enumerate([
            ("Lowercase  a–z  (26 chars)", self._bf_lower),
            ("Uppercase  A–Z  (26 chars)", self._bf_upper),
            ("Digits     0–9  (10 chars)", self._bf_digits),
            ("Symbols    !@#$…  (25 chars)", self._bf_syms),
        ], start=1):
            ctk.CTkCheckBox(
                left, text=label, variable=var,
                font=ctk.CTkFont(family="Segoe UI", size=12),
                text_color=TEXT_MUTED,
                fg_color=ACCENT_CYAN, hover_color="#00aacc",
                checkmark_color="#0f1117",
            ).grid(row=row, column=0, sticky="w", padx=24, pady=3)

        ctk.CTkLabel(left, text="Length Range",
                     font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
                     text_color=TEXT_PRIMARY, anchor="w",
                     ).grid(row=5, column=0, sticky="w", padx=18, pady=(18, 6))

        len_row = ctk.CTkFrame(left, fg_color="transparent")
        len_row.grid(row=6, column=0, sticky="ew", padx=18, pady=(0, 6))

        ctk.CTkLabel(len_row, text="Min:", font=ctk.CTkFont(family="Segoe UI", size=12),
                     text_color=TEXT_MUTED).grid(row=0, column=0, padx=(0, 6))
        self._bf_min_var = tk.IntVar(value=1)
        ctk.CTkEntry(
            len_row, textvariable=self._bf_min_var, width=60, height=30,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color=BG_INPUT, border_color=BORDER_COLOR, text_color=TEXT_PRIMARY,
        ).grid(row=0, column=1, padx=(0, 18))
        self._bf_min_var.trace_add("write", lambda *_: self._bf_update())

        ctk.CTkLabel(len_row, text="Max:", font=ctk.CTkFont(family="Segoe UI", size=12),
                     text_color=TEXT_MUTED).grid(row=0, column=2, padx=(0, 6))
        self._bf_max_var = tk.IntVar(value=4)
        ctk.CTkEntry(
            len_row, textvariable=self._bf_max_var, width=60, height=30,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color=BG_INPUT, border_color=BORDER_COLOR, text_color=TEXT_PRIMARY,
        ).grid(row=0, column=3)
        self._bf_max_var.trace_add("write", lambda *_: self._bf_update())

        # Estimate + warning
        self._bf_estimate_lbl = ctk.CTkLabel(
            left, text="Estimated: 0 entries",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED, anchor="w",
        )
        self._bf_estimate_lbl.grid(row=7, column=0, sticky="w", padx=18, pady=(8, 2))

        self._bf_warn_lbl = ctk.CTkLabel(
            left, text="",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=CLR_ERROR, anchor="w",
        )
        self._bf_warn_lbl.grid(row=8, column=0, sticky="w", padx=18, pady=(0, 4))

        # Generate button + status
        self._bf_gen_btn = ctk.CTkButton(
            left, text="⬇ Generate & Export",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color="#0f1117", height=36, corner_radius=8,
            command=self._bf_generate,
        )
        self._bf_gen_btn.grid(row=9, column=0, sticky="ew", padx=18, pady=(12, 4))

        self._bf_status_lbl = ctk.CTkLabel(
            left, text="",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_MUTED, anchor="w",
        )
        self._bf_status_lbl.grid(row=10, column=0, sticky="w", padx=18, pady=(0, 4))

        # Send-to buttons
        self._build_send_buttons(left, row=11, tab="bf")

        # ── Right: preview ──────────────────────────────────────────────────
        self._bf_preview, self._bf_preview_warn = self._build_preview_panel(frame, col=1)

        self._bf_update()
        return frame

    # ── Mutation Tab ──────────────────────────────────────────────────────────

    def _build_mut_tab(self, parent) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(parent, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)
        frame.grid_rowconfigure(0, weight=1)

        # ── Left: controls ──────────────────────────────────────────────────
        left = ctk.CTkFrame(frame, fg_color=BG_CARD, corner_radius=12,
                            border_width=1, border_color=BORDER_COLOR)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        left.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(left, text="Seed Phrases (one per line)",
                     font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
                     text_color=TEXT_PRIMARY, anchor="w",
                     ).grid(row=0, column=0, sticky="w", padx=18, pady=(18, 6))

        self._mut_seeds_box = ctk.CTkTextbox(
            left, height=90,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            border_width=1, text_color=TEXT_PRIMARY,
        )
        self._mut_seeds_box.grid(row=1, column=0, sticky="ew", padx=18, pady=(0, 8))
        self._mut_seeds_box.bind("<KeyRelease>", lambda e: self._mut_update())

        ctk.CTkLabel(left, text="Mutation Rules",
                     font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
                     text_color=TEXT_PRIMARY, anchor="w",
                     ).grid(row=2, column=0, sticky="w", padx=18, pady=(4, 6))

        self._mut_leet    = tk.BooleanVar(value=False)
        self._mut_lower   = tk.BooleanVar(value=True)
        self._mut_upper   = tk.BooleanVar(value=False)
        self._mut_title   = tk.BooleanVar(value=False)
        self._mut_suffixes = tk.BooleanVar(value=False)

        for var in (self._mut_leet, self._mut_lower, self._mut_upper,
                    self._mut_title, self._mut_suffixes):
            var.trace_add("write", lambda *_: self._mut_update())

        for row, (label, var) in enumerate([
            ("Leet-speak  (a→@, e→3, i→1, o→0, s→$)", self._mut_leet),
            ("Lowercase",                               self._mut_lower),
            ("Uppercase",                               self._mut_upper),
            ("Title Case",                              self._mut_title),
            ("Numeric Suffixes  1–99",                  self._mut_suffixes),
        ], start=3):
            ctk.CTkCheckBox(
                left, text=label, variable=var,
                font=ctk.CTkFont(family="Segoe UI", size=12),
                text_color=TEXT_MUTED,
                fg_color=ACCENT_CYAN, hover_color="#00aacc",
                checkmark_color="#0f1117",
            ).grid(row=row, column=0, sticky="w", padx=24, pady=3)

        ctk.CTkLabel(left, text="Custom Prefix / Suffix",
                     font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
                     text_color=TEXT_MUTED, anchor="w",
                     ).grid(row=8, column=0, sticky="w", padx=18, pady=(10, 4))

        affix_row = ctk.CTkFrame(left, fg_color="transparent")
        affix_row.grid(row=9, column=0, sticky="ew", padx=18, pady=(0, 6))
        affix_row.grid_columnconfigure(1, weight=1)
        affix_row.grid_columnconfigure(3, weight=1)

        ctk.CTkLabel(affix_row, text="Prefix:", font=ctk.CTkFont(family="Segoe UI", size=12),
                     text_color=TEXT_MUTED).grid(row=0, column=0, padx=(0, 6))
        self._mut_prefix = ctk.CTkEntry(
            affix_row, height=28,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color=BG_INPUT, border_color=BORDER_COLOR, text_color=TEXT_PRIMARY,
        )
        self._mut_prefix.grid(row=0, column=1, sticky="ew", padx=(0, 12))
        self._mut_prefix.bind("<KeyRelease>", lambda e: self._mut_update())

        ctk.CTkLabel(affix_row, text="Suffix:", font=ctk.CTkFont(family="Segoe UI", size=12),
                     text_color=TEXT_MUTED).grid(row=0, column=2, padx=(0, 6))
        self._mut_suffix = ctk.CTkEntry(
            affix_row, height=28,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            fg_color=BG_INPUT, border_color=BORDER_COLOR, text_color=TEXT_PRIMARY,
        )
        self._mut_suffix.grid(row=0, column=3, sticky="ew")
        self._mut_suffix.bind("<KeyRelease>", lambda e: self._mut_update())

        # Estimate + warning
        self._mut_estimate_lbl = ctk.CTkLabel(
            left, text="Estimated: 0 entries",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED, anchor="w",
        )
        self._mut_estimate_lbl.grid(row=10, column=0, sticky="w", padx=18, pady=(8, 2))

        self._mut_warn_lbl = ctk.CTkLabel(
            left, text="",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=CLR_ERROR, anchor="w",
        )
        self._mut_warn_lbl.grid(row=11, column=0, sticky="w", padx=18, pady=(0, 4))

        # Generate button + status
        self._mut_gen_btn = ctk.CTkButton(
            left, text="⬇ Generate & Export",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color="#0f1117", height=36, corner_radius=8,
            command=self._mut_generate,
        )
        self._mut_gen_btn.grid(row=12, column=0, sticky="ew", padx=18, pady=(12, 4))

        self._mut_status_lbl = ctk.CTkLabel(
            left, text="",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_MUTED, anchor="w",
        )
        self._mut_status_lbl.grid(row=13, column=0, sticky="w", padx=18, pady=(0, 4))

        # Send-to buttons
        self._build_send_buttons(left, row=14, tab="mut")

        # ── Right: preview ──────────────────────────────────────────────────
        self._mut_preview, self._mut_preview_warn = self._build_preview_panel(frame, col=1)

        self._mut_update()
        return frame

    # ── Shared helpers ────────────────────────────────────────────────────────

    # Preview grid dimensions
    _PREV_COLS  = 4
    _PREV_TOTAL = 200  # entries shown (user scrolls within the panel)

    def _build_preview_panel(self, parent, col: int) -> tuple:
        """
        Build the live-preview panel.
        Returns (list_of_entry_labels, warning_label).
        Labels live inside a CTkScrollableFrame so the panel never grows the
        window — the user scrolls within the preview area instead.
        """
        panel = ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=12,
                             border_width=1, border_color=BORDER_COLOR)
        panel.grid(row=0, column=col, sticky="nsew")
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(2, weight=1)  # scrollable area expands

        ctk.CTkLabel(
            panel, text=f"Live Preview  (first {self._PREV_TOTAL} entries)",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=18, pady=(18, 10))

        # Warning label (spans full width, hidden by default)
        warn = ctk.CTkLabel(
            panel, text="",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=CLR_WARNING, anchor="w", justify="left",
        )
        warn.grid(row=1, column=0, sticky="w", padx=18, pady=(0, 4))

        # Scrollable container for the label grid
        scroll = ctk.CTkScrollableFrame(
            panel, fg_color="transparent", corner_radius=0,
            scrollbar_button_color=BORDER_COLOR,
            scrollbar_button_hover_color=TEXT_DIM,
        )
        scroll.grid(row=2, column=0, sticky="nsew", padx=8, pady=(0, 8))
        for c in range(self._PREV_COLS):
            scroll.grid_columnconfigure(c, weight=1)

        labels = []
        for i in range(self._PREV_TOTAL):
            r = i // self._PREV_COLS
            c = i % self._PREV_COLS
            lbl = ctk.CTkLabel(
                scroll, text="",
                font=ctk.CTkFont(family="Consolas", size=12),
                text_color=ACCENT_CYAN if i % 2 == 0 else TEXT_MUTED,
                anchor="w",
            )
            lbl.grid(row=r, column=c, sticky="w", padx=(10, 6), pady=2)
            labels.append(lbl)

        return labels, warn

    def _build_send_buttons(self, parent, row: int, tab: str):
        lbl = ctk.CTkLabel(parent, text="Send exported list to Credential Tester:",
                           font=ctk.CTkFont(family="Segoe UI", size=11),
                           text_color=TEXT_DIM, anchor="w")
        lbl.grid(row=row, column=0, sticky="w", padx=18, pady=(14, 4))

        btn_frame = ctk.CTkFrame(parent, fg_color="transparent")
        btn_frame.grid(row=row + 1, column=0, sticky="ew", padx=18, pady=(0, 18))
        btn_frame.grid_columnconfigure(0, weight=1)
        btn_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkButton(
            btn_frame, text="▶ Username List", height=30, corner_radius=6,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, hover_color=BG_INPUT,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            command=lambda t=tab: self._send_to_cred(t, "user"),
        ).grid(row=0, column=0, sticky="ew", padx=(0, 4))

        ctk.CTkButton(
            btn_frame, text="▶ Password List", height=30, corner_radius=6,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, hover_color=BG_INPUT,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            command=lambda t=tab: self._send_to_cred(t, "pass"),
        ).grid(row=0, column=1, sticky="ew", padx=(4, 0))

    def _send_to_cred(self, tab: str, kind: str):
        if not self._exported_path:
            return
        set_last_export_path(self._exported_path)
        # Publish via module-level signal so CredentialTesterPage can read it
        from app.ui.pages.wordlist_generator import _signal_cred_tester
        _signal_cred_tester(self._exported_path, kind, self._navigate)

    # ── Brute-force logic ─────────────────────────────────────────────────────

    def _bf_charset_and_sets(self) -> tuple[str, list[str]]:
        cs = ""
        required: list[str] = []
        for flag, chars in [
            (self._bf_lower,  CHARSET_LOWER),
            (self._bf_upper,  CHARSET_UPPER),
            (self._bf_digits, CHARSET_DIGITS),
            (self._bf_syms,   CHARSET_SYMBOLS),
        ]:
            if flag.get():
                cs += chars
                required.append(chars)
        return cs, required

    def _bf_update(self):
        cs, required = self._bf_charset_and_sets()
        try:
            mn = max(1, int(self._bf_min_var.get()))
            mx = max(mn, int(self._bf_max_var.get()))
        except (tk.TclError, ValueError):
            mn, mx = 1, 1
        if not cs:
            self._bf_estimate_lbl.configure(text="Estimated: 0 entries")
            self._bf_warn_lbl.configure(text="⚠ Select at least one charset.")
            self._bf_gen_btn.configure(state="disabled")
            for lbl in self._bf_preview:
                lbl.configure(text="")
            return
        n_req = len(required)
        gen   = BruteforceGenerator(cs, mn, mx, required_sets=required)
        est   = gen.estimated_count()
        multi = n_req > 1
        est_label = f"Up to {est:,} entries" if multi else f"Estimated: {est:,} entries"
        self._bf_estimate_lbl.configure(text=est_label)
        self._bf_warn_lbl.configure(text="")

        # Impossible combination: max length too short to hold one char per set
        if n_req > 1 and mx < n_req:
            self._bf_preview_warn.configure(
                text=f"⚠  Impossible combination: {n_req} character sets selected\n"
                     f"    require at least {n_req} characters per word,\n"
                     f"    but Max Length is {mx}.\n"
                     f"    Increase Max Length to at least {n_req}."
            )
            for lbl in self._bf_preview:
                lbl.configure(text="")
            self._bf_gen_btn.configure(state="disabled")
            return

        self._bf_preview_warn.configure(text="")
        self._bf_gen_btn.configure(state="normal")
        entries = []
        for w in gen:
            entries.append(w)
            if len(entries) >= self._PREV_TOTAL:
                break
        for i, lbl in enumerate(self._bf_preview):
            lbl.configure(text=entries[i] if i < len(entries) else "")

    def _bf_generate(self):
        if self._gen_running:
            return
        cs, required = self._bf_charset_and_sets()
        try:
            mn = max(1, int(self._bf_min_var.get()))
            mx = max(mn, int(self._bf_max_var.get()))
        except (tk.TclError, ValueError):
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile="wordlist_bruteforce.txt",
            title="Save Wordlist",
        )
        if not path:
            return
        gen = BruteforceGenerator(cs, mn, mx, required_sets=required)
        self._run_export(gen, path, self._bf_gen_btn, self._bf_status_lbl)

    # ── Mutation logic ────────────────────────────────────────────────────────

    def _mut_seeds(self) -> list[str]:
        raw = self._mut_seeds_box.get("1.0", "end")
        return [l.strip() for l in raw.splitlines() if l.strip()]

    def _mut_update(self):
        seeds = self._mut_seeds()
        gen = MutationGenerator(
            seeds=seeds,
            leet=self._mut_leet.get(),
            lower=self._mut_lower.get(),
            upper=self._mut_upper.get(),
            title=self._mut_title.get(),
            suffixes=self._mut_suffixes.get(),
            prefix=self._mut_prefix.get(),
            suffix=self._mut_suffix.get(),
        )
        est = gen.estimated_count()
        self._mut_estimate_lbl.configure(text=f"Estimated: {est:,} entries")
        self._mut_warn_lbl.configure(text="")
        self._mut_preview_warn.configure(text="")
        self._mut_gen_btn.configure(state="normal" if seeds else "disabled")
        entries = []
        for w in gen:
            entries.append(w)
            if len(entries) >= self._PREV_TOTAL:
                break
        for i, lbl in enumerate(self._mut_preview):
            lbl.configure(text=entries[i] if i < len(entries) else "")

    def _mut_generate(self):
        if self._gen_running:
            return
        seeds = self._mut_seeds()
        if not seeds:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile="wordlist_mutation.txt",
            title="Save Wordlist",
        )
        if not path:
            return
        gen = MutationGenerator(
            seeds=seeds,
            leet=self._mut_leet.get(),
            lower=self._mut_lower.get(),
            upper=self._mut_upper.get(),
            title=self._mut_title.get(),
            suffixes=self._mut_suffixes.get(),
            prefix=self._mut_prefix.get(),
            suffix=self._mut_suffix.get(),
        )
        self._run_export(gen, path, self._mut_gen_btn, self._mut_status_lbl)

    # ── Export runner (shared) ────────────────────────────────────────────────

    def _run_export(self, gen, path: str, btn, status_lbl):
        self._gen_running = True
        self._stop_event.clear()
        btn.configure(state="disabled")
        status_lbl.configure(text="Generating…", text_color=TEXT_MUTED)
        prog_q: queue.Queue[int | None] = queue.Queue()

        def worker():
            n = generate_to_file(
                gen, path,
                on_progress=lambda c: prog_q.put(c),
                stop_event=self._stop_event,
            )
            prog_q.put(None)  # sentinel

        def poll():
            try:
                while True:
                    item = prog_q.get_nowait()
                    if item is None:
                        self._gen_running = False
                        btn.configure(state="normal")
                        self._exported_path = path
                        set_last_export_path(path)
                        status_lbl.configure(
                            text=f"Done — {path.split('/')[-1].split(chr(92))[-1]}",
                            text_color=CLR_SUCCESS,
                        )
                        return
                    status_lbl.configure(
                        text=f"Generating… {item:,} entries written",
                        text_color=TEXT_MUTED,
                    )
            except queue.Empty:
                pass
            self.after(150, poll)

        self._gen_thread = threading.Thread(target=worker, daemon=True)
        self._gen_thread.start()
        self.after(150, poll)


def _signal_cred_tester(path: str, kind: str, navigate_callback):
    """
    Load the wordlist at *path* directly into the CredentialTesterPage.
    kind = 'user' | 'pass'
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            entries = [l.strip() for l in fh if l.strip()]
    except OSError:
        return
    if not entries:
        return

    # Reach into the app window's pages dict via the navigate callback's __self__
    # (AppWindow.show_page is the callback).
    try:
        app_win = navigate_callback.__self__
        cred_page = app_win._pages.get("credential_tester")
        if cred_page is None:
            return
        if kind == "user":
            cred_page._http_user_list = entries
            cred_page._http_user_label.configure(
                text=f"Custom ({len(entries)} entries)")
            cred_page._ssh_user_list = entries
            cred_page._ssh_user_label.configure(
                text=f"Custom ({len(entries)} entries)")
        else:
            cred_page._http_pass_list = entries
            cred_page._http_pass_label.configure(
                text=f"Custom ({len(entries)} entries)")
            cred_page._ssh_pass_list = entries
            cred_page._ssh_pass_label.configure(
                text=f"Custom ({len(entries)} entries)")
    except AttributeError:
        pass
