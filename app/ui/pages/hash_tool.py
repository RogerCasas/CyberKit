"""
CyberKit — Hash Identifier & Cracker Page
"""

import queue
import threading
import tkinter as tk
from tkinter import filedialog, ttk

import customtkinter as ctk

from app.data.wordlists import CRACK_WORDLIST
from app.modules.hash_identifier import identify, HashMatch
from app.modules.hash_cracker import HashCrackEngine, CrackResult, SUPPORTED_ALGORITHMS
from app.utils.file_helpers import load_wordlist_file

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
CLR_FOUND    = "#22c55e"
CLR_ERROR    = "#ef4444"
CLR_MUTED    = "#8b949e"

POLL_MS = 100
_ALGO_DISPLAY = ["MD5", "SHA-1", "SHA-256", "SHA-512"]


class HashToolPage(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, corner_radius=0, **kwargs)

        self._crack_engine: HashCrackEngine | None = None
        self._crack_queue:  queue.Queue = queue.Queue()
        self._crack_stop:   threading.Event = threading.Event()
        self._crack_running = False
        self._crack_poll_id = None
        self._crack_wordlist: list = list(CRACK_WORDLIST)
        self._crack_use_custom = False

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
            hdr, text="#  Hash Tool",
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            hdr,
            text="Identify hash algorithm by pattern  •  Dictionary attack via hashlib",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        # ── Tab bar ───────────────────────────────────────────────────────────
        tab_bar = ctk.CTkFrame(self, fg_color="transparent")
        tab_bar.grid(row=1, column=0, sticky="ew", padx=30, pady=(18, 0))

        self._tab_id_btn = ctk.CTkButton(
            tab_bar, text="Identify",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            width=110, height=34, corner_radius=8,
            fg_color=ACCENT_CYAN, hover_color="#00aacc", text_color="#0f1117",
            command=lambda: self._switch_tab("identify"),
        )
        self._tab_id_btn.grid(row=0, column=0, padx=(0, 6))

        self._tab_crack_btn = ctk.CTkButton(
            tab_bar, text="Crack",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            width=110, height=34, corner_radius=8,
            fg_color=BG_CARD, hover_color=BG_INPUT,
            border_width=1, border_color=BORDER_COLOR, text_color=TEXT_MUTED,
            command=lambda: self._switch_tab("crack"),
        )
        self._tab_crack_btn.grid(row=0, column=1)

        # ── Tab frames ────────────────────────────────────────────────────────
        self._identify_frame = self._build_identify_tab()
        self._crack_frame    = self._build_crack_tab()

        self._identify_frame.grid(row=2, column=0, sticky="nsew", padx=30, pady=(14, 30))
        self._crack_frame.grid(row=2, column=0, sticky="nsew", padx=30, pady=(14, 30))
        self._identify_frame.tkraise()

    def _build_identify_tab(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        # Input card
        ctrl = ctk.CTkFrame(frame, fg_color=BG_CARD, corner_radius=12,
                            border_width=1, border_color=BORDER_COLOR)
        ctrl.grid(row=0, column=0, sticky="ew")
        ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            ctrl, text="Hash",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED,
        ).grid(row=0, column=0, padx=(18, 10), pady=(14, 4), sticky="w")

        self._id_error = ctk.CTkLabel(
            ctrl, text="",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=CLR_ERROR, anchor="w",
        )
        self._id_error.grid(row=0, column=1, sticky="w", padx=(0, 18), pady=(14, 4))

        self._id_entry = ctk.CTkEntry(
            ctrl,
            placeholder_text="Paste a hash value…",
            font=ctk.CTkFont(family="Consolas", size=13),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, height=38,
        )
        self._id_entry.grid(row=1, column=0, columnspan=2, sticky="ew",
                            padx=18, pady=(0, 6))
        self._id_entry.bind("<Return>", lambda e: self._do_identify())

        ctk.CTkButton(
            ctrl, text="🔍  Identify",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color="#0f1117", height=36, width=130, corner_radius=8,
            command=self._do_identify,
        ).grid(row=2, column=0, padx=(18, 0), pady=(0, 14), sticky="w")

        # Results card
        results = ctk.CTkFrame(frame, fg_color=BG_CARD, corner_radius=12,
                               border_width=1, border_color=BORDER_COLOR)
        results.grid(row=1, column=0, sticky="nsew", pady=(12, 0))
        results.grid_columnconfigure(0, weight=1)
        results.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            results, text="Candidates",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(12, 8))

        self._id_scrollable = ctk.CTkFrame(
            results, fg_color="transparent", corner_radius=0,
        )
        self._id_scrollable.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))
        self._id_scrollable.grid_columnconfigure(0, weight=1)

        self._id_empty = ctk.CTkLabel(
            results,
            text="Paste a hash above and click Identify.",
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=TEXT_DIM,
        )
        self._id_empty.place(relx=0.5, rely=0.5, anchor="center")

        return frame

    def _build_crack_tab(self) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(1, weight=1)

        # Controls card
        ctrl = ctk.CTkFrame(frame, fg_color=BG_CARD, corner_radius=12,
                            border_width=1, border_color=BORDER_COLOR)
        ctrl.grid(row=0, column=0, sticky="ew")
        ctrl.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            ctrl, text="Hash",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED,
        ).grid(row=0, column=0, padx=(18, 10), pady=(14, 4), sticky="w")

        self._crack_error = ctk.CTkLabel(
            ctrl, text="",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=CLR_ERROR, anchor="w",
        )
        self._crack_error.grid(row=0, column=1, columnspan=3,
                               sticky="w", padx=(0, 18), pady=(14, 4))

        self._crack_entry = ctk.CTkEntry(
            ctrl,
            placeholder_text="Paste hash to crack…",
            font=ctk.CTkFont(family="Consolas", size=13),
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY, height=38,
        )
        self._crack_entry.grid(row=1, column=0, columnspan=4, sticky="ew",
                               padx=18, pady=(0, 6))

        # Algorithm selector
        ctk.CTkLabel(
            ctrl, text="Algorithm",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED,
        ).grid(row=2, column=0, padx=(18, 10), pady=(4, 0), sticky="w")

        self._algo_var = tk.StringVar(value="MD5")
        ctk.CTkOptionMenu(
            ctrl, variable=self._algo_var, values=_ALGO_DISPLAY,
            fg_color=BG_INPUT, button_color=ACCENT_CYAN,
            button_hover_color="#00aacc", dropdown_fg_color=BG_CARD,
            text_color=TEXT_PRIMARY, dropdown_text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(family="Segoe UI", size=13), width=140,
        ).grid(row=3, column=0, padx=(18, 10), pady=(4, 14), sticky="w")

        # Wordlist row
        ctk.CTkLabel(
            ctrl, text="Wordlist",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED,
        ).grid(row=2, column=1, padx=(0, 10), pady=(4, 0), sticky="w")

        wl_row = ctk.CTkFrame(ctrl, fg_color="transparent")
        wl_row.grid(row=3, column=1, columnspan=3, padx=(0, 18), pady=(4, 14), sticky="w")

        self._wl_bundled_btn = ctk.CTkButton(
            wl_row, text="Bundled",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            width=90, height=32, corner_radius=8,
            fg_color=ACCENT_CYAN, hover_color="#00aacc", text_color="#0f1117",
            command=lambda: self._set_wl_mode(False),
        )
        self._wl_bundled_btn.grid(row=0, column=0, padx=(0, 6))

        self._wl_custom_btn = ctk.CTkButton(
            wl_row, text="Custom",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            width=90, height=32, corner_radius=8,
            fg_color=BG_INPUT, hover_color=BG_CARD,
            border_width=1, border_color=BORDER_COLOR, text_color=TEXT_MUTED,
            command=lambda: self._set_wl_mode(True),
        )
        self._wl_custom_btn.grid(row=0, column=1, padx=(0, 6))

        self._wl_browse_btn = ctk.CTkButton(
            wl_row, text="Browse…",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            width=90, height=32, corner_radius=8,
            fg_color="transparent", border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, hover_color=BG_INPUT, state="disabled",
            command=self._browse_wordlist,
        )
        self._wl_browse_btn.grid(row=0, column=2, padx=(0, 8))

        self._wl_label = ctk.CTkLabel(
            wl_row, text=f"({len(CRACK_WORDLIST)} words)",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_MUTED,
        )
        self._wl_label.grid(row=0, column=3)

        # Start / Stop
        self._start_btn = ctk.CTkButton(
            ctrl, text="▶  Start",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color="#0f1117", height=36, width=110, corner_radius=8,
            command=self._start_crack,
        )
        self._start_btn.grid(row=4, column=0, padx=(18, 10), pady=(0, 14), sticky="w")

        self._stop_btn = ctk.CTkButton(
            ctrl, text="■  Stop",
            font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
            fg_color=BG_INPUT, hover_color=BG_CARD,
            border_width=1, border_color=BORDER_COLOR,
            text_color=TEXT_MUTED, height=36, width=110, corner_radius=8,
            state="disabled", command=self._stop_crack,
        )
        self._stop_btn.grid(row=4, column=1, padx=(0, 18), pady=(0, 14), sticky="w")

        # Results panel
        results = ctk.CTkFrame(frame, fg_color=BG_CARD, corner_radius=12,
                               border_width=1, border_color=BORDER_COLOR)
        results.grid(row=1, column=0, sticky="nsew", pady=(12, 0))
        results.grid_columnconfigure(0, weight=1)
        results.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            results, text="Result",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(12, 4))

        self._crack_result_label = ctk.CTkLabel(
            results, text="No crack attempted yet.",
            font=ctk.CTkFont(family="Segoe UI", size=15),
            text_color=TEXT_DIM,
        )
        self._crack_result_label.grid(row=1, column=0, padx=18, pady=(4, 8))

        self._crack_status = ctk.CTkLabel(
            results, text="",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_MUTED, anchor="w",
        )
        self._crack_status.grid(row=2, column=0, sticky="w", padx=16, pady=(0, 12))

        self._crack_progress = ctk.CTkProgressBar(
            results, height=4, progress_color=ACCENT_CYAN,
            fg_color=BG_INPUT, corner_radius=2,
        )
        self._crack_progress.set(0)
        self._crack_progress.grid(row=3, column=0, sticky="ew", padx=16, pady=(0, 14))

        return frame

    # ── Tab switching ─────────────────────────────────────────────────────────

    def _switch_tab(self, tab: str):
        if tab == "identify":
            self._identify_frame.tkraise()
            self._tab_id_btn.configure(fg_color=ACCENT_CYAN, hover_color="#00aacc", text_color="#0f1117")
            self._tab_crack_btn.configure(fg_color=BG_CARD, hover_color=BG_INPUT, text_color=TEXT_MUTED)
        else:
            self._crack_frame.tkraise()
            self._tab_crack_btn.configure(fg_color=ACCENT_CYAN, hover_color="#00aacc", text_color="#0f1117")
            self._tab_id_btn.configure(fg_color=BG_CARD, hover_color=BG_INPUT, text_color=TEXT_MUTED)

    # ── Identify ──────────────────────────────────────────────────────────────

    def _do_identify(self):
        self._id_error.configure(text="")
        h = self._id_entry.get().strip()
        if not h:
            self._id_error.configure(text="Please enter a hash value.")
            return

        for w in self._id_scrollable.winfo_children():
            w.destroy()

        matches = identify(h)
        self._id_empty.place_forget()

        if not matches:
            ctk.CTkLabel(
                self._id_scrollable,
                text="No known pattern matched. The hash may be salted, truncated, or an unsupported type.",
                font=ctk.CTkFont(family="Segoe UI", size=12),
                text_color=TEXT_MUTED, anchor="w", wraplength=500, justify="left",
            ).grid(row=0, column=0, sticky="w", padx=8, pady=8)
            return

        for i, m in enumerate(matches):
            row_bg = BG_TABLE_ROW if i % 2 == 0 else BG_TABLE_ALT
            row = ctk.CTkFrame(self._id_scrollable, fg_color=row_bg, corner_radius=6)
            row.grid(row=i, column=0, sticky="ew", pady=2)
            row.grid_columnconfigure(1, weight=1)

            ctk.CTkLabel(
                row, text=m.name,
                font=ctk.CTkFont(family="Segoe UI", size=13, weight="bold"),
                text_color=ACCENT_CYAN, anchor="w", width=160,
            ).grid(row=0, column=0, padx=(10, 0), pady=8, sticky="w")

            ctk.CTkLabel(
                row, text=m.notes,
                font=ctk.CTkFont(family="Segoe UI", size=12),
                text_color=TEXT_MUTED, anchor="w",
            ).grid(row=0, column=1, padx=(8, 10), pady=8, sticky="w")

    # ── Crack ─────────────────────────────────────────────────────────────────

    def _set_wl_mode(self, custom: bool):
        self._crack_use_custom = custom
        if custom:
            self._wl_custom_btn.configure(fg_color=ACCENT_CYAN, text_color="#0f1117")
            self._wl_bundled_btn.configure(fg_color=BG_INPUT, text_color=TEXT_MUTED)
            self._wl_browse_btn.configure(state="normal")
        else:
            self._wl_bundled_btn.configure(fg_color=ACCENT_CYAN, text_color="#0f1117")
            self._wl_custom_btn.configure(fg_color=BG_INPUT, text_color=TEXT_MUTED)
            self._wl_browse_btn.configure(state="disabled")
            self._crack_wordlist = list(CRACK_WORDLIST)
            self._wl_label.configure(text=f"({len(CRACK_WORDLIST)} words)")

    def _browse_wordlist(self):
        words = load_wordlist_file("Select Password Wordlist")
        if words:
            self._crack_wordlist = words
            self._wl_label.configure(text=f"({len(words)} words)")

    def _start_crack(self):
        self._crack_error.configure(text="")
        h = self._crack_entry.get().strip()
        if not h:
            self._crack_error.configure(text="Please enter a hash value.")
            return

        algo_display = self._algo_var.get()
        algo_key = algo_display.lower().replace("-", "")

        try:
            self._crack_stop = threading.Event()
            self._crack_queue = queue.Queue()
            engine = HashCrackEngine(
                hash_str=h,
                algorithm=algo_key,
                wordlist=self._crack_wordlist,
                result_queue=self._crack_queue,
                stop_event=self._crack_stop,
            )
        except ValueError as e:
            self._crack_error.configure(text=str(e))
            return

        self._crack_engine  = engine
        self._crack_running = True
        self._start_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._crack_result_label.configure(
            text="Cracking…", text_color=TEXT_MUTED,
            font=ctk.CTkFont(family="Segoe UI", size=15),
        )
        self._crack_status.configure(text="")
        self._crack_progress.set(0)

        threading.Thread(target=engine.run, daemon=True).start()
        self._crack_poll_id = self.after(POLL_MS, self._poll_crack)

    def _stop_crack(self):
        self._crack_stop.set()

    def _poll_crack(self):
        try:
            batch = 0
            while batch < 10:
                item: CrackResult = self._crack_queue.get_nowait()
                batch += 1
                if item.total:
                    self._crack_progress.set(item.progress / item.total)
                    self._crack_status.configure(
                        text=f"Tested {item.progress:,} / {item.total:,} words"
                    )
                if item.done:
                    self._on_crack_done(item)
                    return
        except queue.Empty:
            pass
        self._crack_poll_id = self.after(POLL_MS, self._poll_crack)

    def _on_crack_done(self, result: CrackResult):
        self._crack_running = False
        self._start_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")
        self._crack_progress.set(1 if result.found else (result.progress / result.total if result.total else 0))

        if result.found:
            self._crack_result_label.configure(
                text=f"✓  Found: {result.word}",
                text_color=CLR_FOUND,
                font=ctk.CTkFont(family="Segoe UI", size=18, weight="bold"),
            )
            self._crack_status.configure(
                text=f"Cracked after {result.progress:,} attempts."
            )
        else:
            self._crack_result_label.configure(
                text="✕  Not found in wordlist.",
                text_color=CLR_ERROR,
                font=ctk.CTkFont(family="Segoe UI", size=15),
            )
            self._crack_status.configure(
                text=f"Exhausted {result.total:,} words — no match."
            )
