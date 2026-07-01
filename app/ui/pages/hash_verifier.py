"""
CyberKit — Hash Verifier Page
"""

import queue
import threading
from tkinter import filedialog

import customtkinter as ctk

from app.modules.hash_verifier import compute, verify, HashResult

# ── Palette ───────────────────────────────────────────────────────────────────
BG_MAIN      = "#0f1117"
BG_CARD      = "#161b22"
ACCENT_CYAN  = "#00d4ff"
TEXT_PRIMARY = "#e6edf3"
TEXT_MUTED   = "#8b949e"
TEXT_DIM     = "#484f58"
BORDER_COLOR = "#21262d"
CLR_OK       = "#22c55e"
CLR_ERROR    = "#ef4444"

POLL_MS = 120


class HashVerifierPage(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, corner_radius=0, **kwargs)
        self._q          = queue.Queue()
        self._stop_event = threading.Event()
        self._running    = False
        self._poll_id    = None
        self._file_path  = ""
        self._result: HashResult | None = None
        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        self.grid_columnconfigure(0, weight=1)

        # Header
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=30, pady=(28, 0))
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(hdr, text="✅  Hash Verifier",
                     font=("Segoe UI", 22, "bold"), text_color=TEXT_PRIMARY).grid(
                     row=0, column=0, sticky="w")
        ctk.CTkLabel(hdr, text="Compute MD5 · SHA-1 · SHA-256 · SHA-512 and verify file integrity",
                     font=("Segoe UI", 13), text_color=TEXT_MUTED).grid(
                     row=1, column=0, sticky="w", pady=(2, 0))

        # Input card
        input_card = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=10)
        input_card.grid(row=1, column=0, sticky="ew", padx=30, pady=(18, 0))
        input_card.grid_columnconfigure(1, weight=1)

        ctk.CTkButton(input_card, text="📂  Open File", width=140,
                      fg_color="#21262d", hover_color="#30363d",
                      text_color=TEXT_PRIMARY, font=("Segoe UI", 12),
                      command=self._pick_file).grid(
                      row=0, column=0, padx=(14, 8), pady=14)

        self._path_lbl = ctk.CTkLabel(input_card, text="No file selected",
                                      font=("Segoe UI", 12), text_color=TEXT_MUTED,
                                      anchor="w")
        self._path_lbl.grid(row=0, column=1, sticky="ew", padx=4)

        self._compute_btn = ctk.CTkButton(input_card, text="Compute",
                                          fg_color=ACCENT_CYAN, hover_color="#00b8d9",
                                          text_color="#0f1117", font=("Segoe UI", 12, "bold"),
                                          width=100, command=self._start)
        self._compute_btn.grid(row=0, column=2, padx=8, pady=14)

        self._stop_btn = ctk.CTkButton(input_card, text="Stop",
                                       fg_color="#21262d", hover_color="#30363d",
                                       text_color=CLR_ERROR, font=("Segoe UI", 12),
                                       width=70, command=self._stop, state="disabled")
        self._stop_btn.grid(row=0, column=3, padx=(0, 14), pady=14)

        # Progress
        self._progress_lbl = ctk.CTkLabel(self, text="", font=("Segoe UI", 12),
                                          text_color=TEXT_MUTED, anchor="w")
        self._progress_lbl.grid(row=2, column=0, sticky="ew", padx=30, pady=(10, 0))

        # Hash results card
        hash_card = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=10)
        hash_card.grid(row=3, column=0, sticky="ew", padx=30, pady=(14, 0))
        hash_card.grid_columnconfigure(1, weight=1)

        self._hash_entries: dict[str, ctk.CTkEntry] = {}
        for i, (algo, key) in enumerate([("MD5", "md5"), ("SHA-1", "sha1"),
                                          ("SHA-256", "sha256"), ("SHA-512", "sha512")]):
            ctk.CTkLabel(hash_card, text=algo, width=80, font=("Segoe UI", 12, "bold"),
                         text_color=TEXT_MUTED, anchor="e").grid(
                         row=i, column=0, padx=(14, 8), pady=6)
            entry = ctk.CTkEntry(hash_card, font=("Courier New", 11),
                                 fg_color="#0d1117", text_color=TEXT_PRIMARY,
                                 border_color=BORDER_COLOR, state="readonly",
                                 placeholder_text="—")
            entry.grid(row=i, column=1, sticky="ew", padx=(0, 14), pady=6)
            self._hash_entries[key] = entry

        # Verify card
        verify_card = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=10)
        verify_card.grid(row=4, column=0, sticky="ew", padx=30, pady=(14, 0))
        verify_card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(verify_card, text="Expected hash:",
                     font=("Segoe UI", 12), text_color=TEXT_MUTED).grid(
                     row=0, column=0, padx=(14, 8), pady=14)

        self._expected_entry = ctk.CTkEntry(verify_card, font=("Courier New", 11),
                                            fg_color="#0d1117", text_color=TEXT_PRIMARY,
                                            border_color=BORDER_COLOR,
                                            placeholder_text="Paste MD5 / SHA-1 / SHA-256 / SHA-512 here")
        self._expected_entry.grid(row=0, column=1, sticky="ew", padx=4, pady=14)

        ctk.CTkButton(verify_card, text="Verify", width=90,
                      fg_color="#21262d", hover_color="#30363d",
                      text_color=ACCENT_CYAN, font=("Segoe UI", 12, "bold"),
                      command=self._verify).grid(row=0, column=2, padx=(4, 14), pady=14)

        self._verify_lbl = ctk.CTkLabel(self, text="", font=("Segoe UI", 18, "bold"),
                                        text_color=TEXT_DIM)
        self._verify_lbl.grid(row=5, column=0, pady=20)

    # ── Interactions ──────────────────────────────────────────────────────────

    def _pick_file(self):
        path = filedialog.askopenfilename(title="Select a file to hash",
                                          filetypes=[("All files", "*.*")])
        if path:
            self._file_path = path
            self._path_lbl.configure(text=path, text_color=TEXT_PRIMARY)
            self._clear_hashes()
            self._verify_lbl.configure(text="")

    def _start(self):
        if self._running or not self._file_path:
            return
        self._clear_hashes()
        self._verify_lbl.configure(text="")
        self._running = True
        self._stop_event.clear()
        self._result = None
        self._compute_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._progress_lbl.configure(text="Hashing… 0 MB / — MB", text_color=TEXT_MUTED)
        threading.Thread(target=self._worker, daemon=True).start()
        self._poll_id = self.after(POLL_MS, self._poll)

    def _stop(self):
        self._stop_event.set()

    def _worker(self):
        def on_progress(done: int, total: int):
            done_mb  = done  / (1024 * 1024)
            total_mb = total / (1024 * 1024)
            self._q.put(("progress", (done_mb, total_mb)))

        result = compute(self._file_path, self._stop_event, on_progress)
        self._q.put(("done", result))

    def _poll(self):
        try:
            while True:
                tag, data = self._q.get_nowait()
                if tag == "progress":
                    done_mb, total_mb = data
                    self._progress_lbl.configure(
                        text=f"Hashing… {done_mb:.1f} MB / {total_mb:.1f} MB")
                elif tag == "done":
                    self._populate(data)
                    self._running = False
                    self._compute_btn.configure(state="normal")
                    self._stop_btn.configure(state="disabled")
                    return
        except queue.Empty:
            pass
        if self._running:
            self._poll_id = self.after(POLL_MS, self._poll)

    def _populate(self, result: HashResult):
        self._result = result
        if result.error:
            self._progress_lbl.configure(text=f"Error: {result.error}", text_color=CLR_ERROR)
            return
        self._progress_lbl.configure(text="Hashing complete.", text_color=CLR_OK)
        for key, entry in self._hash_entries.items():
            val = getattr(result, key)
            entry.configure(state="normal")
            entry.delete(0, "end")
            entry.insert(0, val)
            entry.configure(state="readonly")

    def _verify(self):
        if not self._result or self._result.error:
            return
        expected = self._expected_entry.get().strip()
        if not expected:
            return
        v = verify(self._result, expected)
        if v.match:
            self._verify_lbl.configure(
                text=f"✓  MATCH  ({v.matched_algorithm})", text_color=CLR_OK)
        else:
            self._verify_lbl.configure(text="✗  NO MATCH", text_color=CLR_ERROR)

    def _clear_hashes(self):
        for entry in self._hash_entries.values():
            entry.configure(state="normal")
            entry.delete(0, "end")
            entry.configure(state="readonly")
