"""
CyberKit — File Metadata Extractor Page
"""

import tkinter as tk
from tkinter import filedialog, ttk

import customtkinter as ctk

from app.modules.file_metadata import extract, MetaResult

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
CLR_SENSITIVE = "#f0a500"

_STYLE_INIT = False


def _init_style():
    global _STYLE_INIT
    if _STYLE_INIT:
        return
    _STYLE_INIT = True
    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Meta.Treeview",
                    background="#161b22", fieldbackground="#161b22",
                    foreground="#e6edf3", rowheight=26,
                    borderwidth=0, relief="flat",
                    font=("Segoe UI", 11))
    style.configure("Meta.Treeview.Heading",
                    background="#12171e", foreground="#8b949e",
                    borderwidth=0, relief="flat",
                    font=("Segoe UI", 10, "bold"))
    style.map("Meta.Treeview",
              background=[("selected", "#1a2332")],
              foreground=[("selected", "#00d4ff")])


_TYPE_COLOURS = {
    "image": "#58a6ff",
    "pdf":   "#ff6b6b",
    "docx":  "#22c55e",
    "xlsx":  "#4ade80",
    "unknown": "#484f58",
}


class FileMetadataPage(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, corner_radius=0, **kwargs)
        _init_style()
        self._file_path = ""
        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        self.grid_columnconfigure(0, weight=1)

        # Header
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=30, pady=(28, 0))
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(hdr, text="🔍  File Metadata Extractor",
                     font=("Segoe UI", 22, "bold"), text_color=TEXT_PRIMARY).grid(
                     row=0, column=0, sticky="w")
        ctk.CTkLabel(hdr, text="EXIF · PDF info · Office core properties",
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

        self._type_chip = ctk.CTkLabel(input_card, text="", width=90,
                                       font=("Segoe UI", 11, "bold"),
                                       text_color=TEXT_DIM, fg_color="transparent")
        self._type_chip.grid(row=0, column=2, padx=8)

        self._extract_btn = ctk.CTkButton(input_card, text="Extract",
                                          fg_color=ACCENT_CYAN, hover_color="#00b8d9",
                                          text_color="#0f1117", font=("Segoe UI", 12, "bold"),
                                          width=100, command=self._run)
        self._extract_btn.grid(row=0, column=3, padx=8, pady=14)

        self._clear_btn = ctk.CTkButton(input_card, text="Clear",
                                        fg_color="#21262d", hover_color="#30363d",
                                        text_color=TEXT_MUTED, font=("Segoe UI", 12),
                                        width=70, command=self._clear)
        self._clear_btn.grid(row=0, column=4, padx=(0, 14), pady=14)

        # Status
        self._status_lbl = ctk.CTkLabel(self, text="", font=("Segoe UI", 12),
                                        text_color=TEXT_MUTED, anchor="w")
        self._status_lbl.grid(row=2, column=0, sticky="ew", padx=30, pady=(10, 0))

        # Results card
        results_card = ctk.CTkFrame(self, fg_color=BG_CARD, corner_radius=10)
        results_card.grid(row=3, column=0, sticky="nsew", padx=30, pady=14)
        results_card.grid_columnconfigure(0, weight=1)
        results_card.grid_rowconfigure(1, weight=1)
        self.grid_rowconfigure(3, weight=1)

        legend = ctk.CTkFrame(results_card, fg_color="transparent")
        legend.grid(row=0, column=0, sticky="ew", padx=14, pady=(10, 0))
        ctk.CTkLabel(legend, text="● Sensitive field", font=("Segoe UI", 11),
                     text_color=CLR_SENSITIVE).pack(side="left", padx=(0, 20))
        ctk.CTkLabel(legend, text="Fields are read-only — no modifications made.",
                     font=("Segoe UI", 11), text_color=TEXT_DIM).pack(side="left")

        tree_frame = tk.Frame(results_card, bg=BG_CARD)
        tree_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=(4, 10))
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        self._tree = ttk.Treeview(tree_frame, style="Meta.Treeview",
                                  columns=("field", "value"), show="headings",
                                  height=18)
        self._tree.heading("field", text="Field")
        self._tree.heading("value", text="Value")
        self._tree.column("field", width=180, anchor="w")
        self._tree.column("value", width=600, anchor="w")
        self._tree.tag_configure("sensitive", foreground=CLR_SENSITIVE)

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")

        self._no_meta_lbl = ctk.CTkLabel(results_card,
                                         text="No metadata extractable for this file type.",
                                         font=("Segoe UI", 13), text_color=TEXT_DIM)

    # ── Interactions ──────────────────────────────────────────────────────────

    def _pick_file(self):
        path = filedialog.askopenfilename(
            title="Select a file",
            filetypes=[
                ("Images", "*.jpg *.jpeg *.png *.tiff *.tif *.webp"),
                ("PDF", "*.pdf"),
                ("Word", "*.docx"),
                ("Excel", "*.xlsx"),
                ("All files", "*.*"),
            ],
        )
        if path:
            self._file_path = path
            self._path_lbl.configure(text=path, text_color=TEXT_PRIMARY)
            self._type_chip.configure(text="")
            self._status_lbl.configure(text="")

    def _run(self):
        if not self._file_path:
            return
        self._clear_tree()
        self._no_meta_lbl.grid_forget()
        self._status_lbl.configure(text="Extracting…", text_color=TEXT_MUTED)
        self.update_idletasks()

        result = extract(self._file_path)

        colour = _TYPE_COLOURS.get(result.file_type, TEXT_DIM)
        self._type_chip.configure(text=result.file_type.upper(), text_color=colour)

        if result.error:
            self._status_lbl.configure(text=f"Error: {result.error}", text_color=CLR_ERROR)
            return

        if result.file_type == "unknown":
            self._no_meta_lbl.grid(row=2, column=0, pady=20)
            self._status_lbl.configure(text="", text_color=TEXT_MUTED)
            return

        if not result.fields:
            self._status_lbl.configure(text="No metadata found in this file.", text_color=TEXT_MUTED)
            return

        for f in result.fields:
            tag = ("sensitive",) if f.sensitive else ()
            self._tree.insert("", "end", values=(f.key, f.value), tags=tag)

        count = len(result.fields)
        sens  = sum(1 for f in result.fields if f.sensitive)
        self._status_lbl.configure(
            text=f"{count} field(s) extracted · {sens} sensitive",
            text_color=CLR_OK if not sens else CLR_SENSITIVE,
        )

    def _clear(self):
        self._clear_tree()
        self._file_path = ""
        self._path_lbl.configure(text="No file selected", text_color=TEXT_MUTED)
        self._type_chip.configure(text="")
        self._status_lbl.configure(text="")
        self._no_meta_lbl.grid_forget()

    def _clear_tree(self):
        self._tree.delete(*self._tree.get_children())
