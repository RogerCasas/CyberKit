"""
CyberKit — Root Application Window
"""

import customtkinter as ctk

from app.ui.sidebar import Sidebar
from app.ui.pages.home import HomePage
from app.ui.pages.fuzzer import FuzzerPage
from app.ui.pages.port_scanner import PortScannerPage
from app.ui.pages.header_analyser import HeaderAnalyserPage

# ── Theme ─────────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

BG_MAIN   = "#0f1117"
BG_CONTENT = "#0f1117"


class AppWindow(ctk.CTk):
    """Main application window. Manages sidebar + page switching."""

    MIN_W = 960
    MIN_H = 640

    def __init__(self):
        super().__init__()

        self.title("CyberKit — Cybersecurity Learning Platform")
        self.geometry("1200x760")
        self.minsize(self.MIN_W, self.MIN_H)
        self.configure(fg_color=BG_MAIN)

        self._pages: dict[str, ctk.CTkFrame] = {}
        self._current_page: str | None = None

        self._build_layout()
        self._register_pages()
        self.show_page("home")

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build_layout(self):
        # Sidebar
        self._sidebar = Sidebar(self, navigate_callback=self.show_page)
        self._sidebar.pack(side="left", fill="y")

        # Content area fills remaining space
        self._content = ctk.CTkFrame(self, fg_color=BG_CONTENT, corner_radius=0)
        self._content.pack(side="left", fill="both", expand=True)
        self._content.grid_columnconfigure(0, weight=1)
        self._content.grid_rowconfigure(0, weight=1)

    def _register_pages(self):
        """Instantiate all pages and stack them in the content area."""
        self._pages["home"]             = HomePage(self._content, navigate_callback=self.show_page)
        self._pages["fuzzer"]           = FuzzerPage(self._content)
        self._pages["port_scanner"]     = PortScannerPage(self._content)
        self._pages["header_analyser"]  = HeaderAnalyserPage(self._content)

        for page in self._pages.values():
            page.grid(row=0, column=0, sticky="nsew")

    # ── Navigation ────────────────────────────────────────────────────────────

    def show_page(self, key: str):
        if key not in self._pages:
            return
        if self._current_page == key:
            return
        self._pages[key].tkraise()
        self._current_page = key
        self._sidebar.set_active_page(key)
