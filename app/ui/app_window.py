"""
CyberKit — Root Application Window
"""

import customtkinter as ctk

from app.ui.sidebar import Sidebar
from app.ui.scrollable import AutoHideScrollFrame
from app.ui.pages.home import HomePage
from app.ui.pages.fuzzer import FuzzerPage
from app.ui.pages.port_scanner import PortScannerPage
from app.ui.pages.header_analyser import HeaderAnalyserPage
from app.ui.pages.credential_tester import CredentialTesterPage
from app.ui.pages.dns_enumerator import DNSEnumeratorPage
from app.ui.pages.encoder_decoder import EncoderDecoderPage
from app.ui.pages.hash_tool import HashToolPage
from app.ui.pages.tech_fingerprinter import TechFingerprinterPage
from app.ui.pages.ssl_analyser import SslAnalyserPage
from app.ui.pages.whois_geo import WhoisGeoPage
from app.ui.pages.http_builder import HttpBuilderPage
from app.ui.pages.sqli_tester import SqliTesterPage
from app.ui.pages.xss_tester import XssTesterPage
from app.ui.pages.csrf_analyser import CsrfAnalyserPage
from app.ui.pages.open_redirect import OpenRedirectPage
from app.ui.pages.wordlist_generator import WordlistGeneratorPage
from app.ui.pages.arp_scanner import ARPScannerPage
from app.ui.pages.traceroute import TraceRoutePage
from app.ui.pages.banner_grabber import BannerGrabberPage
from app.ui.pages.packet_sniffer import PacketSnifferPage
from app.ui.pages.jwt_tool import JwtToolPage
from app.ui.pages.cipher_solver import CipherSolverPage
from app.ui.pages.email_header import EmailHeaderPage
from app.ui.pages.robots_sitemap import RobotsSitemapPage
from app.ui.pages.cve_lookup import CveLookupPage
from app.ui.pages.log_analyser import LogAnalyserPage
from app.ui.pages.file_metadata import FileMetadataPage
from app.ui.pages.hash_verifier import HashVerifierPage

# ── Theme ─────────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

BG_MAIN    = "#0f1117"
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

        # _pages  → actual page CTkFrame instances (for attribute access by other pages)
        # _scrollers → AutoHideScrollFrame wrappers (raised on navigation)
        self._pages:    dict[str, ctk.CTkFrame]          = {}
        self._scrollers: dict[str, AutoHideScrollFrame]  = {}
        self._current_page: str | None = None

        self._build_layout()
        self._register_pages()
        self.show_page("home")

    # ── Layout ────────────────────────────────────────────────────────────────

    def _build_layout(self):
        self._sidebar = Sidebar(self, navigate_callback=self.show_page)
        self._sidebar.pack(side="left", fill="y")

        self._content = ctk.CTkFrame(self, fg_color=BG_CONTENT, corner_radius=0)
        self._content.pack(side="left", fill="both", expand=True)
        self._content.grid_columnconfigure(0, weight=1)
        self._content.grid_rowconfigure(0, weight=1)

    # ── Page registration ─────────────────────────────────────────────────────

    def _add_page(self, key: str, PageClass, **kwargs) -> None:
        """Wrap a page in an AutoHideScrollFrame and stack it in the content area."""
        scroller = AutoHideScrollFrame(self._content, fg_color=BG_CONTENT)
        scroller.grid(row=0, column=0, sticky="nsew")

        page = PageClass(scroller.inner, **kwargs)
        page.pack(fill="both", expand=True)

        self._scrollers[key] = scroller
        self._pages[key]     = page

    def _register_pages(self):
        self._add_page("home",              HomePage,            navigate_callback=self.show_page)
        self._add_page("fuzzer",            FuzzerPage)
        self._add_page("port_scanner",      PortScannerPage)
        self._add_page("header_analyser",   HeaderAnalyserPage)
        self._add_page("credential_tester", CredentialTesterPage)
        self._add_page("dns_enumerator",    DNSEnumeratorPage)
        self._add_page("encoder_decoder",   EncoderDecoderPage)
        self._add_page("hash_tool",         HashToolPage)
        self._add_page("tech_fingerprinter",TechFingerprinterPage)
        self._add_page("ssl_analyser",      SslAnalyserPage)
        self._add_page("whois_geo",         WhoisGeoPage)
        self._add_page("http_builder",      HttpBuilderPage)
        self._add_page("sqli_tester",       SqliTesterPage)
        self._add_page("xss_tester",        XssTesterPage)
        self._add_page("csrf_analyser",     CsrfAnalyserPage)
        self._add_page("open_redirect",     OpenRedirectPage)
        self._add_page("wordlist_generator",WordlistGeneratorPage, navigate_callback=self.show_page)
        self._add_page("arp_scanner",       ARPScannerPage)
        self._add_page("traceroute",        TraceRoutePage)
        self._add_page("banner_grabber",    BannerGrabberPage)
        self._add_page("packet_sniffer",    PacketSnifferPage)
        self._add_page("jwt_tool",          JwtToolPage)
        self._add_page("cipher_solver",     CipherSolverPage)
        self._add_page("email_header",      EmailHeaderPage)
        self._add_page("robots_sitemap",    RobotsSitemapPage)
        self._add_page("cve_lookup",        CveLookupPage)
        self._add_page("log_analyser",      LogAnalyserPage)
        self._add_page("file_metadata",     FileMetadataPage)
        self._add_page("hash_verifier",     HashVerifierPage)

    # ── Navigation ────────────────────────────────────────────────────────────

    def show_page(self, key: str):
        if key not in self._scrollers:
            return
        if self._current_page == key:
            return
        self._scrollers[key].tkraise()
        self._scrollers[key].scroll_to_top()
        self._current_page = key
        self._sidebar.set_active_page(key)
