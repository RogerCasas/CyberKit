"""
CyberKit — Robots.txt & Sitemap Parser Page
"""

import queue
import threading
from tkinter import ttk

import customtkinter as ctk

from app.modules.robots_sitemap import (
    RobotsResult, SitemapResult,
    fetch_robots, fetch_sitemap,
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

POLL_MS = 120

_STYLE_INIT = False


def _init_style():
    global _STYLE_INIT
    if _STYLE_INIT:
        return
    _STYLE_INIT = True
    style = ttk.Style()
    style.theme_use("clam")
    for name in ("Robots.Treeview", "Sitemap.Treeview"):
        style.configure(name,
                        background="#161b22", fieldbackground="#161b22",
                        foreground="#e6edf3", rowheight=24,
                        borderwidth=0, relief="flat",
                        font=("Segoe UI", 11))
        style.configure(f"{name}.Heading",
                        background="#12171e", foreground="#8b949e",
                        borderwidth=0, relief="flat",
                        font=("Segoe UI", 10, "bold"))
        style.map(name,
                  background=[("selected", "#1a2332")],
                  foreground=[("selected", "#00d4ff")])


class RobotsSitemapPage(ctk.CTkFrame):
    def __init__(self, parent, **kwargs):
        super().__init__(parent, fg_color=BG_MAIN, corner_radius=0, **kwargs)
        _init_style()
        self._q:          queue.Queue    = queue.Queue()
        self._stop_event: threading.Event = threading.Event()
        self._running     = False
        self._poll_id     = None
        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        self.grid_columnconfigure(0, weight=1)

        # Header
        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=30, pady=(28, 0))
        hdr.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            hdr, text="🤖  Robots.txt & Sitemap Parser",
            font=ctk.CTkFont(family="Segoe UI", size=26, weight="bold"),
            text_color=TEXT_PRIMARY, anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            hdr,
            text="Fetch and parse robots.txt (disallowed paths, crawl-delay) and sitemap XML files for a target domain.",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED, anchor="w", wraplength=700,
        ).grid(row=1, column=0, sticky="w", pady=(4, 0))

        # Input card
        input_card = ctk.CTkFrame(
            self, fg_color=BG_CARD, corner_radius=12,
            border_width=1, border_color=BORDER_COLOR,
        )
        input_card.grid(row=1, column=0, sticky="ew", padx=30, pady=(20, 0))
        input_card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            input_card, text="Domain / URL:",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=TEXT_MUTED,
        ).grid(row=0, column=0, padx=(16, 8), pady=14)

        self._url_entry = ctk.CTkEntry(
            input_card,
            placeholder_text="e.g. example.com  or  https://example.com",
            fg_color=BG_INPUT, border_color=BORDER_COLOR,
            text_color=TEXT_PRIMARY,
            font=ctk.CTkFont(family="Segoe UI", size=12),
            height=36,
        )
        self._url_entry.grid(row=0, column=1, sticky="ew", pady=14)
        self._url_entry.bind("<Return>", lambda _: self._start())

        self._fetch_btn = ctk.CTkButton(
            input_card, text="Fetch",
            width=90, height=36, corner_radius=8,
            fg_color=ACCENT_CYAN, hover_color="#00aacc",
            text_color=BG_MAIN, font=ctk.CTkFont(weight="bold"),
            command=self._start,
        )
        self._fetch_btn.grid(row=0, column=2, padx=(8, 8), pady=14)

        self._status_lbl = ctk.CTkLabel(
            self, text="",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_MUTED,
        )
        self._status_lbl.grid(row=2, column=0, sticky="w", padx=30, pady=(8, 0))

        # Robots card
        self._build_robots_card(row=3)

        # Sitemap card
        self._build_sitemap_card(row=4)

    def _build_robots_card(self, row: int):
        card = ctk.CTkFrame(
            self, fg_color=BG_CARD, corner_radius=12,
            border_width=1, border_color=BORDER_COLOR,
        )
        card.grid(row=row, column=0, sticky="ew", padx=30, pady=(16, 0))
        card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            card, text="robots.txt — Directives",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 6))

        self._robots_tree = ttk.Treeview(
            card, style="Robots.Treeview",
            columns=("agent", "path"), show="headings", height=7,
        )
        self._robots_tree.heading("agent", text="User-Agent")
        self._robots_tree.heading("path",  text="Disallow Path")
        self._robots_tree.column("agent", width=180, anchor="w")
        self._robots_tree.column("path",  width=450, anchor="w")
        self._robots_tree.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 6))

        ctk.CTkLabel(
            card, text="Raw robots.txt",
            font=ctk.CTkFont(family="Segoe UI", size=11, weight="bold"),
            text_color=TEXT_DIM, anchor="w",
        ).grid(row=2, column=0, sticky="w", padx=16, pady=(8, 2))
        self._robots_raw = ctk.CTkTextbox(
            card, height=120,
            fg_color=BG_INPUT, text_color=TEXT_MUTED,
            font=ctk.CTkFont(family="Consolas", size=10),
            border_width=1, border_color=BORDER_COLOR,
            corner_radius=6, state="disabled",
        )
        self._robots_raw.grid(row=3, column=0, sticky="ew", padx=16, pady=(0, 14))

    def _build_sitemap_card(self, row: int):
        card = ctk.CTkFrame(
            self, fg_color=BG_CARD, corner_radius=12,
            border_width=1, border_color=BORDER_COLOR,
        )
        card.grid(row=row, column=0, sticky="ew", padx=30, pady=(16, 30))
        card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            card, text="Sitemap URLs",
            font=ctk.CTkFont(family="Segoe UI", size=12, weight="bold"),
            text_color=TEXT_MUTED, anchor="w",
        ).grid(row=0, column=0, sticky="w", padx=16, pady=(14, 6))

        self._sitemap_count_lbl = ctk.CTkLabel(
            card, text="",
            font=ctk.CTkFont(family="Segoe UI", size=11),
            text_color=TEXT_DIM, anchor="w",
        )
        self._sitemap_count_lbl.grid(row=1, column=0, sticky="w", padx=16, pady=(0, 4))

        self._sitemap_tree = ttk.Treeview(
            card, style="Sitemap.Treeview",
            columns=("url",), show="headings", height=10,
        )
        self._sitemap_tree.heading("url", text="Page URL")
        self._sitemap_tree.column("url", width=700, anchor="w")
        self._sitemap_tree.grid(row=2, column=0, sticky="ew", padx=16, pady=(0, 14))

    # ── Fetch logic ───────────────────────────────────────────────────────────

    def _start(self):
        domain = self._url_entry.get().strip()
        if not domain or self._running:
            return

        self._running = True
        self._fetch_btn.configure(state="disabled", text="Fetching…")
        self._status_lbl.configure(text="Fetching robots.txt…", text_color=TEXT_MUTED)
        self._clear_results()
        self._stop_event.clear()

        threading.Thread(target=self._worker, args=(domain,), daemon=True).start()
        self._poll()

    def _worker(self, domain: str):
        robots = fetch_robots(domain)
        self._q.put(("robots", robots))

        if robots.error:
            self._q.put(("done", None))
            return

        # Sitemap sources: from robots.txt directives, or probe standard paths
        sitemap_sources = list(robots.sitemap_urls)
        if not sitemap_sources:
            from urllib.parse import urlparse
            parsed = urlparse(robots.url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            fallbacks = [f"{base}/sitemap.xml", f"{base}/sitemap_index.xml"]
            self._q.put(("status", "No Sitemap: directives in robots.txt — probing standard paths…"))
            for candidate in fallbacks:
                if self._stop_event.is_set():
                    break
                self._q.put(("status", f"Trying {candidate}…"))
                result = fetch_sitemap(candidate)
                if not result.error:
                    sitemap_sources = [candidate]
                    break

        all_sitemap_urls: list[str] = []
        found_any = False
        for sm_url in sitemap_sources:
            if self._stop_event.is_set():
                break
            self._q.put(("status", f"Fetching sitemap: {sm_url}"))
            result = fetch_sitemap(sm_url)
            if not result.error:
                all_sitemap_urls.extend(result.urls)
                found_any = True

        if not found_any and not self._stop_event.is_set():
            self._q.put(("no_sitemap", None))
        else:
            self._q.put(("sitemaps", all_sitemap_urls))
        self._q.put(("done", None))

    def _poll(self):
        try:
            while True:
                tag, data = self._q.get_nowait()
                if tag == "robots":
                    self._populate_robots(data)
                elif tag == "sitemaps":
                    self._populate_sitemaps(data)
                elif tag == "no_sitemap":
                    self._sitemap_count_lbl.configure(
                        text="No sitemap found — this site does not publish an XML sitemap at a standard path.",
                        text_color=TEXT_MUTED,
                    )
                elif tag == "status":
                    self._status_lbl.configure(text=data)
                elif tag == "done":
                    self._on_done()
                    return
        except queue.Empty:
            pass
        self._poll_id = self.after(POLL_MS, self._poll)

    def _on_done(self):
        self._running = False
        self._fetch_btn.configure(state="normal", text="Fetch")
        self._status_lbl.configure(text="Done.", text_color=CLR_OK)

    # ── Population ────────────────────────────────────────────────────────────

    def _clear_results(self):
        for item in self._robots_tree.get_children():
            self._robots_tree.delete(item)
        for item in self._sitemap_tree.get_children():
            self._sitemap_tree.delete(item)
        self._robots_raw.configure(state="normal")
        self._robots_raw.delete("1.0", "end")
        self._robots_raw.configure(state="disabled")
        self._sitemap_count_lbl.configure(text="")

    def _populate_robots(self, result: RobotsResult):
        if result.error:
            self._status_lbl.configure(
                text=f"Error fetching robots.txt: {result.error}",
                text_color=CLR_ERROR,
            )
            return

        self._status_lbl.configure(
            text=f"robots.txt fetched from {result.url}  •  {len(result.directives)} directives  •  {len(result.sitemap_urls)} sitemaps",
            text_color=TEXT_MUTED,
        )
        for agent, path in result.directives:
            self._robots_tree.insert("", "end", values=(agent, path or "/"))

        self._robots_raw.configure(state="normal")
        self._robots_raw.delete("1.0", "end")
        self._robots_raw.insert("1.0", result.raw_text)
        self._robots_raw.configure(state="disabled")

    def _populate_sitemaps(self, urls: list[str]):
        for item in self._sitemap_tree.get_children():
            self._sitemap_tree.delete(item)
        for url in urls:
            self._sitemap_tree.insert("", "end", values=(url,))
        count = len(urls)
        if count:
            self._sitemap_count_lbl.configure(
                text=f"{count} URL{'s' if count != 1 else ''} found across all sitemaps",
                text_color=CLR_OK,
            )
        else:
            self._sitemap_count_lbl.configure(
                text="Sitemap file found but contained no URLs.",
                text_color=TEXT_MUTED,
            )
