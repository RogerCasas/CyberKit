"""
CyberKit — Collapsible Sidebar with category accordion
"""

import tkinter as tk
import customtkinter as ctk
from app.ui.scrollable import AutoHideScrollFrame
from app.data.categories import CATEGORIES, PAGE_TO_CATEGORY

# ── Palette ───────────────────────────────────────────────────────────────────
BG_SIDEBAR      = "#0d1117"
BG_ITEM_HOVER   = "#161b22"
BG_ITEM_ACTIVE  = "#1a2332"
BG_CAT_HEADER   = "#12171e"
ACCENT_CYAN     = "#00d4ff"
TEXT_PRIMARY    = "#e6edf3"
TEXT_MUTED      = "#8b949e"
TEXT_DIM        = "#484f58"
BORDER_COLOR    = "#21262d"

SIDEBAR_W_EXPANDED  = 210
SIDEBAR_W_COLLAPSED = 56


class Sidebar(ctk.CTkFrame):
    """
    Sidebar with two independent collapse mechanisms:

    1. Width toggle (◀/▶ button): shrinks sidebar to 56 px icon-only mode.
       All category headers are hidden; all tool items shown flat (icons only).

    2. Category accordion (click header): expand/collapse a category's tool rows.
       Active only in expanded (210 px) sidebar mode.
    """

    def __init__(self, parent, navigate_callback, **kwargs):
        super().__init__(
            parent,
            width=SIDEBAR_W_EXPANDED,
            corner_radius=0,
            fg_color=BG_SIDEBAR,
            border_width=0,
            **kwargs,
        )
        self.navigate      = navigate_callback
        self._sidebar_open = True   # width-toggle state
        self._active_page  = "home"
        self._tooltip_win: tk.Toplevel | None = None

        # Per-category accordion state (True = expanded)
        self._cat_expanded: dict[str, bool] = {cat.key: False for cat in CATEGORIES}

        # Widget refs
        self._cat_header_frames: dict[str, ctk.CTkFrame] = {}
        self._cat_arrow_labels:  dict[str, ctk.CTkLabel] = {}
        self._cat_name_labels:   dict[str, ctk.CTkLabel] = {}
        self._cat_tool_frames:   dict[str, list[ctk.CTkFrame]] = {}

        # All tool item frames keyed by page_key
        self._item_frames:   dict[str, ctk.CTkFrame] = {}
        self._icon_labels:   dict[str, ctk.CTkLabel] = {}
        self._label_widgets: dict[str, ctk.CTkLabel] = {}

        self.grid_propagate(False)
        self._build()

    # ── Build ─────────────────────────────────────────────────────────────────

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        # ── Toggle row ────────────────────────────────────────────────────────
        toggle_row = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        toggle_row.grid(row=0, column=0, sticky="ew", padx=0, pady=(8, 0))
        toggle_row.grid_columnconfigure(0, weight=1)

        self._logo_label = ctk.CTkLabel(
            toggle_row,
            text="⚡ CyberKit",
            font=ctk.CTkFont(family="Segoe UI", size=15, weight="bold"),
            text_color=ACCENT_CYAN,
            anchor="w",
        )
        self._logo_label.grid(row=0, column=0, sticky="w", padx=(14, 0))

        self._toggle_btn = ctk.CTkButton(
            toggle_row,
            text="◀",
            width=30, height=30, corner_radius=6,
            fg_color="transparent", hover_color=BG_ITEM_HOVER,
            text_color=TEXT_MUTED, font=ctk.CTkFont(size=11),
            command=self.toggle,
        )
        self._toggle_btn.grid(row=0, column=1, padx=(0, 8))

        # ── Separator ─────────────────────────────────────────────────────────
        ctk.CTkFrame(self, height=1, fg_color=BORDER_COLOR,
                     corner_radius=0).grid(row=1, column=0, sticky="ew",
                                           padx=8, pady=(6, 4))

        # ── Section label ─────────────────────────────────────────────────────
        self._section_label = ctk.CTkLabel(
            self, text="MODULES",
            font=ctk.CTkFont(family="Segoe UI", size=9, weight="bold"),
            text_color=TEXT_MUTED, anchor="w",
        )
        self._section_label.grid(row=2, column=0, sticky="w", padx=16, pady=(2, 4))

        # ── Scrollable nav area ───────────────────────────────────────────────
        self._nav_scroll = AutoHideScrollFrame(
            self, fg_color=BG_SIDEBAR,
            scrollbar_button_color="#3d4451",
            scrollbar_button_hover_color="#8b949e",
        )
        self._nav_scroll.grid(row=3, column=0, sticky="nsew")
        nav = self._nav_scroll.inner
        nav.grid_columnconfigure(0, weight=1)

        row = 0

        # Home — always visible, outside categories
        self._home_frame = self._make_tool_item(nav, "Home", "⌂", "home", row)
        row += 1

        # Category groups
        for cat in CATEGORIES:
            # Header row
            header = ctk.CTkFrame(nav, fg_color=BG_CAT_HEADER, corner_radius=6,
                                  cursor="hand2")
            header.grid(row=row, column=0, sticky="ew", padx=6, pady=(6, 1))
            header.grid_columnconfigure(0, weight=1)
            row += 1

            name_lbl = ctk.CTkLabel(
                header,
                text=cat.label.upper(),
                font=ctk.CTkFont(family="Segoe UI", size=9, weight="bold"),
                text_color=TEXT_DIM,
                anchor="w",
            )
            name_lbl.grid(row=0, column=0, sticky="w", padx=(10, 0), pady=5)

            arrow_lbl = ctk.CTkLabel(
                header,
                text="▶",
                font=ctk.CTkFont(size=9),
                text_color=TEXT_DIM,
                width=20,
            )
            arrow_lbl.grid(row=0, column=1, padx=(0, 8), pady=5)

            self._cat_header_frames[cat.key] = header
            self._cat_name_labels[cat.key]   = name_lbl
            self._cat_arrow_labels[cat.key]  = arrow_lbl

            for w in (header, name_lbl, arrow_lbl):
                w.bind("<Button-1>", lambda e, k=cat.key: self._toggle_category(k))
                w.bind("<Enter>",    lambda e, h=header: h.configure(fg_color=BG_ITEM_HOVER))
                w.bind("<Leave>",    lambda e, h=header: h.configure(fg_color=BG_CAT_HEADER))

            # Tool items for this category (start hidden — accordion collapsed)
            tool_frames = []
            for tool in cat.tools:
                f = self._make_tool_item(nav, tool.label, tool.icon, tool.page_key, row)
                f.grid_remove()   # collapsed by default
                tool_frames.append(f)
                row += 1

            self._cat_tool_frames[cat.key] = tool_frames

        # ── Version label ─────────────────────────────────────────────────────
        self._version_label = ctk.CTkLabel(
            self, text="v4.0.0",
            font=ctk.CTkFont(family="Segoe UI", size=10),
            text_color=TEXT_MUTED,
        )
        self._version_label.grid(row=4, column=0, pady=(4, 12))

        self._set_active("home")

    # ── Tooltip (collapsed mode only) ────────────────────────────────────────

    def _show_tooltip(self, widget: tk.Widget, text: str) -> None:
        if self._sidebar_open:
            return
        self._hide_tooltip()
        try:
            x = widget.winfo_rootx() + widget.winfo_width() + 6
            y = widget.winfo_rooty() + widget.winfo_height() // 2
        except tk.TclError:
            return

        win = tk.Toplevel(self)
        win.wm_overrideredirect(True)
        win.wm_attributes("-topmost", True)
        win.configure(bg="#21262d")

        lbl = tk.Label(
            win, text=text,
            bg="#21262d", fg="#e6edf3",
            font=("Segoe UI", 11),
            padx=10, pady=5,
        )
        lbl.pack()
        win.update_idletasks()
        win.wm_geometry(f"+{x}+{y - win.winfo_height() // 2}")
        self._tooltip_win = win

    def _hide_tooltip(self) -> None:
        if self._tooltip_win is not None:
            try:
                self._tooltip_win.destroy()
            except tk.TclError:
                pass
            self._tooltip_win = None

    def _make_tool_item(self, nav, label: str, icon: str, key: str,
                        row: int) -> ctk.CTkFrame:
        frame = ctk.CTkFrame(nav, fg_color="transparent",
                             corner_radius=8, cursor="hand2")
        frame.grid(row=row, column=0, sticky="ew", padx=6, pady=2)
        frame.grid_columnconfigure(1, weight=1)

        icon_lbl = ctk.CTkLabel(
            frame, text=icon, width=28,
            font=ctk.CTkFont(size=15),
            text_color=TEXT_MUTED, anchor="center",
        )
        icon_lbl.grid(row=0, column=0, padx=(8, 0), pady=8)

        text_lbl = ctk.CTkLabel(
            frame, text=label,
            font=ctk.CTkFont(family="Segoe UI", size=13),
            text_color=TEXT_MUTED, anchor="w",
        )
        text_lbl.grid(row=0, column=1, sticky="w", padx=(8, 8))

        self._item_frames[key]   = frame
        self._icon_labels[key]   = icon_lbl
        self._label_widgets[key] = text_lbl

        for w in (frame, icon_lbl, text_lbl):
            w.bind("<Button-1>", lambda e, k=key: self._on_click(k))
            w.bind("<Enter>",    lambda e, f=frame, k=key, lbl=label: (
                self._on_hover(f, k, True),
                self._show_tooltip(f, lbl),
            ))
            w.bind("<Leave>",    lambda e, f=frame, k=key: (
                self._on_hover(f, k, False),
                self._hide_tooltip(),
            ))

        return frame

    # ── Category accordion ────────────────────────────────────────────────────

    def _toggle_category(self, cat_key: str):
        """Toggle one category open/closed (accordion, sidebar must be open)."""
        if not self._sidebar_open:
            return
        new_state = not self._cat_expanded[cat_key]
        self._cat_expanded[cat_key] = new_state
        self._apply_accordion(cat_key)

    def expand_category(self, cat_key: str):
        """Expand the named category and collapse all others."""
        if not self._sidebar_open:
            # Remember state for when sidebar re-opens
            for k in self._cat_expanded:
                self._cat_expanded[k] = (k == cat_key)
            return
        for k in self._cat_expanded:
            self._cat_expanded[k] = (k == cat_key)
            self._apply_accordion(k)

    def _apply_accordion(self, cat_key: str):
        """Show or hide tool frames and update arrow for one category."""
        expanded = self._cat_expanded[cat_key]
        arrow = "▼" if expanded else "▶"
        self._cat_arrow_labels[cat_key].configure(text=arrow)
        for frame in self._cat_tool_frames[cat_key]:
            if expanded:
                frame.grid()
            else:
                frame.grid_remove()
        # grid/grid_remove don't always fire <Configure> on the inner frame,
        # so force the scroll frame to re-measure and show/hide the scrollbar.
        self._nav_scroll._schedule_sync()

    # ── Interaction ───────────────────────────────────────────────────────────

    def _on_click(self, key: str):
        self._set_active(key)
        self.navigate(key)

    def _on_hover(self, frame: ctk.CTkFrame, key: str, entering: bool):
        if key == self._active_page:
            return
        frame.configure(fg_color=BG_ITEM_HOVER if entering else "transparent")

    def _set_active(self, key: str):
        if self._active_page in self._item_frames:
            self._item_frames[self._active_page].configure(fg_color="transparent")
            self._label_widgets[self._active_page].configure(text_color=TEXT_MUTED)
            self._icon_labels[self._active_page].configure(text_color=TEXT_MUTED)
        self._active_page = key
        if key in self._item_frames:
            self._item_frames[key].configure(fg_color=BG_ITEM_ACTIVE)
            self._label_widgets[key].configure(text_color=ACCENT_CYAN)
            self._icon_labels[key].configure(text_color=ACCENT_CYAN)
        # Auto-expand the category containing this tool (without collapsing others).
        # Collapse all categories only when navigating to Home.
        if key in PAGE_TO_CATEGORY:
            cat_key = PAGE_TO_CATEGORY[key]
            if not self._cat_expanded[cat_key]:
                self._cat_expanded[cat_key] = True
                if self._sidebar_open:
                    self._apply_accordion(cat_key)
        elif key == "home":
            for k in list(self._cat_expanded):
                self._cat_expanded[k] = False
                if self._sidebar_open:
                    self._apply_accordion(k)
            if self._sidebar_open:
                self._nav_scroll._schedule_sync()

    # ── Width toggle ──────────────────────────────────────────────────────────

    def toggle(self):
        self._sidebar_open = not self._sidebar_open
        if self._sidebar_open:
            self._open_sidebar()
        else:
            self._close_sidebar()
        self.winfo_toplevel().update_idletasks()

    def _open_sidebar(self):
        """Restore full 210 px sidebar with accordion categories."""
        self._hide_tooltip()
        self._logo_label.configure(text="⚡ CyberKit")
        self._section_label.configure(text="MODULES")
        self._version_label.configure(text="v4.0.0")
        self._toggle_btn.configure(text="◀")
        self.configure(width=SIDEBAR_W_EXPANDED)

        # Show category headers
        for cat in CATEGORIES:
            self._cat_header_frames[cat.key].grid()
            self._cat_name_labels[cat.key].configure(text=cat.label.upper())

        # Restore text labels for all tool items
        for key, lbl in self._label_widgets.items():
            # Find label text from categories or Home
            if key == "home":
                lbl.configure(text="Home")
            else:
                for cat in CATEGORIES:
                    for tool in cat.tools:
                        if tool.page_key == key:
                            lbl.configure(text=tool.label)

        # Restore accordion state (hide tools in collapsed categories)
        for cat in CATEGORIES:
            for frame in self._cat_tool_frames[cat.key]:
                if self._cat_expanded[cat.key]:
                    frame.grid()
                else:
                    frame.grid_remove()
        self._nav_scroll._schedule_sync()

    def _close_sidebar(self):
        """Shrink to 56 px icon-only mode: hide headers, show all tools flat."""
        self._logo_label.configure(text="")
        self._section_label.configure(text="")
        self._version_label.configure(text="")
        self._toggle_btn.configure(text="▶")
        self.configure(width=SIDEBAR_W_COLLAPSED)

        # Hide all category headers
        for header in self._cat_header_frames.values():
            header.grid_remove()

        # Show all tool items (flat) and hide their text labels
        for key, frame in self._item_frames.items():
            frame.grid()
            self._label_widgets[key].configure(text="")

    # ── Public ────────────────────────────────────────────────────────────────

    def set_active_page(self, key: str):
        self._set_active(key)
