"""
Reusable auto-hiding vertical scroll frame for CyberKit.

AutoHideScrollFrame wraps any content in a canvas + scrollbar that:
  - appears only when content exceeds the visible area
  - fills full width at all times
  - fills full height when content is smaller than viewport
  - scrolls with the mousewheel while the cursor is inside it
"""

import tkinter as tk
from tkinter import ttk

import customtkinter as ctk

_STYLE_APPLIED = False


def _ensure_style():
    global _STYLE_APPLIED
    if _STYLE_APPLIED:
        return
    # Switch to "clam" so every module's ttk.Style configuration (Treeview
    # scrollbars, etc.) is applied correctly.  The Windows-default "vista"
    # theme uses native OS rendering and silently ignores all custom colours.
    # This runs before any page __init__, so all module styles land here too.
    ttk.Style().theme_use("clam")
    _STYLE_APPLIED = True


class AutoHideScrollFrame(ctk.CTkFrame):
    """
    Drop-in scrollable container.

    Place content inside `.inner` (a CTkFrame) — it is packed and
    configured automatically.  The container itself behaves like any
    CTkFrame and can be used with grid or pack.

    The scrollbar uses CTkScrollbar so it matches the rounded, minimalist
    style of CTkScrollableFrame used elsewhere in the app.
    """

    # Match the button_color / hover used by CTkScrollableFrame across the app.
    _BTN_COLOR       = "#21262d"
    _BTN_HOVER_COLOR = "#484f58"

    def __init__(self, parent, fg_color: str = "#0f1117", **kwargs):
        _ensure_style()
        super().__init__(parent, fg_color=fg_color, corner_radius=0, **kwargs)

        self._fg = fg_color
        self._wheel_registered = False
        self._destroyed = False
        self._sync_pending = False

        self._canvas = tk.Canvas(
            self, bg=fg_color, highlightthickness=0, bd=0
        )
        # CTkScrollbar gives the same pill-shaped, arrow-free look as
        # CTkScrollableFrame — the style the rest of the app uses.
        self._vsb = ctk.CTkScrollbar(
            self,
            orientation="vertical",
            command=self._canvas.yview,
            button_color=self._BTN_COLOR,
            button_hover_color=self._BTN_HOVER_COLOR,
            fg_color="transparent",
        )
        self._inner = ctk.CTkFrame(
            self._canvas, fg_color=fg_color, corner_radius=0
        )
        self._win_id = self._canvas.create_window(
            (0, 0), window=self._inner, anchor="nw"
        )

        self._canvas.configure(yscrollcommand=self._on_yscroll)
        self._canvas.pack(side="left", fill="both", expand=True)
        # scrollbar hidden until needed

        self._inner.bind("<Configure>", self._schedule_sync)
        self._canvas.bind("<Configure>", self._schedule_sync)

        # Force an initial sync once the widget is fully laid out.
        self.bind("<Map>", self._schedule_sync)

        # Register mousewheel binding on the toplevel after layout is complete.
        # _on_wheel checks cursor position so only the frame under the cursor scrolls.
        self.after_idle(self._register_wheel)

    # ── Public ────────────────────────────────────────────────────────────────

    def _update_dimensions_event(self, event) -> None:
        """Guard CTk's internal redraw against teardown-order TclErrors."""
        try:
            super()._update_dimensions_event(event)
        except tk.TclError:
            pass

    def destroy(self) -> None:
        self._destroyed = True
        try:
            self._inner.unbind("<Configure>")
            self._canvas.unbind("<Configure>")
        except Exception:
            pass
        super().destroy()

    @property
    def inner(self) -> ctk.CTkFrame:
        return self._inner

    def scroll_to_top(self) -> None:
        self._canvas.yview_moveto(0.0)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _on_yscroll(self, first: str, last: str) -> None:
        """Show/hide scrollbar depending on whether all content is visible."""
        if float(first) <= 0.0 and float(last) >= 1.0:
            self._vsb.pack_forget()
        else:
            self._vsb.pack(side="right", fill="y")
            self._vsb.set(float(first), float(last))

    def _schedule_sync(self, _event=None) -> None:
        """Coalesce rapid Configure events into a single after_idle sync."""
        if self._destroyed or self._sync_pending:
            return
        self._sync_pending = True
        self.after_idle(self._sync)

    def _sync(self) -> None:
        """Keep inner frame width = canvas width and height >= canvas height."""
        self._sync_pending = False
        if self._destroyed:
            return
        try:
            cw = self._canvas.winfo_width()
            ch = self._canvas.winfo_height()
            rh = self._inner.winfo_reqheight()
            h  = max(rh, ch) if ch > 1 else rh
            self._canvas.itemconfig(self._win_id, width=max(cw, 1), height=h)
            self._canvas.configure(scrollregion=(0, 0, 0, h))
            # Manually trigger scrollbar visibility — Tk doesn't always fire
            # yscrollcommand when only scrollregion changes.
            first, last = self._canvas.yview()
            self._on_yscroll(str(first), str(last))
        except tk.TclError:
            pass

    def _register_wheel(self) -> None:
        """Bind mousewheel to the toplevel once, using add='+' to stack handlers."""
        if self._wheel_registered:
            return
        top = self.winfo_toplevel()
        if top:
            top.bind("<MouseWheel>", self._on_wheel, add="+")
            self._wheel_registered = True

    def _on_wheel(self, event) -> None:
        """Scroll only if cursor is within our canvas and not over a Treeview."""
        if isinstance(event.widget, ttk.Treeview):
            return
        try:
            cx = self._canvas.winfo_rootx()
            cy = self._canvas.winfo_rooty()
            cw = self._canvas.winfo_width()
            ch = self._canvas.winfo_height()
            if cx <= event.x_root <= cx + cw and cy <= event.y_root <= cy + ch:
                self._canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
        except tk.TclError:
            pass
