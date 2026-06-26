"""
CyberKit — Shared file-import helper.
"""

from tkinter import filedialog


def load_wordlist_file(title: str = "Select Wordlist") -> list[str]:
    """Open a file dialog and return non-empty stripped lines from the chosen file.

    Returns an empty list if the user cancels or the file is unreadable.
    """
    path = filedialog.askopenfilename(
        title=title,
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
    )
    if not path:
        return []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return [line.strip() for line in fh if line.strip()]
    except OSError:
        return []
