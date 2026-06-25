"""
CyberKit — Entry Point
Run with: python main.py
"""

from app.ui.app_window import AppWindow


def main():
    app = AppWindow()
    app.mainloop()


if __name__ == "__main__":
    main()
