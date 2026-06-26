"""Application bootstrap for the USB scanner desktop UI."""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from config.settings import AppSettings
from core.context import AppContext
from ui.main_window import MainWindow


def create_app(settings: AppSettings | None = None) -> tuple[QApplication, MainWindow]:
    """Create the Qt application and root window."""
    app = QApplication(sys.argv)
    context = AppContext(settings=settings or AppSettings())
    window = MainWindow(context=context)
    context.theme_manager.apply(app, context.settings.theme)
    return app, window


def main() -> int:
    app, window = create_app()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
