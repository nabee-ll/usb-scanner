"""Root window shell for future screens."""

from __future__ import annotations

from PySide6.QtWidgets import QMainWindow, QStackedWidget

from core.context import AppContext
from ui.pages import DashboardPage, ScanPage


class MainWindow(QMainWindow):
    """Hosts the route stack without defining any screens."""

    def __init__(self, context: AppContext) -> None:
        super().__init__()
        self.context = context
        self.stack = QStackedWidget(self)

        self.setWindowTitle(context.settings.app_name)
        self.setMinimumSize(context.settings.min_width, context.settings.min_height)
        self.setCentralWidget(self.stack)
        context.router.attach_stack(self.stack)
        context.router.register("dashboard", lambda: DashboardPage(context))
        context.router.register("scan", lambda: ScanPage(context))
        context.router.navigate("scan")
