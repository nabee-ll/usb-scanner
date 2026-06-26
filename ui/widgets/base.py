"""Base widget class for future pages and components."""

from __future__ import annotations

from PySide6.QtWidgets import QWidget

from core.context import AppContext
from ui.responsive import ResponsiveMixin


class BaseWidget(QWidget, ResponsiveMixin):
    """Common lifecycle and context access for UI widgets."""

    def __init__(self, context: AppContext, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.context = context
        self.setup_ui()
        self.bind_events()

    def setup_ui(self) -> None:
        """Create child widgets and layouts."""

    def bind_events(self) -> None:
        """Connect signals and slots."""

    def on_enter(self) -> None:
        """Called when the widget becomes active."""

    def on_leave(self) -> None:
        """Called before the widget is replaced."""
