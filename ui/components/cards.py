"""Glass containers for application content."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QVBoxLayout, QWidget

from ui.components.effects import add_shadow


class GlassCard(QFrame):
    """Rounded translucent content panel."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("glassCard")
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setMinimumHeight(48)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(20, 20, 20, 20)
        self.layout.setSpacing(14)
        add_shadow(self, blur_radius=16, y_offset=5)
