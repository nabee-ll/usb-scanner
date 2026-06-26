"""Glass containers for application content."""

from __future__ import annotations

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QLinearGradient, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QApplication, QFrame, QVBoxLayout, QWidget

from ui.components.effects import add_shadow


class GlassCard(QFrame):
    """Rounded translucent content panel with layered glass painting."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("glassCard")
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_NoSystemBackground)
        self.setAutoFillBackground(False)
        self.setMinimumHeight(48)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(20, 20, 20, 20)
        self.layout.setSpacing(14)
        add_shadow(self, color="rgba(35, 48, 70, 0.16)", blur_radius=22, y_offset=8)

    def paintEvent(self, event) -> None:  # noqa: ANN001
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = QRectF(self.rect()).adjusted(1.0, 1.0, -1.0, -1.0)
        radius = 16.0
        path = QPainterPath()
        path.addRoundedRect(rect, radius, radius)

        app = QApplication.instance()
        is_dark = app is not None and app.property("theme_name") == "dark"
        if is_dark:
            top = QColor(255, 255, 255, 36)
            bottom = QColor(255, 255, 255, 18)
            border = QColor(255, 255, 255, 42)
            inner = QColor(94, 177, 255, 24)
        else:
            top = QColor(255, 255, 255, 218)
            bottom = QColor(255, 255, 255, 132)
            border = QColor(255, 255, 255, 230)
            inner = QColor(10, 132, 255, 22)

        fill = QLinearGradient(rect.topLeft(), rect.bottomRight())
        fill.setColorAt(0.0, top)
        fill.setColorAt(0.62, bottom)
        fill.setColorAt(1.0, inner)
        painter.fillPath(path, fill)

        shine_rect = QRectF(
            rect.left() + 1,
            rect.top() + 1,
            rect.width() - 2,
            rect.height() * 0.42,
        )
        shine_path = QPainterPath()
        shine_path.addRoundedRect(shine_rect, radius - 2, radius - 2)
        shine = QLinearGradient(shine_rect.topLeft(), shine_rect.bottomLeft())
        shine.setColorAt(0.0, QColor(255, 255, 255, 72 if is_dark else 115))
        shine.setColorAt(1.0, QColor(255, 255, 255, 0))
        painter.fillPath(shine_path.intersected(path), shine)

        painter.setPen(QPen(border, 1.2))
        painter.drawPath(path)

        inset = rect.adjusted(1.5, 1.5, -1.5, -1.5)
        inset_path = QPainterPath()
        inset_path.addRoundedRect(inset, radius - 2, radius - 2)
        painter.setPen(QPen(QColor(255, 255, 255, 55 if is_dark else 120), 0.8))
        painter.drawPath(inset_path)
