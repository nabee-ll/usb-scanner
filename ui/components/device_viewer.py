"""Animated USB device viewer used by the Scan screen."""

from __future__ import annotations

import math

from PySide6.QtCore import QRect, QTimer, Qt
from PySide6.QtGui import QColor, QLinearGradient, QPainter, QPen
from PySide6.QtWidgets import QSizePolicy, QWidget


class AnimatedDeviceViewer(QWidget):
    """Decorative animated USB device visual with scanning rings."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("animatedDeviceViewer")
        self.setMinimumHeight(150)
        self.setMaximumHeight(170)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self._phase = 0.0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(16)

    def paintEvent(self, event) -> None:  # noqa: ANN001
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = self.rect().adjusted(10, 8, -10, -8)
        center = rect.center()
        pulse = (math.sin(self._phase) + 1.0) / 2.0

        panel_gradient = QLinearGradient(rect.topLeft(), rect.bottomRight())
        panel_gradient.setColorAt(0.0, QColor(255, 255, 255, 110))
        panel_gradient.setColorAt(1.0, QColor(94, 177, 255, 72))
        painter.setPen(QPen(QColor(255, 255, 255, 135), 1))
        painter.setBrush(panel_gradient)
        painter.drawRoundedRect(rect, 22, 22)

        for index in range(2):
            radius = 36 + index * 26 + int(pulse * 8)
            alpha = max(20, 70 - index * 20)
            painter.setPen(QPen(QColor(10, 132, 255, alpha), 2))
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawEllipse(center, radius, radius)

        body_width = min(118, rect.width() // 5)
        body_height = 58
        body_x = center.x() - body_width // 2
        body_y = center.y() - body_height // 2 + 12
        body_rect = QRect(body_x, body_y, body_width, body_height)

        device_gradient = QLinearGradient(body_rect.topLeft(), body_rect.bottomRight())
        device_gradient.setColorAt(0.0, QColor(248, 252, 255, 235))
        device_gradient.setColorAt(1.0, QColor(205, 224, 246, 210))
        painter.setPen(QPen(QColor(255, 255, 255, 190), 1))
        painter.setBrush(device_gradient)
        painter.drawRoundedRect(body_rect, 16, 16)

        connector_width = body_width // 2
        connector_rect = QRect(
            center.x() - connector_width // 2,
            body_rect.top() - 24,
            connector_width,
            28,
        )
        painter.setBrush(QColor(220, 232, 244, 225))
        painter.drawRoundedRect(connector_rect, 8, 8)

        painter.setPen(QPen(QColor(10, 132, 255, 180), 4))
        scan_y = body_rect.top() + int((body_rect.height() + 18) * pulse) - 8
        painter.drawLine(body_rect.left() + 18, scan_y, body_rect.right() - 18, scan_y)

        painter.setPen(QPen(QColor(23, 32, 51, 150), 2))
        painter.drawLine(center.x(), body_rect.top() + 14, center.x(), body_rect.bottom() - 14)
        painter.drawLine(center.x(), body_rect.top() + 14, center.x() - 13, body_rect.top() + 30)
        painter.drawLine(center.x(), body_rect.top() + 14, center.x() + 13, body_rect.top() + 30)

        painter.setPen(QPen(QColor(10, 132, 255, 130), 2))
        for offset in (-70, -44, 44, 70):
            start_x = center.x() + offset
            painter.drawLine(start_x, center.y() + 54, center.x(), body_rect.bottom())

    def _tick(self) -> None:
        self._phase = (self._phase + 0.055) % (math.pi * 2)
        self.update()
