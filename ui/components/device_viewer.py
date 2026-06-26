"""Animated glass banner used by the Scan screen."""

from __future__ import annotations

import math

from PySide6.QtCore import QTimer
from PySide6.QtGui import QColor, QLinearGradient, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QSizePolicy, QWidget


class AnimatedDeviceViewer(QWidget):
    """Minimal animated glass surface without scan symbols."""

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
        pulse = (math.sin(self._phase) + 1.0) / 2.0

        panel_gradient = QLinearGradient(rect.topLeft(), rect.bottomRight())
        panel_gradient.setColorAt(0.0, QColor(255, 255, 255, 178))
        panel_gradient.setColorAt(0.45, QColor(224, 240, 255, 106))
        panel_gradient.setColorAt(1.0, QColor(94, 177, 255, 92))
        painter.setPen(QPen(QColor(255, 255, 255, 210), 1.4))
        painter.setBrush(panel_gradient)
        painter.drawRoundedRect(rect, 22, 22)

        glass_path = QPainterPath()
        glass_path.addRoundedRect(rect, 22, 22)
        painter.setClipPath(glass_path)

        shimmer_x = rect.left() - rect.width() * 0.25 + rect.width() * 1.5 * pulse
        shimmer = QLinearGradient(shimmer_x - 90, rect.top(), shimmer_x + 90, rect.bottom())
        shimmer.setColorAt(0.0, QColor(255, 255, 255, 0))
        shimmer.setColorAt(0.5, QColor(255, 255, 255, 92))
        shimmer.setColorAt(1.0, QColor(255, 255, 255, 0))
        painter.fillRect(rect, shimmer)

        painter.setPen(QPen(QColor(10, 132, 255, 48), 2))
        wave_y = rect.center().y() + int(math.sin(self._phase * 1.4) * 14)
        painter.drawLine(rect.left() + 36, wave_y, rect.right() - 36, wave_y)

        painter.setClipping(False)
        painter.setPen(QPen(QColor(255, 255, 255, 120), 1))
        painter.drawRoundedRect(rect.adjusted(2, 2, -2, -2), 20, 20)

    def _tick(self) -> None:
        self._phase = (self._phase + 0.055) % (math.pi * 2)
        self.update()
