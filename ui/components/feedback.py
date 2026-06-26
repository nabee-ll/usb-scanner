"""Progress, status, risk, and notification widgets."""

from __future__ import annotations

from PySide6.QtCore import QEasingCurve, Qt, QTimer, QVariantAnimation
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import (
    QFrame,
    QLabel,
    QProgressBar,
    QVBoxLayout,
    QWidget,
)

from ui.components.effects import add_glow, add_shadow


class GlassProgressBar(QProgressBar):
    """Progress bar styled for translucent glass surfaces."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("glassProgressBar")
        self.setRange(0, 100)
        self.setTextVisible(False)
        self.setMinimumHeight(14)


class StatusChip(QLabel):
    """Compact status label for device and scan states."""

    COLORS = {
        "neutral": ("rgba(99, 112, 131, 0.16)", "#637083"),
        "success": ("rgba(52, 199, 89, 0.18)", "#1f8f3d"),
        "warning": ("rgba(255, 159, 10, 0.20)", "#a96400"),
        "danger": ("rgba(255, 59, 48, 0.18)", "#c92820"),
    }

    def __init__(
        self,
        text: str,
        status: str = "neutral",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(text, parent)
        self.setObjectName("statusChip")
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setMinimumHeight(32)
        self.set_status(status)

    def set_status(self, status: str) -> None:
        background, color = self.COLORS.get(status, self.COLORS["neutral"])
        self.setStyleSheet(
            f"background: {background}; color: {color}; border-radius: 16px;"
            "padding: 0 12px; font-weight: 650;"
        )


class RiskMeter(QWidget):
    """Circular meter for low, medium, and high risk indicators."""

    def __init__(self, value: int = 0, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._value = max(0, min(100, value))
        self.setMinimumSize(128, 128)

    def set_value(self, value: int) -> None:
        self._value = max(0, min(100, value))
        self.update()

    def value(self) -> int:
        return self._value

    def paintEvent(self, event) -> None:  # noqa: ANN001
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        side = min(self.width(), self.height()) - 18
        rect_x = (self.width() - side) / 2
        rect_y = (self.height() - side) / 2

        background_pen = QPen(QColor(160, 170, 184, 70), 12)
        background_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(background_pen)
        painter.drawArc(int(rect_x), int(rect_y), side, side, 225 * 16, -270 * 16)

        color = QColor("#34c759")
        if self._value >= 70:
            color = QColor("#ff3b30")
        elif self._value >= 40:
            color = QColor("#ff9f0a")

        value_pen = QPen(color, 12)
        value_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(value_pen)
        painter.drawArc(
            int(rect_x),
            int(rect_y),
            side,
            side,
            225 * 16,
            int(-270 * 16 * (self._value / 100)),
        )

        painter.setPen(color)
        font = QFont()
        font.setPointSize(22)
        font.setWeight(QFont.Weight.Bold)
        painter.setFont(font)
        painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, f"{self._value}%")


class NotificationToast(QFrame):
    """Small floating notification with timed fade-out."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("notificationToast")
        self.setWindowOpacity(0.0)
        self.setMinimumHeight(56)
        self.message_label = QLabel("", self)
        self.message_label.setWordWrap(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 12, 18, 12)
        layout.addWidget(self.message_label)
        add_shadow(self, blur_radius=30, y_offset=12)

        self._fade = QVariantAnimation(self)
        self._fade.setDuration(360)
        self._fade.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._fade.valueChanged.connect(lambda value: self.setWindowOpacity(value))
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.hide_animated)

    def show_message(self, message: str, duration_ms: int = 2800) -> None:
        self.message_label.setText(message)
        add_glow(self)
        self.show()
        self._animate_opacity(0.0, 1.0)
        self._timer.start(duration_ms)

    def hide_animated(self) -> None:
        self._animate_opacity(self.windowOpacity(), 0.0)
        self._fade.finished.connect(self.hide)

    def _animate_opacity(self, start: float, end: float) -> None:
        try:
            self._fade.finished.disconnect(self.hide)
        except RuntimeError:
            pass
        self._fade.stop()
        self._fade.setStartValue(start)
        self._fade.setEndValue(end)
        self._fade.start()
