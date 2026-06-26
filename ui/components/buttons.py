"""Liquid Glass button widgets with ripple and press feedback."""

from __future__ import annotations

from PySide6.QtCore import (
    QPoint,
    QPropertyAnimation,
    QEasingCurve,
    Signal,
    QVariantAnimation,
    Qt,
)
from PySide6.QtGui import QColor, QMouseEvent, QPainter
from PySide6.QtWidgets import QHBoxLayout, QPushButton, QSizePolicy, QWidget

from ui.components.effects import add_glow, add_shadow


class AnimatedButton(QPushButton):
    """Base button with 48px touch target, ripple, hover, and press animation."""

    object_name = "secondaryButton"
    ripple_color = QColor(255, 255, 255, 90)

    def __init__(self, text: str = "", parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self._ripple_radius = 0.0
        self._ripple_opacity = 0.0
        self._ripple_center = QPoint()
        self._ripple_animation = QVariantAnimation(self)
        self._ripple_animation.setDuration(420)
        self._ripple_animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._ripple_animation.valueChanged.connect(self._set_ripple_progress)
        self._press_animation = QPropertyAnimation(self, b"geometry", self)
        self._press_animation.setDuration(140)
        self._press_animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._hover_animation: QPropertyAnimation | None = None

        self.setObjectName(self.object_name)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(48)
        self.setSizePolicy(QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Fixed)
        add_shadow(self, blur_radius=18, y_offset=6)

    def mousePressEvent(self, event: QMouseEvent) -> None:
        self._ripple_center = event.position().toPoint()
        self._ripple_animation.stop()
        self._ripple_animation.setStartValue(0.0)
        self._ripple_animation.setEndValue(1.0)
        self._ripple_animation.start()
        self._animate_press(True)
        self.setDown(True)
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:
        self._animate_press(False)
        self.setDown(False)
        super().mouseReleaseEvent(event)

    def enterEvent(self, event) -> None:  # noqa: ANN001
        effect = add_glow(self)
        self._animate_blur(effect, 18, 32)
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:  # noqa: ANN001
        effect = add_shadow(self, blur_radius=32, y_offset=6)
        self._animate_blur(effect, 32, 18)
        super().leaveEvent(event)

    def paintEvent(self, event) -> None:  # noqa: ANN001
        super().paintEvent(event)
        if self._ripple_opacity <= 0:
            return

        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        color = QColor(self.ripple_color)
        color.setAlphaF(self._ripple_opacity)
        painter.setBrush(color)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawEllipse(
            self._ripple_center,
            int(self._ripple_radius),
            int(self._ripple_radius),
        )

    def _set_ripple_progress(self, value: float) -> None:
        max_radius = max(self.width(), self.height()) * 1.4
        self._ripple_radius = max_radius * value
        self._ripple_opacity = max(0.0, 0.42 * (1.0 - value))
        self.update()

    def _animate_press(self, pressed: bool) -> None:
        current = self.geometry()
        target = current.adjusted(2, 2, -2, -2) if pressed else current.adjusted(-2, -2, 2, 2)
        self._press_animation.stop()
        self._press_animation.setStartValue(current)
        self._press_animation.setEndValue(target)
        self._press_animation.start()

    def _animate_blur(self, effect, start: int, end: int) -> None:  # noqa: ANN001
        self._hover_animation = QPropertyAnimation(effect, b"blurRadius", self)
        self._hover_animation.setDuration(320)
        self._hover_animation.setStartValue(start)
        self._hover_animation.setEndValue(end)
        self._hover_animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._hover_animation.start()


class PrimaryButton(AnimatedButton):
    object_name = "primaryButton"


class SecondaryButton(AnimatedButton):
    object_name = "secondaryButton"
    ripple_color = QColor(47, 191, 113, 58)


class DangerButton(AnimatedButton):
    object_name = "dangerButton"


class NavigationButton(SecondaryButton):
    object_name = "navigationButton"

    def __init__(self, text: str = "", parent: QWidget | None = None) -> None:
        super().__init__(text, parent)
        self.setCheckable(True)


class BottomNavigation(QWidget):
    """Touch-friendly bottom navigation bar composed of NavigationButton items."""

    navigation_requested = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("bottomNavigation")
        self.setMinimumHeight(72)
        self._buttons: dict[str, NavigationButton] = {}
        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(12, 12, 12, 12)
        self._layout.setSpacing(8)
        add_shadow(self, blur_radius=28, y_offset=10)

    def add_button(self, route_name: str, label: str) -> NavigationButton:
        button = NavigationButton(label, self)
        button.clicked.connect(lambda: self._activate(route_name))
        self._buttons[route_name] = button
        self._layout.addWidget(button)
        return button

    def set_active(self, route_name: str) -> None:
        for name, button in self._buttons.items():
            button.setChecked(name == route_name)

    def _activate(self, route_name: str) -> None:
        self.set_active(route_name)
        self.navigation_requested.emit(route_name)
