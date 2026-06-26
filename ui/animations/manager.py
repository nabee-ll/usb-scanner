"""Reusable animation registry for Qt widgets."""

from __future__ import annotations

from PySide6.QtCore import QEasingCurve, QPropertyAnimation
from PySide6.QtWidgets import QWidget


class AnimationManager:
    """Creates and tracks widget animations so they are not garbage-collected."""

    def __init__(self) -> None:
        self._active: list[QPropertyAnimation] = []

    def fade_in(self, widget: QWidget, duration_ms: int = 180) -> QPropertyAnimation:
        animation = QPropertyAnimation(widget, b"windowOpacity", widget)
        animation.setDuration(duration_ms)
        animation.setStartValue(0.0)
        animation.setEndValue(1.0)
        animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        animation.finished.connect(lambda: self._forget(animation))
        self._active.append(animation)
        animation.start()
        return animation

    def _forget(self, animation: QPropertyAnimation) -> None:
        if animation in self._active:
            self._active.remove(animation)
