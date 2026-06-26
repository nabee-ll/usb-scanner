"""Visual effects shared by design-system widgets."""

from __future__ import annotations

import re

from PySide6.QtGui import QColor
from PySide6.QtWidgets import QGraphicsBlurEffect, QGraphicsDropShadowEffect, QWidget


def color_from_css(value: str) -> QColor:
    rgba = re.fullmatch(
        r"rgba\((\d+),\s*(\d+),\s*(\d+),\s*([0-9.]+)\)",
        value.strip(),
    )
    if rgba:
        red, green, blue, alpha = rgba.groups()
        color = QColor(int(red), int(green), int(blue))
        color.setAlphaF(float(alpha))
        return color
    return QColor(value)


def add_shadow(
    widget: QWidget,
    color: str = "rgba(31, 35, 32, 0.16)",
    blur_radius: int = 26,
    y_offset: int = 12,
) -> QGraphicsDropShadowEffect:
    effect = QGraphicsDropShadowEffect(widget)
    effect.setBlurRadius(blur_radius)
    effect.setOffset(0, y_offset)
    effect.setColor(color_from_css(color))
    widget.setGraphicsEffect(effect)
    return effect


def add_glow(
    widget: QWidget,
    color: str = "rgba(47, 191, 113, 0.28)",
    blur_radius: int = 30,
) -> QGraphicsDropShadowEffect:
    effect = QGraphicsDropShadowEffect(widget)
    effect.setBlurRadius(blur_radius)
    effect.setOffset(0, 0)
    effect.setColor(color_from_css(color))
    widget.setGraphicsEffect(effect)
    return effect


def add_blur(widget: QWidget, radius: int = 16) -> QGraphicsBlurEffect:
    effect = QGraphicsBlurEffect(widget)
    effect.setBlurRadius(radius)
    widget.setGraphicsEffect(effect)
    return effect
