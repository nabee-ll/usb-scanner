"""Responsive layout helpers for PySide6 widgets."""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtWidgets import QWidget


@dataclass(frozen=True, slots=True)
class Breakpoints:
    compact: int = 700
    medium: int = 1100


class ResponsiveMixin:
    """Mixin that maps widget width to simple layout buckets."""

    breakpoints = Breakpoints()

    def layout_mode(self: QWidget) -> str:
        width = self.width()
        if width < self.breakpoints.compact:
            return "compact"
        if width < self.breakpoints.medium:
            return "medium"
        return "expanded"

    def is_compact(self: QWidget) -> bool:
        return self.layout_mode() == "compact"
