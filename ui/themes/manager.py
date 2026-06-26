"""QSS theme loader and applier."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import QApplication


class ThemeManager:
    """Loads QSS theme files by name."""

    def __init__(self, themes_dir: Path) -> None:
        self.themes_dir = themes_dir
        self.current_theme: str | None = None

    def load(self, name: str) -> str:
        theme_path = self.themes_dir / f"{name}.qss"
        if not theme_path.exists():
            raise FileNotFoundError(f"Theme not found: {theme_path}")
        return theme_path.read_text(encoding="utf-8")

    def apply(self, app: QApplication, name: str) -> None:
        app.setStyleSheet(self.load(name))
        self.current_theme = name
