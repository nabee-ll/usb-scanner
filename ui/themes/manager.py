"""QSS theme loader and applier."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QEasingCurve, QVariantAnimation
from PySide6.QtWidgets import QApplication

from ui.themes.tokens import THEME_TOKENS, ThemeTokens


class ThemeManager:
    """Loads QSS theme files by name and exposes theme tokens."""

    def __init__(self, themes_dir: Path) -> None:
        self.themes_dir = themes_dir
        self.current_theme: str | None = None
        self.tokens: ThemeTokens = THEME_TOKENS["light"]
        self._transition: QVariantAnimation | None = None

    def load(self, name: str) -> str:
        theme_path = self.themes_dir / f"{name}.qss"
        if not theme_path.exists():
            raise FileNotFoundError(f"Theme not found: {theme_path}")
        return theme_path.read_text(encoding="utf-8")

    def apply(self, app: QApplication, name: str) -> None:
        app.setStyleSheet(self.load(name))
        self.current_theme = name
        self.tokens = THEME_TOKENS.get(name, THEME_TOKENS["light"])

    def toggle(self, app: QApplication) -> str:
        next_theme = "dark" if self.current_theme != "dark" else "light"
        self.apply(app, next_theme)
        return next_theme

    def apply_with_transition(
        self,
        app: QApplication,
        name: str,
        duration_ms: int = 420,
    ) -> QVariantAnimation:
        self.apply(app, name)
        window = app.activeWindow()
        self._transition = QVariantAnimation()
        self._transition.setDuration(duration_ms)
        self._transition.setStartValue(0.92)
        self._transition.setEndValue(1.0)
        self._transition.setEasingCurve(QEasingCurve.Type.OutCubic)
        if window is not None:
            window.setWindowOpacity(0.92)
            self._transition.valueChanged.connect(window.setWindowOpacity)
        self._transition.start()
        return self._transition
