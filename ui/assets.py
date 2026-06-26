"""Asset path resolver for images, icons, and static UI files."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtGui import QIcon, QPixmap


class AssetManager:
    """Resolves assets from dedicated UI folders."""

    def __init__(self, assets_dir: Path, icons_dir: Path) -> None:
        self.assets_dir = assets_dir
        self.icons_dir = icons_dir

    def asset_path(self, name: str) -> Path:
        return self.assets_dir / name

    def icon_path(self, name: str) -> Path:
        return self.icons_dir / name

    def icon(self, name: str) -> QIcon:
        return QIcon(str(self.icon_path(name)))

    def pixmap(self, name: str) -> QPixmap:
        return QPixmap(str(self.asset_path(name)))
