"""Runtime settings for the USB scanner UI."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True, slots=True)
class AppSettings:
    """Central settings shared by UI and backend layers."""

    app_name: str = "USB Scanner"
    theme: str = "light"
    database_path: Path = PROJECT_ROOT / "malware_hashes.db"
    assets_dir: Path = PROJECT_ROOT / "ui" / "assets"
    icons_dir: Path = PROJECT_ROOT / "ui" / "icons"
    themes_dir: Path = PROJECT_ROOT / "ui" / "themes"
    min_width: int = 900
    min_height: int = 560
