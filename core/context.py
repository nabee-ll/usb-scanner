"""Application context wiring shared infrastructure together."""

from __future__ import annotations

from dataclasses import dataclass, field

from backend.database.connection import SQLiteConnectionFactory
from backend.services import ServiceContainer
from config.settings import AppSettings
from ui.animations.manager import AnimationManager
from ui.assets import AssetManager
from ui.navigation import NavigationController
from ui.router import Router
from ui.themes.manager import ThemeManager


@dataclass(slots=True)
class AppContext:
    """Composition root for UI managers and backend services."""

    settings: AppSettings
    router: Router = field(default_factory=Router)
    navigation: NavigationController = field(default_factory=NavigationController)
    animation_manager: AnimationManager = field(default_factory=AnimationManager)
    theme_manager: ThemeManager = field(init=False)
    asset_manager: AssetManager = field(init=False)
    services: ServiceContainer = field(init=False)

    def __post_init__(self) -> None:
        self.theme_manager = ThemeManager(self.settings.themes_dir)
        self.asset_manager = AssetManager(
            assets_dir=self.settings.assets_dir,
            icons_dir=self.settings.icons_dir,
        )
        self.services = ServiceContainer(
            database=SQLiteConnectionFactory(self.settings.database_path),
        )
        self.navigation.attach_router(self.router)
