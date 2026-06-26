"""Navigation facade used by UI widgets."""

from __future__ import annotations

from typing import Any

from ui.router import Router


class NavigationController:
    """Small facade over routing to keep widgets decoupled from stack details."""

    def __init__(self) -> None:
        self._router: Router | None = None

    def attach_router(self, router: Router) -> None:
        self._router = router

    def go_to(self, route_name: str, **params: Any) -> None:
        if self._router is None:
            raise RuntimeError("NavigationController has no router attached.")
        self._router.navigate(route_name, **params)

    def go_back(self) -> None:
        if self._router is None:
            raise RuntimeError("NavigationController has no router attached.")
        self._router.back()
