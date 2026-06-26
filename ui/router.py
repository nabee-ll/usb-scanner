"""Route registry and QStackedWidget navigation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from PySide6.QtWidgets import QStackedWidget, QWidget


WidgetFactory = Callable[..., QWidget]


@dataclass(frozen=True, slots=True)
class Route:
    name: str
    factory: WidgetFactory


class Router:
    """Central route registry for page widgets."""

    def __init__(self) -> None:
        self._routes: dict[str, Route] = {}
        self._stack: QStackedWidget | None = None
        self._history: list[str] = []

    def attach_stack(self, stack: QStackedWidget) -> None:
        self._stack = stack

    def register(self, name: str, factory: WidgetFactory) -> None:
        self._routes[name] = Route(name=name, factory=factory)

    def navigate(self, name: str, **params: Any) -> QWidget:
        if self._stack is None:
            raise RuntimeError("Router has no QStackedWidget attached.")
        if name not in self._routes:
            raise KeyError(f"Unknown route: {name}")

        widget = self._routes[name].factory(**params)
        widget.setProperty("route_name", name)
        self._stack.addWidget(widget)
        self._stack.setCurrentWidget(widget)
        self._history.append(name)
        return widget

    def back(self) -> None:
        if self._stack is None or len(self._history) <= 1:
            return

        self._history.pop()
        previous_name = self._history[-1]
        for index in range(self._stack.count() - 1, -1, -1):
            widget = self._stack.widget(index)
            if widget.property("route_name") == previous_name:
                self._stack.setCurrentWidget(widget)
                return
