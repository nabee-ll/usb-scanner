"""Dependency container for backend services."""

from __future__ import annotations

from dataclasses import dataclass

from backend.database.connection import SQLiteConnectionFactory


@dataclass(slots=True)
class ServiceContainer:
    """Holds backend dependencies while keeping UI code backend-agnostic."""

    database: SQLiteConnectionFactory
