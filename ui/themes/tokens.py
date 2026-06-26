"""Design tokens for the Liquid Glass inspired UI."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ThemeTokens:
    name: str
    background: str
    surface: str
    glass: str
    glass_border: str
    text: str
    text_muted: str
    primary: str
    primary_hover: str
    danger: str
    danger_hover: str
    success: str
    warning: str
    shadow: str
    glow: str


LIGHT_TOKENS = ThemeTokens(
    name="light",
    background="#f8f6f1",
    surface="#ffffff",
    glass="rgba(255, 255, 255, 0.34)",
    glass_border="rgba(255, 255, 255, 0.58)",
    text="#1f2320",
    text_muted="#6e6a60",
    primary="#218c5a",
    primary_hover="#1a754b",
    danger="#d14b57",
    danger_hover="#b93643",
    success="#2fbf71",
    warning="#d97706",
    shadow="rgba(31, 35, 32, 0.16)",
    glow="rgba(47, 191, 113, 0.28)",
)

DARK_TOKENS = ThemeTokens(
    name="dark",
    background="#121313",
    surface="#171615",
    glass="rgba(255, 255, 255, 0.10)",
    glass_border="rgba(255, 255, 255, 0.16)",
    text="#f4f1e8",
    text_muted="#b6b0a4",
    primary="#43d17a",
    primary_hover="#6ee391",
    danger="#ff7a86",
    danger_hover="#ff98a1",
    success="#43d17a",
    warning="#d97706",
    shadow="rgba(0, 0, 0, 0.42)",
    glow="rgba(67, 209, 122, 0.26)",
)

THEME_TOKENS = {
    LIGHT_TOKENS.name: LIGHT_TOKENS,
    DARK_TOKENS.name: DARK_TOKENS,
}
