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
    background="#f4f7fb",
    surface="#ffffff",
    glass="rgba(255, 255, 255, 0.66)",
    glass_border="rgba(255, 255, 255, 0.86)",
    text="#172033",
    text_muted="#637083",
    primary="#0a84ff",
    primary_hover="#006ee6",
    danger="#ff3b30",
    danger_hover="#d92d24",
    success="#34c759",
    warning="#ff9f0a",
    shadow="rgba(35, 48, 70, 0.18)",
    glow="rgba(10, 132, 255, 0.34)",
)

DARK_TOKENS = ThemeTokens(
    name="dark",
    background="#101319",
    surface="#171b23",
    glass="rgba(34, 39, 50, 0.68)",
    glass_border="rgba(255, 255, 255, 0.16)",
    text="#f2f6ff",
    text_muted="#a7b1c2",
    primary="#5eb1ff",
    primary_hover="#8fc8ff",
    danger="#ff6961",
    danger_hover="#ff837d",
    success="#45d36d",
    warning="#ffb340",
    shadow="rgba(0, 0, 0, 0.42)",
    glow="rgba(94, 177, 255, 0.32)",
)

THEME_TOKENS = {
    LIGHT_TOKENS.name: LIGHT_TOKENS,
    DARK_TOKENS.name: DARK_TOKENS,
}
