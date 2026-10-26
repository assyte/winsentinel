"""AMOLED theme helpers and compact typography."""

from __future__ import annotations

from typing import Literal

import customtkinter as ctk

from core.constants import COLORS, FONT_DISPLAY, FONT_MONO, FONT_UI

Weight = Literal["normal", "bold"]


def ui_font(size: int = 12, weight: Weight = "normal") -> tuple[str, int, str]:
    return (FONT_UI, size, weight)


def display_font(size: int = 22, weight: Weight = "bold") -> tuple[str, int, str]:
    return (FONT_DISPLAY, size, weight)


def mono_font(size: int = 9, weight: Weight = "normal") -> tuple[str, int, str]:
    return (FONT_MONO, size, weight)


def apply_theme() -> None:
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")


def primary_button_kwargs(*, compact: bool = False) -> dict:
    return {
        "fg_color": COLORS["accent"],
        "hover_color": COLORS["accent_hover"],
        "text_color": "#032a31",
        "corner_radius": 8,
        "height": 32 if compact else 34,
        "font": ui_font(11, "bold"),
        "border_width": 0,
    }


def secondary_button_kwargs(*, compact: bool = False) -> dict:
    return {
        "fg_color": COLORS["card"],
        "hover_color": COLORS["card_hover"],
        "text_color": COLORS["text"],
        "corner_radius": 8,
        "height": 32 if compact else 34,
        "font": ui_font(10, "bold"),
        "border_width": 1,
        "border_color": COLORS["border_bright"],
    }


def ghost_button_kwargs(*, compact: bool = False) -> dict:
    return {
        "fg_color": "transparent",
        "hover_color": COLORS["card_hover"],
        "text_color": COLORS["text_muted"],
        "corner_radius": 7,
        "height": 26 if compact else 30,
        "font": ui_font(10),
        "border_width": 0,
    }


def danger_button_kwargs(*, compact: bool = False) -> dict:
    return {
        "fg_color": COLORS["danger_soft"],
        "hover_color": "#3a1111",
        "text_color": COLORS["danger"],
        "corner_radius": 8,
        "height": 32 if compact else 34,
        "font": ui_font(10, "bold"),
        "border_width": 1,
        "border_color": "#5c1a1a",
    }
