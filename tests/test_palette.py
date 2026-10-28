"""Palette integrity checks for the light and dark themes."""

from __future__ import annotations

import unittest

from core.constants import COLORS, DARK_COLORS, DNS_PROVIDER_BY_KEY, LIGHT_COLORS, THEMES


class PaletteTests(unittest.TestCase):
    def test_both_palettes_expose_the_same_tokens(self) -> None:
        self.assertEqual(set(DARK_COLORS), set(LIGHT_COLORS))

    def test_required_tokens_are_present(self) -> None:
        required = {
            "bg",
            "sidebar",
            "card",
            "border",
            "text",
            "text_muted",
            "accent",
            "accent_hover",
            "accent_soft",
            "accent_text",
            "success",
            "warning",
            "danger",
            "danger_hover",
            "danger_border",
            "info",
            "select_bg",
        }
        for name, palette in THEMES.items():
            self.assertTrue(required.issubset(palette), name)

    def test_theme_modes_are_exactly_dark_and_light(self) -> None:
        self.assertEqual(set(THEMES), {"dark", "light"})

    def test_dns_provider_accent_tracks_the_active_palette(self) -> None:
        original = COLORS["accent"]
        try:
            COLORS["accent"] = "#123456"
            self.assertEqual(DNS_PROVIDER_BY_KEY["cloudflare"].accent, "#123456")
        finally:
            COLORS["accent"] = original
