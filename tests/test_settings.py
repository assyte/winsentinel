"""Tests for the local-only settings store."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import settings


class SettingsTests(unittest.TestCase):
    def test_theme_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            with patch.object(settings, "settings_path", return_value=path):
                self.assertEqual(settings.load_theme("dark"), "dark")
                settings.save_theme("light")
                self.assertEqual(settings.load_theme("dark"), "light")
                self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["theme"], "light")

    def test_invalid_saved_theme_falls_back(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            path.write_text('{"theme": "neon"}', encoding="utf-8")
            with patch.object(settings, "settings_path", return_value=path):
                self.assertEqual(settings.load_theme("dark"), "dark")

    def test_invalid_theme_is_not_written(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "settings.json"
            with patch.object(settings, "settings_path", return_value=path):
                settings.save_theme("neon")
                self.assertFalse(path.exists())
