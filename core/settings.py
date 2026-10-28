"""Small, local-only user preferences for WinSentinel."""

from __future__ import annotations

import json
import os
from pathlib import Path

from core.constants import APP_DATA_DIRNAME

VALID_THEMES = ("dark", "light")


def settings_path() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    if base:
        return Path(base) / APP_DATA_DIRNAME / "settings.json"
    return Path.home() / f".{APP_DATA_DIRNAME.lower()}" / "settings.json"


def _read_settings() -> dict:
    path = settings_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, TypeError):
        return {}


def load_theme(default: str = "dark") -> str:
    value = str(_read_settings().get("theme") or default).lower()
    return value if value in VALID_THEMES else default


def save_theme(mode: str) -> None:
    if mode not in VALID_THEMES:
        return
    path = settings_path()
    data = _read_settings()
    data["theme"] = mode
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_suffix(".tmp")
        temp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        temp.replace(path)
    except OSError:
        # A read-only profile should never prevent a theme change in the UI.
        pass
