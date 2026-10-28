"""Small Windows API helpers with safe fallbacks for development."""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from pathlib import Path
from typing import Any


def is_windows() -> bool:
    return os.name == "nt"


def is_admin() -> bool:
    """Return True when the current process is elevated."""

    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def windows_build() -> int:
    if not is_windows():
        return 0
    try:
        return int(sys.getwindowsversion().build)
    except Exception:
        return 0


def set_dpi_awareness() -> None:
    if not is_windows():
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)  # per-monitor aware
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def apply_dark_titlebar(window: Any, dark: bool = True) -> None:
    """Ask DWM to render the native title bar in the requested mode."""

    if not is_windows():
        return
    try:
        window.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(window.winfo_id())
        if not hwnd:
            hwnd = window.winfo_id()
        enabled = ctypes.c_int(1 if dark else 0)
        for attribute in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE variants
            result = ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd,
                attribute,
                ctypes.byref(enabled),
                ctypes.sizeof(enabled),
            )
            if result == 0:
                break
    except Exception:
        pass


def asset_path(filename: str) -> Path:
    """Resolve a bundled asset in both source and PyInstaller builds."""

    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    return base / "assets" / filename


def center_window(window: Any, width: int, height: int) -> None:
    window.update_idletasks()
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    x = max(0, (screen_width - width) // 2)
    y = max(0, (screen_height - height) // 2 - 18)
    window.geometry(f"{width}x{height}+{x}+{y}")


def _python_gui_executable() -> str:
    """Prefer pythonw.exe when relaunching a script to avoid a console flash."""

    executable = Path(sys.executable)
    if not getattr(sys, "frozen", False) and executable.name.lower() == "python.exe":
        pythonw = executable.with_name("pythonw.exe")
        if pythonw.exists():
            return str(pythonw)
    return str(executable)


def relaunch_as_admin() -> bool:
    """Request UAC elevation. Returns True if the elevated process was launched."""

    if not is_windows():
        return False

    if getattr(sys, "frozen", False):
        executable = sys.executable
        arguments = sys.argv[1:]
    else:
        executable = _python_gui_executable()
        script = os.path.abspath(sys.argv[0])
        arguments = [script, *sys.argv[1:]]

    parameters = subprocess.list2cmdline(arguments)
    working_dir = os.getcwd()

    try:
        result = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            executable,
            parameters,
            working_dir,
            1,  # SW_SHOWNORMAL
        )
        return int(result) > 32
    except Exception:
        return False


def show_native_error(title: str, message: str, warning: bool = True) -> None:
    if not is_windows():
        print(f"{title}: {message}", file=sys.stderr)
        return
    flags = 0x00000030 if warning else 0x00000010  # MB_ICONWARNING / MB_ICONERROR
    try:
        ctypes.windll.user32.MessageBoxW(None, message, title, flags)
    except Exception:
        print(f"{title}: {message}", file=sys.stderr)


def open_url(url: str) -> bool:
    """Open a URL with the default browser without invoking a shell string."""

    if not is_windows():
        return False
    try:
        result = ctypes.windll.shell32.ShellExecuteW(None, "open", url, None, None, 1)
        return int(result) > 32
    except Exception:
        return False


def get_default_gateway() -> str:
    """Best-effort default IPv4 gateway lookup used by the Wi-Fi helper."""

    if not is_windows():
        return ""
    try:
        from core.shell import SHELL

        rows = SHELL.powershell_json(
            "(Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null } | "
            "Select-Object -First 1 -ExpandProperty IPv4DefaultGateway).NextHop"
        )
        if isinstance(rows, str):
            return rows
        if isinstance(rows, list) and rows:
            return str(rows[0])
    except Exception:
        pass
    return ""
