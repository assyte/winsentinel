"""WinSentinel entrypoint with mandatory Windows elevation."""

from __future__ import annotations

import ctypes
import os
import sys
import traceback

from core.constants import APP_NAME, APP_VERSION
from core.logger import get_log_path, get_logger, setup_logging
from core.winapi import (
    is_admin,
    is_windows,
    relaunch_as_admin,
    set_dpi_awareness,
    show_native_error,
)


def _acquire_single_instance():
    """Hold a named mutex for the lifetime of the process."""

    if not is_windows():
        return None
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateMutexW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_bool,
            ctypes.c_wchar_p,
        ]
        kernel32.CreateMutexW.restype = ctypes.c_void_p
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_bool

        handle = kernel32.CreateMutexW(None, False, "Local\\WinSentinel.Security.1")
        if not handle:
            return None
        if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
            kernel32.CloseHandle(handle)
            return None
        return handle
    except Exception:
        return None


def main() -> int:
    if not is_windows():
        print("WinSentinel requires Windows 10 or Windows 11.", file=sys.stderr)
        return 1

    if len(sys.argv) > 1 and sys.argv[1] in {"--version", "-v"}:
        print(f"{APP_NAME} {APP_VERSION}")
        return 0
    if len(sys.argv) > 1 and sys.argv[1] in {"--help", "-h"}:
        print(
            f"{APP_NAME} {APP_VERSION}\n"
            "Windows security auditor and one-click hardening dashboard.\n\n"
            "Usage: python main.py\n"
            "Administrator privileges are requested automatically via UAC."
        )
        return 0

    set_dpi_awareness()
    setup_logging()
    log = get_logger("main")

    if not is_admin():
        log.info("Not elevated; requesting UAC elevation.")
        if relaunch_as_admin():
            return 0
        log.warning("User declined elevation or the UAC launch failed.")
        show_native_error(
            f"{APP_NAME} requires administrator rights",
            (
                "WinSentinel needs administrator rights to read and change Windows "
                "Firewall, DNS, UAC, and browser policies.\n\n"
                "Right-click the app and choose 'Run as administrator', then try again."
            ),
        )
        return 1

    mutex = _acquire_single_instance()
    if mutex is None:
        show_native_error(
            f"{APP_NAME} is already running",
            "Close the existing WinSentinel window before starting another instance.",
        )
        return 0

    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            "WinSentinel.Security.1"
        )
    except Exception:
        pass

    log.info("Elevation confirmed; launching interface")
    try:
        from ui.app import WinSentinelApp

        app = WinSentinelApp()
        app.mainloop()
        return 0
    except Exception as exc:
        log.exception("Fatal application error")
        details = traceback.format_exc(limit=6)
        log_path = get_log_path()
        show_native_error(
            f"{APP_NAME} encountered an error",
            (
                f"{exc}\n\n"
                "The full traceback is available in:\n"
                f"{log_path or 'the application log'}"
            ),
            warning=False,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
