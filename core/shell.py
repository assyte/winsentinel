"""Hardened subprocess helpers for PowerShell, netsh, and native tools."""

from __future__ import annotations

import ctypes
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Sequence

from core.logger import get_logger

LOG = get_logger("shell")

_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0
_PS_PREFIX = (
    "$ProgressPreference='SilentlyContinue';"
    "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
    "$OutputEncoding=[System.Text.Encoding]::UTF8;"
)


class ShellError(RuntimeError):
    """Raised when a system command fails and its output is required."""


@dataclass(slots=True)
class CommandResult:
    args: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    @property
    def command_display(self) -> str:
        return subprocess.list2cmdline(self.args)

    @property
    def error_text(self) -> str:
        text = (self.stderr or "").strip() or (self.stdout or "").strip()
        if self.timed_out:
            return "The command timed out."
        if not text:
            return f"Command exited with code {self.returncode}."
        return _shorten(text, 1600)

    def require_ok(self) -> "CommandResult":
        if not self.ok:
            raise ShellError(self.error_text)
        return self


def _shorten(value: str, limit: int = 3000) -> str:
    text = value.strip()
    if len(text) <= limit:
        return text
    return f"{text[:limit]}…"


def _oem_encoding() -> str:
    if os.name != "nt":
        return "utf-8"
    try:
        return f"cp{ctypes.windll.kernel32.GetOEMCP()}"
    except Exception:
        return "utf-8"


def _decode(data: bytes | str | None, encoding: str) -> str:
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    try:
        return data.decode(encoding, errors="replace")
    except (LookupError, UnicodeDecodeError):
        return data.decode("utf-8", errors="replace")


def powershell_quote(value: str) -> str:
    """Escape a value for a single-quoted PowerShell literal."""

    return "'" + str(value).replace("'", "''") + "'"


class SystemShell:
    """Runs system commands with timeouts, no console flash, and audit logging."""

    def __init__(self, powershell_timeout: int = 35) -> None:
        self.powershell_timeout = powershell_timeout
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        self.powershell_exe = os.path.join(
            system_root,
            "System32",
            "WindowsPowerShell",
            "v1.0",
            "powershell.exe",
        )
        self._startupinfo = None
        if os.name == "nt":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE
            self._startupinfo = startupinfo

    # ------------------------------------------------------------------
    def run(
        self,
        args: Sequence[str],
        *,
        timeout: int = 30,
        encoding: str | None = None,
        label: str = "",
        log_output: bool = False,
    ) -> CommandResult:
        args_list = [str(part) for part in args]
        display = subprocess.list2cmdline(args_list)
        started = time.monotonic()
        if label and (len(display) > 260 or "\n" in display):
            LOG.debug("Command [%s] started", label)
        else:
            LOG.debug("Command%s: %s", f" [{label}]" if label else "", display)

        try:
            completed = subprocess.run(
                args_list,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                creationflags=_CREATE_NO_WINDOW,
                startupinfo=self._startupinfo,
                check=False,
            )
            stdout = _decode(completed.stdout, encoding or _oem_encoding())
            stderr = _decode(completed.stderr, encoding or _oem_encoding())
            result = CommandResult(
                args=args_list,
                returncode=completed.returncode,
                stdout=stdout,
                stderr=stderr,
                duration=time.monotonic() - started,
            )
        except subprocess.TimeoutExpired as exc:
            result = CommandResult(
                args=args_list,
                returncode=-1,
                stdout=_decode(exc.stdout, encoding or _oem_encoding()),
                stderr=_decode(exc.stderr, encoding or _oem_encoding()),
                duration=time.monotonic() - started,
                timed_out=True,
            )
        except OSError as exc:
            result = CommandResult(
                args=args_list,
                returncode=-1,
                stdout="",
                stderr=str(exc),
                duration=time.monotonic() - started,
            )

        if result.ok:
            if log_output and result.stdout.strip():
                LOG.debug("Output%s: %s", f" [{label}]" if label else "", _shorten(result.stdout))
        else:
            LOG.warning(
                "Command failed%s (exit %s): %s",
                f" [{label}]" if label else "",
                result.returncode,
                result.error_text,
            )
        return result

    # ------------------------------------------------------------------
    def powershell(
        self,
        script: str,
        *,
        timeout: int | None = None,
        label: str = "",
        log_output: bool = False,
    ) -> CommandResult:
        command = (
            "$ErrorActionPreference='Stop';"
            + _PS_PREFIX
            + script
        )
        return self.run(
            [
                self.powershell_exe,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                command,
            ],
            timeout=timeout or self.powershell_timeout,
            encoding="utf-8-sig",
            label=label or "PowerShell",
            log_output=log_output,
        )

    # ------------------------------------------------------------------
    def powershell_json(
        self,
        script: str,
        *,
        timeout: int | None = None,
        label: str = "",
    ) -> Any:
        result = self.powershell(script, timeout=timeout, label=label)
        if not result.ok:
            raise ShellError(result.error_text)
        return parse_json_output(result.stdout)

    # ------------------------------------------------------------------
    def netsh(
        self,
        arguments: Sequence[str],
        *,
        timeout: int = 30,
        label: str = "netsh",
    ) -> CommandResult:
        return self.run(
            ["netsh", *arguments],
            timeout=timeout,
            encoding=_oem_encoding(),
            label=label,
        )

    def ipconfig(self, *arguments: str, timeout: int = 20) -> CommandResult:
        return self.run(
            ["ipconfig", *arguments],
            timeout=timeout,
            encoding=_oem_encoding(),
            label="ipconfig",
        )


def parse_json_output(raw: str) -> Any:
    """Parse JSON emitted by PowerShell, tolerating a BOM or leading noise."""

    text = raw.replace("\ufeff", "").strip()
    if not text:
        return None
    if text.startswith("null"):
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        starts = [index for index in (text.find("{"), text.find("[")) if index >= 0]
        if not starts:
            raise
        candidate = text[min(starts) :]
        return json.loads(candidate)


SHELL = SystemShell()
