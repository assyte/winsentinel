"""Browser extension policies and Windows security policy management."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from core.constants import (
    ALL_MANAGED_EXTENSION_IDS,
    BROWSER_BY_KEY,
    BROWSERS,
    EXTENSION_NAME_BY_ID,
    UAC_POLICY_KEY,
    BrowserPolicy,
)
from core.logger import get_logger
from core.models import OperationResult, UACState
from core.winapi import is_admin

try:
    import winreg
except ImportError:  # pragma: no cover - the application targets Windows
    winreg = None  # type: ignore[assignment]

LOG = get_logger("policy")

_HKLM = winreg.HKEY_LOCAL_MACHINE if winreg else 0
_HKCU = winreg.HKEY_CURRENT_USER if winreg else 0
_KEY_READ = winreg.KEY_READ if winreg else 0
_KEY_WRITE = winreg.KEY_WRITE if winreg else 0
_WOW64_64 = getattr(winreg, "KEY_WOW64_64KEY", 0) if winreg else 0


@dataclass(slots=True)
class ForcedExtension:
    browser_key: str
    hive: str
    value_name: str
    raw_value: str
    extension_id: str
    name: str

    @property
    def update_url(self) -> str:
        parts = self.raw_value.split(";", 1)
        return parts[1].strip() if len(parts) > 1 else ""


@dataclass(slots=True)
class BrowserPolicyState:
    browser: BrowserPolicy
    installed: bool
    entries: list[ForcedExtension] = field(default_factory=list)
    error: str = ""

    @property
    def extension_ids(self) -> set[str]:
        return {entry.extension_id for entry in self.entries}

    @property
    def extension_names(self) -> list[str]:
        names: list[str] = []
        for entry in self.entries:
            if entry.name not in names:
                names.append(entry.name)
        return names

    @property
    def adblock_found(self) -> bool:
        from core.constants import ADBLOCK_EXTENSION_IDS

        return bool(self.extension_ids & ADBLOCK_EXTENSION_IDS)

    @property
    def privacy_found(self) -> bool:
        from core.constants import PRIVACY_EXTENSION_IDS

        return bool(self.extension_ids & PRIVACY_EXTENSION_IDS)

    @property
    def compliant(self) -> bool:
        return self.adblock_found and self.privacy_found


# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------
def _open_key(root: int, path: str, access: int):
    if winreg is None:
        raise OSError("The Windows registry is unavailable on this platform.")
    return winreg.OpenKey(root, path, 0, access | _WOW64_64)


def _read_force_list(browser: BrowserPolicy, hive: int, hive_name: str) -> list[ForcedExtension]:
    if winreg is None:
        return []
    try:
        with _open_key(hive, browser.force_list_key, _KEY_READ) as key:
            entries: list[ForcedExtension] = []
            index = 0
            count = winreg.QueryInfoKey(key)[1]
            for _ in range(count):
                try:
                    name, value, _value_type = winreg.EnumValue(key, index)
                except OSError:
                    break
                index += 1
                raw = str(value).strip()
                if not raw:
                    continue
                extension_id = raw.split(";", 1)[0].strip().lower()
                entries.append(
                    ForcedExtension(
                        browser_key=browser.key,
                        hive=hive_name,
                        value_name=name,
                        raw_value=raw,
                        extension_id=extension_id,
                        name=EXTENSION_NAME_BY_ID.get(extension_id, "Managed extension"),
                    )
                )
            return entries
    except FileNotFoundError:
        return []
    except OSError:
        return []


def _entry_sort_key(name: str) -> tuple[int, int | str]:
    try:
        return (0, int(name))
    except (TypeError, ValueError):
        return (1, name.lower())


def parse_force_value(raw: str) -> tuple[str, str]:
    parts = str(raw).split(";", 1)
    extension_id = parts[0].strip().lower()
    update_url = parts[1].strip() if len(parts) > 1 else ""
    return extension_id, update_url


# ---------------------------------------------------------------------------
# Browser discovery
# ---------------------------------------------------------------------------
def _app_path_from_registry(executable: str) -> str:
    if winreg is None:
        return ""
    relative = rf"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{executable}"
    for hive in (_HKCU, _HKLM):
        try:
            with _open_key(hive, relative, _KEY_READ) as key:
                value, _kind = winreg.QueryValueEx(key, "")
                if value and Path(str(value)).exists():
                    return str(value)
        except OSError:
            continue
    return ""


def _known_browser_paths(browser: BrowserPolicy) -> list[Path]:
    candidates: list[Path] = []
    roots = [
        os.environ.get("PROGRAMFILES"),
        os.environ.get("PROGRAMFILES(X86)"),
        os.environ.get("LOCALAPPDATA"),
    ]
    if browser.key == "chrome":
        for root in roots[:2]:
            if root:
                candidates.append(Path(root) / "Google" / "Chrome" / "Application" / "chrome.exe")
        if os.environ.get("LOCALAPPDATA"):
            candidates.append(
                Path(os.environ["LOCALAPPDATA"])
                / "Google"
                / "Chrome"
                / "Application"
                / "chrome.exe"
            )
    elif browser.key == "edge":
        for root in roots[:2]:
            if root:
                candidates.append(
                    Path(root) / "Microsoft" / "Edge" / "Application" / "msedge.exe"
                )
    return candidates


def is_browser_installed(browser: BrowserPolicy) -> bool:
    for executable in browser.executable_names:
        path = _app_path_from_registry(executable)
        if path:
            return True
    return any(path.exists() for path in _known_browser_paths(browser))


def detect_installed_browsers() -> list[BrowserPolicy]:
    return [browser for browser in BROWSERS if is_browser_installed(browser)]


# ---------------------------------------------------------------------------
# Browser policy manager
# ---------------------------------------------------------------------------
class PolicyManager:
    """Reads and writes machine-wide browser and UAC policies."""

    def get_browser_state(self, browser: BrowserPolicy) -> BrowserPolicyState:
        installed = is_browser_installed(browser)
        entries = _read_force_list(browser, _HKLM, "HKLM")
        entries.extend(_read_force_list(browser, _HKCU, "HKCU"))
        # De-duplicate values imported from machine and user hives.
        seen: set[tuple[str, str]] = set()
        filtered: list[ForcedExtension] = []
        for entry in entries:
            marker = (entry.hive, entry.extension_id)
            if marker in seen:
                continue
            seen.add(marker)
            filtered.append(entry)
        return BrowserPolicyState(browser=browser, installed=installed, entries=filtered)

    def get_all_browser_states(self) -> list[BrowserPolicyState]:
        return [self.get_browser_state(browser) for browser in BROWSERS]

    def installed_browser_states(self) -> list[BrowserPolicyState]:
        return [state for state in self.get_all_browser_states() if state.installed]

    def enforce_browser_extensions(
        self,
        browsers: list[BrowserPolicy] | None = None,
    ) -> OperationResult:
        """Append WinSentinel's blockers to existing force-install policies."""

        if not is_admin():
            return OperationResult.error(
                "Administrator rights are required to update browser policies."
            )
        if winreg is None:
            return OperationResult.error("The Windows registry is unavailable.")

        targets = browsers or list(BROWSERS)
        details: list[str] = []
        added = 0
        existing = 0
        failed = 0

        for browser in targets:
            try:
                with winreg.CreateKeyEx(
                    _HKLM,
                    browser.force_list_key,
                    0,
                    _KEY_READ | _KEY_WRITE | _WOW64_64,
                ) as key:
                    raw_values: dict[str, str] = {}
                    count = winreg.QueryInfoKey(key)[1]
                    for index in range(count):
                        try:
                            name, value, _kind = winreg.EnumValue(key, index)
                        except OSError:
                            break
                        raw_values[str(name)] = str(value)
                    present_ids = {
                        parse_force_value(value)[0]
                        for value in raw_values.values()
                        if value.strip()
                    }
                    numeric_names = []
                    for name in raw_values:
                        try:
                            numeric_names.append(int(name))
                        except ValueError:
                            continue
                    next_index = max(numeric_names, default=0) + 1

                    for spec in browser.extensions:
                        if spec.extension_id in present_ids:
                            existing += 1
                            details.append(f"{browser.name}: {spec.name} is already managed.")
                            continue
                        value = f"{spec.extension_id};{browser.update_url}"
                        winreg.SetValueEx(
                            key,
                            str(next_index),
                            0,
                            winreg.REG_SZ,
                            value,
                        )
                        next_index += 1
                        added += 1
                        details.append(f"{browser.name}: queued {spec.name} for install.")
                LOG.info(
                    "Browser policy updated for %s (%s extension entries)",
                    browser.name,
                    len(browser.extensions),
                )
            except OSError as exc:
                failed += 1
                message = f"{browser.name}: registry update failed — {exc}"
                details.append(message)
                LOG.error(message)

        if failed and not added and not existing:
            return OperationResult.error(
                "Could not update browser extension policies. See the system log.",
                details,
            )

        if added:
            message = (
                f"Ad blockers enforced for {len(targets)} browser polic"
                f"{'y' if len(targets) == 1 else 'ies'}. Restart browsers to apply."
            )
        else:
            message = "Ad blocker policies were already configured."
        if failed:
            message += f" {failed} browser polic{'y' if failed == 1 else 'ies'} could not be updated."

        return OperationResult(
            success=failed == 0,
            message=message,
            details=details,
            reboot_required=False,
        )

    def remove_browser_extensions(
        self,
        browsers: list[BrowserPolicy] | None = None,
    ) -> OperationResult:
        """Remove only WinSentinel-managed blockers, preserving other policies."""

        if not is_admin():
            return OperationResult.error(
                "Administrator rights are required to update browser policies."
            )
        if winreg is None:
            return OperationResult.error("The Windows registry is unavailable.")

        targets = browsers or list(BROWSERS)
        details: list[str] = []
        removed = 0
        preserved = 0

        for browser in targets:
            try:
                policy_key = _open_key(
                    _HKLM,
                    browser.force_list_key,
                    _KEY_READ | _KEY_WRITE,
                )
            except FileNotFoundError:
                continue
            except OSError as exc:
                details.append(f"{browser.name}: could not open policy — {exc}")
                LOG.error("Failed to open browser policy for %s: %s", browser.name, exc)
                continue
            try:
                with policy_key as key:
                    values: list[tuple[str, str]] = []
                    count = winreg.QueryInfoKey(key)[1]
                    for index in range(count):
                        try:
                            name, value, _kind = winreg.EnumValue(key, index)
                        except OSError:
                            break
                        if str(value).strip():
                            values.append((str(name), str(value)))

                    keep: list[str] = []
                    for _name, value in values:
                        extension_id, _url = parse_force_value(value)
                        if extension_id in ALL_MANAGED_EXTENSION_IDS:
                            removed += 1
                            details.append(
                                f"{browser.name}: removed {EXTENSION_NAME_BY_ID.get(extension_id, extension_id)}."
                            )
                        else:
                            keep.append(value)
                            preserved += 1

                    if len(keep) == len(values):
                        continue

                    for name, _value in values:
                        try:
                            winreg.DeleteValue(key, name)
                        except OSError:
                            pass
                    for index, value in enumerate(keep, start=1):
                        winreg.SetValueEx(key, str(index), 0, winreg.REG_SZ, value)
                    LOG.info("Removed WinSentinel browser policies for %s", browser.name)
            except OSError as exc:
                details.append(f"{browser.name}: could not update policy — {exc}")
                LOG.error("Failed to remove browser policy for %s: %s", browser.name, exc)

        if not removed:
            return OperationResult.ok(
                "No WinSentinel-managed browser extensions were configured.",
                details,
            )
        message = f"Removed {removed} forced extension entr{'y' if removed == 1 else 'ies'}."
        if preserved:
            message += f" Preserved {preserved} unrelated policy entr{'y' if preserved == 1 else 'ies'}."
        return OperationResult(
            success=True,
            message=message,
            details=details,
            reboot_required=False,
        )

    # ------------------------------------------------------------------
    # UAC
    # ------------------------------------------------------------------
    def get_uac_state(self) -> UACState:
        if winreg is None:
            return UACState(enable_lua=0, consent_prompt_behavior=0, prompt_on_secure_desktop=0)
        values: dict[str, int] = {}
        try:
            with _open_key(_HKLM, UAC_POLICY_KEY, _KEY_READ) as key:
                for name, default in (
                    ("EnableLUA", 1),
                    ("ConsentPromptBehaviorAdmin", 5),
                    ("PromptOnSecureDesktop", 1),
                ):
                    try:
                        value, _kind = winreg.QueryValueEx(key, name)
                        values[name] = int(value)
                    except OSError:
                        values[name] = default
        except OSError:
            values = {
                "EnableLUA": 0,
                "ConsentPromptBehaviorAdmin": 0,
                "PromptOnSecureDesktop": 0,
            }
        return UACState(
            enable_lua=values["EnableLUA"],
            consent_prompt_behavior=values["ConsentPromptBehaviorAdmin"],
            prompt_on_secure_desktop=values["PromptOnSecureDesktop"],
        )

    @staticmethod
    def uac_is_compliant(state: UACState) -> bool:
        return (
            state.enable_lua == 1
            and state.consent_prompt_behavior != 0
            and state.prompt_on_secure_desktop == 1
        )

    def harden_uac(self) -> OperationResult:
        """Restore the recommended UAC defaults (requires a sign-out to apply)."""

        if not is_admin():
            return OperationResult.error("Administrator rights are required to change UAC.")
        if winreg is None:
            return OperationResult.error("The Windows registry is unavailable.")

        current = self.get_uac_state()
        if self.uac_is_compliant(current):
            return OperationResult.ok(
                "UAC already uses the recommended secure defaults.",
                ["No registry changes were needed."],
                skipped=True,
            )

        target = {
            "EnableLUA": 1,
            "ConsentPromptBehaviorAdmin": 5,
            "PromptOnSecureDesktop": 1,
        }
        try:
            with winreg.OpenKey(
                _HKLM,
                UAC_POLICY_KEY,
                0,
                _KEY_READ | _KEY_WRITE | _WOW64_64,
            ) as key:
                for name, value in target.items():
                    winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
        except OSError as exc:
            LOG.error("Could not update UAC policy: %s", exc)
            return OperationResult.error(f"UAC could not be updated: {exc}")

        LOG.info("UAC hardening applied; a restart or sign-out is required.")
        return OperationResult(
            success=True,
            message="UAC restored to the secure default. Sign out or restart to apply.",
            details=[
                "EnableLUA = 1",
                "ConsentPromptBehaviorAdmin = 5",
                "PromptOnSecureDesktop = 1",
            ],
            reboot_required=True,
        )


def browser_for_key(key: str) -> BrowserPolicy | None:
    return BROWSER_BY_KEY.get(key)
