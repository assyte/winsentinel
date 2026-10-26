"""Windows Firewall and Defender control plane."""

from __future__ import annotations

from core.constants import FIREWALL_PROFILES
from core.logger import get_logger
from core.models import DefenderStatus, FirewallProfile, OperationResult
from core.shell import SHELL, ShellError
from core.winapi import is_admin

LOG = get_logger("firewall")

_PROFILE_QUERY = r"""
try {
    @(Get-NetFirewallProfile -ErrorAction Stop |
        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction) |
        ConvertTo-Json -Depth 3 -Compress
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
"""

_DEFENDER_QUERY = r"""
try {
    $s = Get-MpComputerStatus -ErrorAction Stop
    $p = Get-MpPreference -ErrorAction SilentlyContinue
    [pscustomobject]@{
        available = $true
        antivirus = [bool]$s.AntivirusEnabled
        realtime = [bool]$s.RealTimeProtectionEnabled
        am_service = [bool]$s.AMServiceEnabled
        tamper = [string]$s.TamperProtectionSource
        signature_version = [string]$s.AntivirusSignatureVersion
        signature_age = if ($null -ne $s.AntivirusSignatureAge) { [int]$s.AntivirusSignatureAge } else { -1 }
        disable_realtime = if ($null -ne $p) { [bool]$p.DisableRealtimeMonitoring } else { $false }
    } | ConvertTo-Json -Compress
} catch {
    [pscustomobject]@{
        available = $false
        error = $_.Exception.Message
    } | ConvertTo-Json -Compress
}
"""

_INBOUND_MAP = {0: "Not configured", 1: "Allow", 2: "Block"}
_OUTBOUND_MAP = {0: "Not configured", 1: "Allow", 2: "Block"}
_ACTION_BY_NUMBER = {1: "Allow", 2: "Block"}
_NUMBER_BY_ACTION = {"allow": 1, "block": 2}


def _as_list(value: object) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _enum_label(value: object, mapping: dict[int, str]) -> str:
    if isinstance(value, str):
        if value.isdigit():
            return mapping.get(int(value), value)
        return value
    try:
        return mapping.get(int(value), str(value))
    except (TypeError, ValueError):
        return str(value)


def _bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in {"true", "1", "yes", "enabled"}


class FirewallManager:
    """Queries and applies Windows Firewall and Microsoft Defender settings."""

    # ------------------------------------------------------------------
    def get_profiles(self) -> list[FirewallProfile]:
        data = SHELL.powershell_json(_PROFILE_QUERY, label="Firewall profiles")
        profiles: list[FirewallProfile] = []
        for row in _as_list(data):
            if not isinstance(row, dict):
                continue
            profiles.append(
                FirewallProfile(
                    name=str(row.get("Name") or "Unknown"),
                    enabled=_bool(row.get("Enabled")),
                    default_inbound=_enum_label(row.get("DefaultInboundAction"), _INBOUND_MAP),
                    default_outbound=_enum_label(row.get("DefaultOutboundAction"), _OUTBOUND_MAP),
                )
            )
        order = {name: index for index, name in enumerate(FIREWALL_PROFILES)}
        profiles.sort(key=lambda profile: order.get(profile.name, 99))
        return profiles

    def set_profile_enabled(self, profile: str, enabled: bool) -> OperationResult:
        if not is_admin():
            return OperationResult.error("Administrator rights are required to change the firewall.")
        if profile not in FIREWALL_PROFILES:
            return OperationResult.error(f"Unknown firewall profile: {profile}")
        script = (
            f"Set-NetFirewallProfile -Profile {profile} "
            f"-Enabled {'$true' if enabled else '$false'} -ErrorAction Stop"
        )
        result = SHELL.powershell(script, label=f"Firewall {profile}")
        if not result.ok:
            return OperationResult.error(
                f"Could not turn {profile} firewall {'on' if enabled else 'off'}.",
                [result.error_text],
            )
        try:
            profiles = self.get_profiles()
        except ShellError as exc:
            return OperationResult.error("Firewall changed, but verification failed.", [str(exc)])
        target = next((item for item in profiles if item.name == profile), None)
        if target is None or target.enabled != enabled:
            return OperationResult.error(
                f"The {profile} firewall did not accept the change.",
                ["A Group Policy or security product may be enforcing this setting."],
            )
        LOG.info("Firewall profile %s set to %s", profile, "on" if enabled else "off")
        return OperationResult.ok(
            f"{profile} firewall turned {'on' if enabled else 'off'}.",
            [f"Profile: {profile}", f"Enabled: {enabled}"],
        )

    def set_all_enabled(self, enabled: bool = True) -> OperationResult:
        if not is_admin():
            return OperationResult.error("Administrator rights are required to change the firewall.")
        script = (
            "Set-NetFirewallProfile -Profile Domain,Private,Public "
            f"-Enabled {'$true' if enabled else '$false'} -ErrorAction Stop"
        )
        result = SHELL.powershell(script, label="All firewall profiles")
        if not result.ok:
            return OperationResult.error(
                "Could not update all firewall profiles.",
                [result.error_text],
            )
        try:
            profiles = self.get_profiles()
        except ShellError as exc:
            return OperationResult.error("Firewall changed, but verification failed.", [str(exc)])
        if len(profiles) < 3 or any(profile.enabled != enabled for profile in profiles):
            return OperationResult.error(
                "One or more firewall profiles did not accept the change.",
                ["Check Group Policy, third-party firewall, or tamper protection."],
            )
        LOG.info("All firewall profiles set to %s", "on" if enabled else "off")
        return OperationResult.ok(
            f"All firewall profiles turned {'on' if enabled else 'off'}.",
            [f"{profile.name}: {'on' if profile.enabled else 'off'}" for profile in profiles],
        )

    def block_inbound(self, enabled: bool = True) -> OperationResult:
        if not is_admin():
            return OperationResult.error("Administrator rights are required to change the firewall.")
        action = "Block" if enabled else "NotConfigured"
        script = (
            f"Set-NetFirewallProfile -Profile Domain,Private,Public "
            f"-DefaultInboundAction {action} -ErrorAction Stop"
        )
        result = SHELL.powershell(script, label="Firewall inbound default")
        if not result.ok:
            return OperationResult.error(
                "Could not change the inbound firewall default.",
                [result.error_text],
            )
        try:
            profiles = self.get_profiles()
        except ShellError as exc:
            return OperationResult.error("Inbound policy changed, but verification failed.", [str(exc)])
        if enabled:
            if not all(profile.inbound_is_blocked for profile in profiles):
                return OperationResult.error(
                    "Inbound blocking was not applied to every profile.",
                    ["Group Policy may be overriding this setting."],
                )
            LOG.info("Inbound firewall default set to Block")
            return OperationResult.ok(
                "Inbound traffic is now blocked unless explicitly allowed.",
                [f"{profile.name}: {profile.default_inbound}" for profile in profiles],
            )
        LOG.warning("Inbound firewall default reset; inbound traffic may now be allowed")
        return OperationResult.ok(
            "Inbound default reset. Windows will use its default behavior.",
            [f"{profile.name}: {profile.default_inbound}" for profile in profiles],
        )

    # ------------------------------------------------------------------
    def get_defender_status(self) -> DefenderStatus:
        try:
            data = SHELL.powershell_json(_DEFENDER_QUERY, label="Defender status")
        except ShellError as exc:
            return DefenderStatus(available=False, raw_error=str(exc))
        if not isinstance(data, dict) or not _bool(data.get("available")):
            return DefenderStatus(
                available=False,
                raw_error=str(data.get("error") if isinstance(data, dict) else "Unknown error"),
            )
        age_value = data.get("signature_age")
        try:
            age = int(age_value)
        except (TypeError, ValueError):
            age = -1
        return DefenderStatus(
            available=True,
            antivirus_enabled=_bool(data.get("antivirus")),
            realtime_enabled=_bool(data.get("realtime")),
            am_service_enabled=_bool(data.get("am_service")),
            tamper_protection=str(data.get("tamper") or "Unknown"),
            signature_version=str(data.get("signature_version") or "Unknown"),
            signature_age_days=age if age >= 0 else None,
        )

    def set_realtime_protection(self, enabled: bool) -> OperationResult:
        if not is_admin():
            return OperationResult.error("Administrator rights are required to change Defender.")
        script = (
            "Set-MpPreference "
            f"-DisableRealtimeMonitoring {'$false' if enabled else '$true'} -ErrorAction Stop"
        )
        result = SHELL.powershell(script, label="Defender real-time")
        if not result.ok:
            return OperationResult.error(
                f"Could not turn real-time protection {'on' if enabled else 'off'}.",
                [
                    result.error_text,
                    "Tamper Protection or a third-party antivirus may block this change.",
                ],
            )
        status = self.get_defender_status()
        if not status.available:
            return OperationResult.error(
                "Defender returned no status after the change.",
                [status.raw_error],
            )
        if status.realtime_enabled != enabled:
            return OperationResult.error(
                f"Defender did not accept the real-time protection change.",
                [
                    f"Reported real-time state: {'on' if status.realtime_enabled else 'off'}",
                    "Tamper Protection can prevent changes made by local tools.",
                ],
            )
        LOG.info("Defender real-time protection set to %s", "on" if enabled else "off")
        return OperationResult.ok(
            f"Real-time protection turned {'on' if enabled else 'off'}.",
            [
                f"Antivirus: {'on' if status.antivirus_enabled else 'off'}",
                f"Real-time: {'on' if status.realtime_enabled else 'off'}",
            ],
        )


def status_label(enabled: bool) -> str:
    return "Active" if enabled else "Disabled"
