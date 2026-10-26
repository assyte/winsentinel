"""Read-only security posture audit for the local Windows machine."""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Iterable

from core.constants import (
    ADBLOCK_EXTENSION_IDS,
    BROWSER_BY_KEY,
    FIREWALL_PROFILES,
    KNOWN_SECURE_DNS,
    PRIVACY_EXTENSION_IDS,
    BrowserPolicy,
)
from core.logger import get_logger
from core.models import (
    AuditReport,
    DefenderStatus,
    Finding,
    FirewallProfile,
    Status,
)
from core.policy_manager import PolicyManager
from core.shell import SHELL, ShellError
from core.winapi import is_admin

LOG = get_logger("auditor")
ProgressCallback = Callable[[int, int, str], None]

_WIFI_AUTH_KEYS = (
    "authentication",
    "kimlik doğrulama",
    "authentifizierung",
    "authentification",
    "autenticación",
    "autenticazione",
)
_WIFI_CIPHER_KEYS = (
    "cipher",
    "şifre",
    "verschlüsselung",
    "chiffrement",
    "cifrado",
    "crittografia",
)
_WIFI_STATE_KEYS = ("state", "durum", "status", "état", "estado", "stato")
_WIFI_SIGNAL_KEYS = ("signal", "sinyal", "signalstärke", "señal", "segnale")


def _as_list(value: object) -> list:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in {"true", "1", "yes", "enabled"}


def _action_label(value: object, mapping: dict[int, str]) -> str:
    """Normalise PowerShell enum values, which may arrive as ints or strings."""

    if isinstance(value, str) and not value.isdigit():
        return value
    try:
        return mapping.get(int(value or 0), str(value))
    except (TypeError, ValueError):
        return str(value)


def classify_dns_servers(servers: Iterable[str]) -> tuple[bool, list[str]]:
    """Return whether every server is a known privacy resolver, and its names."""

    addresses = [str(server).strip() for server in servers if str(server).strip()]
    if not addresses:
        return False, []
    names: list[str] = []
    for address in addresses:
        provider = KNOWN_SECURE_DNS.get(address)
        if not provider:
            return False, names
        if provider not in names:
            names.append(provider)
    return True, names


@dataclass(slots=True)
class WifiInfo:
    available: bool
    connected: bool
    interface_name: str = ""
    ssid: str = ""
    authentication: str = ""
    cipher: str = ""
    signal: str = ""
    state: str = ""
    wps_status: str = "not_exposed"
    raw_error: str = ""
    raw: str = ""


def _value_for_keys(values: dict[str, str], keys: Iterable[str]) -> str:
    for key in keys:
        for label, value in values.items():
            normalized = label.strip().lower()
            if normalized == key or normalized.startswith(key + " ") or key in normalized:
                if value:
                    return value.strip()
    return ""


def parse_wifi_interfaces(output: str) -> WifiInfo:
    """Parse ``netsh wlan show interfaces`` output.

    Windows translates the field labels, so detection also falls back to
    scanning values for WPA/WEP/Open tokens and the universal SSID label.
    """

    text = output or ""
    if not text.strip():
        return WifiInfo(available=False, connected=False, raw_error="No WLAN output.")
    lowered = text.lower()
    if "no wireless interface" in lowered or "there is no wireless" in lowered:
        return WifiInfo(available=False, connected=False)
    if "service is not running" in lowered or "not running" in lowered and "wlan" in lowered:
        return WifiInfo(available=False, connected=False, raw_error="WLAN AutoConfig is not running.")

    values: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(r"^\s{2,}([^:]+?)\s*:\s*(.*?)\s*$", line)
        if match:
            key, value = match.group(1), match.group(2)
            if key and value:
                values[key] = value

    state = _value_for_keys(values, _WIFI_STATE_KEYS)
    state_lower = state.strip().lower()
    connected = state_lower in {
        "connected",
        "bağlı",
        "verbunden",
        "connecté",
        "conectado",
        "connesso",
    } or (state_lower.startswith("connected") and not state_lower.startswith("disconnected"))
    # Localised netsh output still commonly includes "SSID" verbatim.
    ssid = ""
    for label, value in values.items():
        if label.strip().upper() == "SSID":
            ssid = value
            break
    interface_name = ""
    for label, value in values.items():
        if label.strip().lower() in {"name", "ad", "nom", "nombre", "nome"}:
            interface_name = value
            break

    authentication = _value_for_keys(values, _WIFI_AUTH_KEYS)
    cipher = _value_for_keys(values, _WIFI_CIPHER_KEYS)
    signal = _value_for_keys(values, _WIFI_SIGNAL_KEYS)

    if not authentication:
        for value in values.values():
            if re.search(r"\b(?:WPA[23]?|WEP|OPEN|NONE|AÇIK|ABIERTA|OUVERT)\b", value, re.I):
                authentication = value
                break
    if not cipher:
        for value in values.values():
            if re.search(r"\b(?:CCMP|GCMP|TKIP|WEP)\b", value, re.I):
                cipher = value
                break

    wps_status = "not_exposed"
    wps_matches = re.findall(r"(?im)^\s*WPS[^\n:]*:\s*(.+)$", text)
    if wps_matches:
        enabled_tokens = ("enabled", "on", "açık", "aktiv", "actif", "activado", "attivo")
        disabled_tokens = ("disabled", "off", "kapalı", "deaktiviert", "désactivé")
        for match in wps_matches:
            lower = match.lower()
            if any(token in lower for token in enabled_tokens):
                wps_status = "enabled"
                break
            if any(token in lower for token in disabled_tokens):
                wps_status = "disabled"
        if wps_status == "not_exposed" and wps_matches:
            wps_status = "detected"
    elif re.search(r"(?i)\bWPS\b", text):
        wps_status = "detected"

    # When disconnected, the output omits SSID/auth entirely.
    if not state and not authentication and not ssid:
        connected = False

    return WifiInfo(
        available=True,
        connected=connected,
        interface_name=interface_name,
        ssid=ssid,
        authentication=authentication,
        cipher=cipher,
        signal=signal,
        state=state,
        wps_status=wps_status,
        raw=text,
    )


def assess_wifi(info: WifiInfo) -> tuple[Status, str, str]:
    """Return status, summary, and detail for a parsed Wi-Fi interface."""

    if not info.available:
        return (
            Status.INFO,
            "No active Wi-Fi adapter",
            info.raw_error or "This PC is using a wired connection or Wi-Fi is disabled.",
        )
    if not info.connected:
        return (
            Status.INFO,
            "Wi-Fi is not connected",
            "No active wireless association was found. Connect to Wi-Fi and scan again to assess encryption.",
        )

    auth = (info.authentication or "").strip()
    cipher = (info.cipher or "").strip()
    auth_upper = auth.upper()
    cipher_upper = cipher.upper()
    weak_reasons: list[str] = []

    if not auth:
        status = Status.WARN
        weak_reasons.append("Encryption type could not be determined.")
    elif re.search(r"\bOPEN\b|\bNONE\b|\bAÇIK\b", auth_upper) or not auth_upper.strip():
        status = Status.FAIL
        weak_reasons.append("The network uses no encryption.")
    elif "WEP" in auth_upper:
        status = Status.FAIL
        weak_reasons.append("WEP encryption is obsolete and easily cracked.")
    elif re.search(r"(?<!WPA)(?<!WPA2)(?<!WPA3)\bWPA(?:-|$)", auth_upper) or (
        "WPA" in auth_upper and "WPA2" not in auth_upper and "WPA3" not in auth_upper
    ):
        status = Status.FAIL
        weak_reasons.append("WPA1 is deprecated; use WPA2 or WPA3.")
    elif "WPA3" in auth_upper:
        status = Status.PASS
    elif "WPA2" in auth_upper:
        status = Status.PASS
    else:
        status = Status.WARN
        weak_reasons.append(f"Unrecognised encryption type: {auth}.")

    if "TKIP" in cipher_upper:
        weak_reasons.append("TKIP cipher is legacy; CCMP/AES is preferred.")
        if status is Status.PASS:
            status = Status.WARN
    if "WEP" in cipher_upper:
        weak_reasons.append("WEP cipher detected.")
        if status is Status.PASS:
            status = Status.FAIL
    if info.wps_status == "enabled":
        weak_reasons.append("WPS appears to be enabled — WPS PIN has known brute-force weaknesses.")
        status = Status.FAIL

    if info.wps_status == "not_exposed":
        wps_note = "Windows/netsh did not expose a WPS state; verify WPS is off in your router."
    elif info.wps_status == "disabled":
        wps_note = "WPS is disabled."
    elif info.wps_status == "enabled":
        wps_note = "WPS is enabled."
    else:
        wps_note = "WPS was detected; verify it is disabled in your router."

    if status is Status.PASS:
        summary = f"{auth or 'Encrypted'} · {cipher or 'secure cipher'}"
    elif status is Status.WARN:
        summary = weak_reasons[0] if weak_reasons else "Wireless security needs review"
    else:
        summary = weak_reasons[0] if weak_reasons else "Insecure wireless network"

    detail_parts = [
        f"SSID: {info.ssid or 'unknown'}",
        f"Authentication: {auth or 'unknown'}",
        f"Cipher: {cipher or 'unknown'}",
    ]
    if info.signal:
        detail_parts.append(f"Signal: {info.signal}")
    detail_parts.append(wps_note)
    if weak_reasons:
        detail_parts.extend(weak_reasons)
    return status, summary, " · ".join(detail_parts)


class Auditor:
    """Runs all security checks and builds a scored :class:`AuditReport`."""

    def __init__(self, policy_manager: PolicyManager | None = None) -> None:
        self.policy_manager = policy_manager or PolicyManager()

    def scan(self, progress: ProgressCallback | None = None) -> AuditReport:
        started = datetime.now()
        findings: list[Finding] = []
        errors: list[str] = []
        checks = (
            ("defender", "Windows Defender", self.audit_defender),
            ("firewall", "Windows Firewall", self.audit_firewall),
            ("dns", "Private DNS", self.audit_dns),
            ("wifi", "Wi-Fi Security", self.audit_wifi),
            ("browser", "Browser Privacy", self.audit_browser_privacy),
            ("uac", "User Account Control", self.audit_uac),
        )
        total = len(checks)
        LOG.info("Security audit started")
        for index, (key, label, check) in enumerate(checks, start=1):
            if progress:
                progress(index - 1, total, f"Checking {label}…")
            try:
                finding = check()
            except Exception as exc:  # A broken check must not abort the audit.
                LOG.exception("Audit check failed: %s", key)
                errors.append(f"{label}: {exc}")
                finding = Finding(
                    key=key,
                    title=label,
                    status=Status.UNKNOWN,
                    summary="Check could not be completed",
                    detail=str(exc),
                    recommendation="Run WinSentinel as administrator and scan again.",
                )
            findings.append(finding)
            LOG.info(
                "Audit check %s: %s — %s",
                key,
                finding.status.value.upper(),
                finding.summary,
            )
            if progress:
                progress(index, total, f"Checked {label}")

        finished = datetime.now()
        report = AuditReport(
            findings=findings,
            started_at=started,
            finished_at=finished,
            is_admin=is_admin(),
            hostname=socket.gethostname(),
            errors=errors,
        )
        LOG.info(
            "Security audit finished: score %s/100, %s issue(s), %.1fs",
            report.score,
            len(report.issues),
            report.duration_seconds,
        )
        return report

    # ------------------------------------------------------------------
    def audit_defender(self) -> Finding:
        script = r"""
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
        error = ""
    } | ConvertTo-Json -Compress
} catch {
    [pscustomobject]@{
        available = $false
        error = $_.Exception.Message
    } | ConvertTo-Json -Compress
}
"""
        try:
            data = SHELL.powershell_json(script, label="Defender status")
        except ShellError as exc:
            return Finding(
                key="defender",
                title="Windows Defender",
                status=Status.UNKNOWN,
                summary="Defender status unavailable",
                detail=f"PowerShell could not query Microsoft Defender: {exc}",
                recommendation="Open Windows Security and verify real-time protection is on.",
                fix_action="defender",
            )
        if not isinstance(data, dict):
            raise ShellError("Unexpected Defender response.")

        if not _bool(data.get("available")):
            reason = str(data.get("error") or "Microsoft Defender is not reporting status.")
            return Finding(
                key="defender",
                title="Windows Defender",
                status=Status.UNKNOWN,
                summary="Defender is not available",
                detail=reason,
                recommendation=(
                    "A third-party antivirus may be managing protection. Verify active AV "
                    "coverage in Windows Security."
                ),
                fix_action="defender",
                evidence=data,
            )

        status_obj = DefenderStatus(
            available=True,
            antivirus_enabled=_bool(data.get("antivirus")),
            realtime_enabled=_bool(data.get("realtime")),
            am_service_enabled=_bool(data.get("am_service")),
            tamper_protection=str(data.get("tamper") or "Unknown"),
            signature_version=str(data.get("signature_version") or "Unknown"),
            signature_age_days=(
                int(data["signature_age"])
                if data.get("signature_age") is not None and int(data["signature_age"]) >= 0
                else None
            ),
        )
        if status_obj.antivirus_enabled and status_obj.realtime_enabled:
            status = Status.PASS
            summary = "Real-time protection is active"
        elif not status_obj.antivirus_enabled:
            status = Status.FAIL
            summary = "Antivirus protection is disabled"
        else:
            status = Status.FAIL
            summary = "Real-time protection is disabled"

        detail_parts = [
            f"Antivirus: {'on' if status_obj.antivirus_enabled else 'off'}",
            f"Real-time: {'on' if status_obj.realtime_enabled else 'off'}",
            f"AM service: {'on' if status_obj.am_service_enabled else 'off'}",
            f"Tamper protection: {status_obj.tamper_protection or 'unknown'}",
        ]
        if status_obj.signature_age_days is not None:
            detail_parts.append(f"Definitions: {status_obj.signature_age_days} day(s) old")
        return Finding(
            key="defender",
            title="Windows Defender",
            status=status,
            summary=summary,
            detail=" · ".join(detail_parts),
            recommendation=(
                "Keep real-time protection on. If it will not stay enabled, check Tamper "
                "Protection and any third-party antivirus."
            ),
            fix_action="defender",
            evidence={
                "antivirus": status_obj.antivirus_enabled,
                "realtime": status_obj.realtime_enabled,
                "tamper": status_obj.tamper_protection,
                "signature_age_days": status_obj.signature_age_days,
            },
        )

    # ------------------------------------------------------------------
    def audit_firewall(self) -> Finding:
        script = r"""
try {
    @(Get-NetFirewallProfile -ErrorAction Stop |
        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction) |
        ConvertTo-Json -Depth 3 -Compress
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
"""
        data = SHELL.powershell_json(script, label="Firewall status")
        rows = _as_list(data)
        if not rows:
            raise ShellError("No firewall profiles were returned.")
        inbound_map = {0: "Not configured", 1: "Allow", 2: "Block"}
        outbound_map = {0: "Not configured", 1: "Allow", 2: "Block"}
        profiles: list[FirewallProfile] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            profiles.append(
                FirewallProfile(
                    name=str(row.get("Name") or "Unknown"),
                    enabled=_bool(row.get("Enabled")),
                    default_inbound=_action_label(
                        row.get("DefaultInboundAction"), inbound_map
                    ),
                    default_outbound=_action_label(
                        row.get("DefaultOutboundAction"), outbound_map
                    ),
                )
            )
        if not profiles:
            raise ShellError("Firewall profile data was empty.")

        enabled_profiles = [profile for profile in profiles if profile.enabled]
        all_enabled = len(enabled_profiles) == len(profiles) == len(FIREWALL_PROFILES)
        inbound_blocked = all(profile.inbound_is_blocked for profile in profiles)
        critical_off = [profile.name for profile in profiles if not profile.enabled]

        if not all_enabled:
            status = Status.FAIL
            summary = f"{len(enabled_profiles)}/{len(profiles)} firewall profiles enabled"
        elif not inbound_blocked:
            status = Status.WARN
            summary = "Firewall is on; inbound default is not blocking"
        else:
            status = Status.PASS
            summary = "All profiles enabled · inbound blocked"

        detail = " · ".join(
            f"{profile.name}: {'on' if profile.enabled else 'OFF'} "
            f"(in {profile.default_inbound.lower()})"
            for profile in profiles
        )
        if critical_off:
            detail += f" — disabled: {', '.join(critical_off)}"
        recommendation = (
            "Turn on Domain, Private, and Public firewall profiles and set inbound "
            "traffic to Block by default."
            if status is not Status.PASS
            else "All firewall profiles are active with a blocking inbound default."
        )
        return Finding(
            key="firewall",
            title="Windows Firewall",
            status=status,
            summary=summary,
            detail=detail,
            recommendation=recommendation,
            fix_action="firewall",
            evidence={
                "profiles": [
                    {
                        "name": profile.name,
                        "enabled": profile.enabled,
                        "inbound": profile.default_inbound,
                        "outbound": profile.default_outbound,
                    }
                    for profile in profiles
                ]
            },
        )

    # ------------------------------------------------------------------
    def audit_dns(self) -> Finding:
        script = r"""
try {
    $rows = @()
    $configs = Get-NetIPConfiguration -ErrorAction Stop | Where-Object {
        $_.NetAdapter.Status -eq 'Up' -and
        $_.IPv4Address -ne $null -and
        $_.IPv4DefaultGateway -ne $null -and
        $_.InterfaceAlias -notmatch 'Loopback'
    }
    foreach ($config in $configs) {
        $dns4 = @(
            (Get-DnsClientServerAddress -InterfaceIndex $config.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses |
            Where-Object { $_ }
        )
        $dns6 = @(
            (Get-DnsClientServerAddress -InterfaceIndex $config.InterfaceIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue).ServerAddresses |
            Where-Object { $_ }
        )
        $ipif = Get-NetIPInterface -InterfaceIndex $config.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        $rows += [pscustomobject]@{
            Name = [string]$config.InterfaceAlias
            Description = [string]$config.InterfaceDescription
            Index = [int]$config.InterfaceIndex
            Address = [string]$config.IPv4Address[0].IPAddress
            Gateway = [string]$config.IPv4DefaultGateway[0].NextHop
            DNS = @($dns4)
            DNS6 = @($dns6)
            DHCP = if ($null -ne $ipif) { ([int]$ipif.Dhcp -eq 1) } else { $false }
        }
    }
    $rows | ConvertTo-Json -Depth 5 -Compress
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
"""
        data = SHELL.powershell_json(script, label="DNS configuration")
        rows = _as_list(data)
        adapters: list[dict] = [row for row in rows if isinstance(row, dict)]
        if not adapters:
            return Finding(
                key="dns",
                title="Private DNS",
                status=Status.INFO,
                summary="No active internet adapter",
                detail="Connect to a network and scan again to assess DNS privacy.",
                recommendation="Once online, choose a privacy-respecting DNS provider.",
                fix_action="secure_dns",
                weight=0.0,
            )

        detail_lines: list[str] = []
        unknown: list[str] = []
        providers: set[str] = set()
        auto_only: list[str] = []
        all_secure = True
        for adapter in adapters:
            name = str(adapter.get("Name") or "Adapter")
            dns_servers = [str(item) for item in _as_list(adapter.get("DNS")) if str(item).strip()]
            dns6_servers = [str(item) for item in _as_list(adapter.get("DNS6")) if str(item).strip()]
            servers = dns_servers or dns6_servers
            if not servers:
                all_secure = False
                auto_only.append(name)
                mode = "automatic" if _bool(adapter.get("DHCP")) else "not configured"
                detail_lines.append(f"{name}: {mode} DNS")
                continue
            secure, names = classify_dns_servers(servers)
            if not secure:
                all_secure = False
                unknown.extend(address for address in servers if address not in KNOWN_SECURE_DNS)
            providers.update(names)
            label = ", ".join(names) if names else "Unknown / ISP resolver"
            detail_lines.append(f"{name}: {', '.join(servers)} ({label})")

        if all_secure:
            status = Status.PASS
            summary = f"Secure resolver · {', '.join(sorted(providers)) or 'privacy DNS'}"
        elif auto_only and not unknown:
            status = Status.WARN
            summary = "DNS is automatic (router or ISP)"
        elif unknown:
            status = Status.WARN
            summary = "Using an unverified or ISP DNS resolver"
        else:
            status = Status.WARN
            summary = "DNS privacy needs review"

        recommendation = (
            "Set each adapter to a privacy-respecting resolver such as Cloudflare 1.1.1.1."
            if status is not Status.PASS
            else "DNS traffic is directed to a recognised privacy resolver."
        )
        return Finding(
            key="dns",
            title="Private DNS",
            status=status,
            summary=summary,
            detail=" · ".join(detail_lines),
            recommendation=recommendation,
            fix_action="secure_dns",
            evidence={
                "adapters": [
                    {
                        "name": adapter.get("Name"),
                        "dns": _as_list(adapter.get("DNS")),
                        "dns6": _as_list(adapter.get("DNS6")),
                        "dhcp": _bool(adapter.get("DHCP")),
                        "gateway": adapter.get("Gateway"),
                    }
                    for adapter in adapters
                ]
            },
        )

    # ------------------------------------------------------------------
    def audit_wifi(self) -> Finding:
        result = SHELL.netsh(["wlan", "show", "interfaces"], label="Wi-Fi audit")
        output = f"{result.stdout}\n{result.stderr}"
        if not result.ok and not output.strip():
            return Finding(
                key="wifi",
                title="Wi-Fi Security",
                status=Status.INFO,
                summary="Wi-Fi status unavailable",
                detail=result.error_text,
                recommendation="Verify the WLAN AutoConfig service is running.",
                fix_action="wifi_help",
                weight=0.0,
            )
        info = parse_wifi_interfaces(output)
        status, summary, detail = assess_wifi(info)
        if not info.available or not info.connected:
            weight = 0.0
        else:
            weight = 1.0
        recommendation = (
            "Use WPA3 (or WPA2-AES) and disable WPS in your router's wireless settings."
            if status in (Status.PASS, Status.INFO)
            else "Switch the router to WPA3 or WPA2-AES, use a strong passphrase, and disable WPS."
        )
        return Finding(
            key="wifi",
            title="Wi-Fi Security",
            status=status,
            summary=summary,
            detail=detail,
            recommendation=recommendation,
            fix_action="wifi_help",
            weight=weight,
            evidence={
                "connected": info.connected,
                "ssid": info.ssid,
                "authentication": info.authentication,
                "cipher": info.cipher,
                "wps": info.wps_status,
                "signal": info.signal,
            },
        )

    # ------------------------------------------------------------------
    def audit_browser_privacy(self) -> Finding:
        states = self.policy_manager.get_all_browser_states()
        installed = [state for state in states if state.installed]
        if not installed:
            return Finding(
                key="browser",
                title="Browser Privacy",
                status=Status.INFO,
                summary="No supported browser detected",
                detail="Chrome and Edge were not found on this PC.",
                recommendation="Install a browser and enforce an ad/tracker blocker.",
                fix_action="browser_extensions",
                weight=0.0,
            )

        compliant = [state for state in installed if state.compliant]
        partial = [state for state in installed if not state.compliant and state.entries]
        missing = [state for state in installed if not state.entries]
        detail_lines: list[str] = []
        for state in installed:
            if state.compliant:
                detail_lines.append(
                    f"{state.browser.name}: {' + '.join(state.extension_names)} forced"
                )
            elif state.extension_ids:
                missing_names = [
                    ext.name
                    for ext in state.browser.extensions
                    if ext.extension_id not in state.extension_ids
                    and not (
                        ext.name == "uBlock Origin"
                        and state.extension_ids & ADBLOCK_EXTENSION_IDS
                    )
                    and not (
                        ext.name == "Privacy Badger"
                        and state.extension_ids & PRIVACY_EXTENSION_IDS
                    )
                ]
                detail_lines.append(
                    f"{state.browser.name}: managed but incomplete"
                    + (f" — add {', '.join(missing_names)}" if missing_names else "")
                )
            else:
                detail_lines.append(f"{state.browser.name}: no forced ad blocker")

        if len(compliant) == len(installed):
            status = Status.PASS
            summary = "Ad and tracker blockers are enforced"
        elif compliant or partial:
            status = Status.WARN
            summary = f"Blockers enforced in {len(compliant)}/{len(installed)} browsers"
        else:
            status = Status.FAIL
            summary = "No forced ad or tracker blocker"

        return Finding(
            key="browser",
            title="Browser Privacy",
            status=status,
            summary=summary,
            detail=" · ".join(detail_lines),
            recommendation=(
                "Force-install uBlock Origin and Privacy Badger for Chrome and Edge. "
                "Restart browsers after applying the policy."
            ),
            fix_action="browser_extensions",
            evidence={
                "browsers": [
                    {
                        "name": state.browser.name,
                        "installed": state.installed,
                        "compliant": state.compliant,
                        "extensions": state.extension_names,
                    }
                    for state in states
                ]
            },
        )

    # ------------------------------------------------------------------
    def audit_uac(self) -> Finding:
        state = self.policy_manager.get_uac_state()
        if state.enable_lua != 1:
            status = Status.FAIL
            summary = "UAC is disabled"
        elif state.consent_prompt_behavior == 0:
            status = Status.FAIL
            summary = "Admin approval prompts are disabled"
        elif state.prompt_on_secure_desktop != 1:
            status = Status.WARN
            summary = "UAC prompts do not use the secure desktop"
        else:
            status = Status.PASS
            summary = "UAC is enabled with secure prompts"

        detail = (
            f"EnableLUA: {state.enable_lua} · "
            f"ConsentPromptBehaviorAdmin: {state.consent_prompt_behavior} · "
            f"Secure desktop: {state.prompt_on_secure_desktop} · "
            f"Level: {state.level_label}"
        )
        return Finding(
            key="uac",
            title="User Account Control",
            status=status,
            summary=summary,
            detail=detail,
            recommendation=(
                "Enable UAC and require consent on the secure desktop. A sign-out or "
                "restart is needed after changing these settings."
                if status is not Status.PASS
                else "UAC is enforcing elevation prompts at the recommended level."
            ),
            fix_action="uac",
            evidence={
                "EnableLUA": state.enable_lua,
                "ConsentPromptBehaviorAdmin": state.consent_prompt_behavior,
                "PromptOnSecureDesktop": state.prompt_on_secure_desktop,
            },
        )


def finding_for(report: AuditReport, key: str) -> Finding | None:
    return report.finding(key)


def browser_key_from_state(browser_key: str) -> BrowserPolicy | None:
    return BROWSER_BY_KEY.get(browser_key)
