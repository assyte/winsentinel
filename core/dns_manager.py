"""DNS discovery and secure resolver switching through netsh."""

from __future__ import annotations

import ipaddress
import time
from typing import Iterable

from core.constants import DNSProvider, DNS_PROVIDER_BY_KEY
from core.logger import get_logger
from core.models import AdapterInfo, OperationResult
from core.shell import SHELL, ShellError, powershell_quote
from core.winapi import is_admin

LOG = get_logger("dns")

_ADAPTER_QUERY = r"""
try {
    $rows = @()
    $configs = Get-NetIPConfiguration -ErrorAction Stop | Where-Object {
        $_.NetAdapter.Status -eq 'Up' -and
        $_.IPv4Address -ne $null -and
        $_.IPv4DefaultGateway -ne $null -and
        $_.InterfaceAlias -notmatch 'Loopback'
    }
    foreach ($config in $configs) {
        $dns = @(
            (Get-DnsClientServerAddress -InterfaceIndex $config.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses |
            Where-Object { $_ }
        )
        $ipif = Get-NetIPInterface -InterfaceIndex $config.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
        $rows += [pscustomobject]@{
            Name = [string]$config.InterfaceAlias
            Description = [string]$config.InterfaceDescription
            Index = [int]$config.InterfaceIndex
            DNS = @($dns)
            DHCP = if ($null -ne $ipif) { ([int]$ipif.Dhcp -eq 1) } else { $false }
            Address = [string]$config.IPv4Address[0].IPAddress
            Gateway = [string]$config.IPv4DefaultGateway[0].NextHop
            Status = [string]$config.NetAdapter.Status
        }
    }
    $rows | ConvertTo-Json -Depth 5 -Compress
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
"""

_DNS_FOR_ADAPTER = r"""
try {
    @((Get-DnsClientServerAddress -InterfaceIndex __INDEX__ -AddressFamily IPv4 -ErrorAction Stop).ServerAddresses) |
        ConvertTo-Json -Compress
} catch {
    Write-Error $_.Exception.Message
    exit 1
}
"""


def _as_list(value: object) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _validate_address(address: str) -> str:
    return str(ipaddress.ip_address(address))


class DNSManager:
    """Queries active adapters and applies DNS presets with netsh."""

    def __init__(self) -> None:
        self._providers = DNS_PROVIDER_BY_KEY

    # ------------------------------------------------------------------
    def list_active_adapters(self) -> list[AdapterInfo]:
        data = SHELL.powershell_json(_ADAPTER_QUERY, label="List network adapters")
        rows = _as_list(data)
        adapters: list[AdapterInfo] = []
        for row in rows:
            if not isinstance(row, dict):
                continue
            try:
                index = int(row.get("Index") or 0)
            except (TypeError, ValueError):
                index = 0
            if not index:
                continue
            adapters.append(
                AdapterInfo(
                    name=str(row.get("Name") or "Unknown"),
                    description=str(row.get("Description") or ""),
                    index=index,
                    dns_servers=[
                        str(item) for item in _as_list(row.get("DNS")) if str(item).strip()
                    ],
                    dhcp_enabled=bool(row.get("DHCP")),
                    ipv4_address=str(row.get("Address") or ""),
                    gateway=str(row.get("Gateway") or ""),
                    status=str(row.get("Status") or "Up"),
                )
            )
        adapters.sort(key=lambda adapter: adapter.name.lower())
        return adapters

    def get_dns_servers(self, adapter: AdapterInfo) -> list[str]:
        script = _DNS_FOR_ADAPTER.replace("__INDEX__", str(int(adapter.index)))
        data = SHELL.powershell_json(script, label=f"DNS for {adapter.name}")
        return [str(item) for item in _as_list(data) if str(item).strip()]

    # ------------------------------------------------------------------
    def set_provider(
        self,
        adapter: AdapterInfo,
        provider_key: str,
    ) -> OperationResult:
        provider = self._providers.get(provider_key)
        if provider is None:
            return OperationResult.error(f"Unknown DNS provider: {provider_key}")
        if not is_admin():
            return OperationResult.error("Administrator rights are required to change DNS.")
        return self._apply_provider(adapter, provider)

    def reset_to_dhcp(self, adapter: AdapterInfo) -> OperationResult:
        if not is_admin():
            return OperationResult.error("Administrator rights are required to change DNS.")

        details: list[str] = []
        errors: list[str] = []
        for family in ("ipv4", "ipv6"):
            result = SHELL.netsh(
                [
                    "interface",
                    family,
                    "set",
                    "dnsservers",
                    f"name={adapter.name}",
                    "source=dhcp",
                ],
                label=f"Reset {family} DNS",
            )
            if result.ok:
                details.append(f"{family.upper()}: automatic (DHCP).")
            else:
                errors.append(f"{family.upper()}: {result.error_text}")

        SHELL.ipconfig("/flushdns", timeout=15)
        LOG.info("Reset DNS to DHCP on %s", adapter.name)
        if errors and len(errors) == 2:
            return OperationResult.error(
                f"Could not reset DNS for {adapter.name}.",
                errors,
            )
        message = f"DNS reset to automatic on {adapter.name}."
        if errors:
            message += " Some address families could not be changed."
        return OperationResult.ok(message, details + errors)

    # ------------------------------------------------------------------
    def apply_to_active(self, provider_key: str) -> OperationResult:
        provider = self._providers.get(provider_key)
        if provider is None:
            return OperationResult.error(f"Unknown DNS provider: {provider_key}")
        if not is_admin():
            return OperationResult.error("Administrator rights are required to change DNS.")
        try:
            adapters = self.list_active_adapters()
        except ShellError as exc:
            return OperationResult.error("Could not enumerate network adapters.", [str(exc)])
        if not adapters:
            return OperationResult.ok(
                "No active internet adapter was found.",
                ["Connect to a network and try again."],
                skipped=True,
            )

        details: list[str] = []
        failures = 0
        for adapter in adapters:
            result = self._apply_provider(adapter, provider)
            details.extend(result.details or [result.message])
            if not result.success:
                failures += 1
        if failures == len(adapters):
            return OperationResult.error(
                f"DNS could not be changed on any active adapter ({failures}).",
                details,
            )
        message = f"{provider.short_name} DNS applied to {len(adapters) - failures}/{len(adapters)} adapter(s)."
        if failures:
            message += " Some adapters could not be updated."
        return OperationResult(
            success=failures == 0,
            message=message,
            details=details,
        )

    # ------------------------------------------------------------------
    def _apply_provider(
        self,
        adapter: AdapterInfo,
        provider: DNSProvider,
    ) -> OperationResult:
        primary = _validate_address(provider.primary)
        secondary = _validate_address(provider.secondary)
        expected_v4 = {primary, secondary}
        details: list[str] = []
        errors: list[str] = []

        # Primary IPv4 resolver through netsh.
        primary_result = SHELL.netsh(
            [
                "interface",
                "ipv4",
                "set",
                "dnsservers",
                f"name={adapter.name}",
                "source=static",
                f"address={primary}",
                "register=primary",
                "validate=no",
            ],
            label=f"{provider.short_name} DNS primary",
        )
        if primary_result.ok:
            details.append(f"IPv4 primary → {primary}")
            # Add the secondary at index 2. Any legacy resolver remains at a
            # higher index and is normalised below.
            secondary_result = SHELL.netsh(
                [
                    "interface",
                    "ipv4",
                    "add",
                    "dnsservers",
                    f"name={adapter.name}",
                    f"address={secondary}",
                    "index=2",
                    "validate=no",
                ],
                label=f"{provider.short_name} DNS secondary",
            )
            if secondary_result.ok:
                details.append(f"IPv4 secondary → {secondary}")
            else:
                errors.append(f"IPv4 secondary: {secondary_result.error_text}")
        else:
            errors.append(f"IPv4 primary: {primary_result.error_text}")

        # Normalise with the PowerShell cmdlet when netsh left stale entries or
        # this adapter rejects one of the netsh operations. netsh remains the
        # primary path required by WinSentinel's network module.
        active: list[str] = []
        for attempt in range(3):
            try:
                active = self.get_dns_servers(adapter)
            except ShellError:
                active = []
            if set(active) == expected_v4:
                break
            if attempt < 2:
                time.sleep(0.25)

        if set(active) != expected_v4:
            LOG.debug(
                "Normalising DNS list on %s from %s to %s",
                adapter.name,
                active,
                sorted(expected_v4),
            )
            fallback = self._set_with_powershell(adapter, provider.ipv4_servers, "IPv4")
            if fallback.success:
                details.append("Normalised the resolver list with the PowerShell fallback.")
                details.extend(fallback.details)
                errors.clear()
                for attempt in range(3):
                    try:
                        active = self.get_dns_servers(adapter)
                    except ShellError:
                        active = []
                    if set(active) == expected_v4:
                        break
                    if attempt < 2:
                        time.sleep(0.25)
            else:
                errors.extend(fallback.details)

        # IPv6 is best-effort: some adapters have IPv6 disabled.
        if provider.ipv6_servers:
            v6_primary = _validate_address(provider.ipv6_primary or "")
            v6_secondary = (
                _validate_address(provider.ipv6_secondary)
                if provider.ipv6_secondary
                else ""
            )
            v6_result = SHELL.netsh(
                [
                    "interface",
                    "ipv6",
                    "set",
                    "dnsservers",
                    f"name={adapter.name}",
                    "source=static",
                    f"address={v6_primary}",
                    "register=primary",
                    "validate=no",
                ],
                label=f"{provider.short_name} IPv6 DNS",
            )
            if v6_result.ok:
                details.append(f"IPv6 primary → {v6_primary}")
                if v6_secondary:
                    v6_secondary_result = SHELL.netsh(
                        [
                            "interface",
                            "ipv6",
                            "add",
                            "dnsservers",
                            f"name={adapter.name}",
                            f"address={v6_secondary}",
                            "index=2",
                            "validate=no",
                        ],
                        label=f"{provider.short_name} IPv6 secondary",
                    )
                    if v6_secondary_result.ok:
                        details.append(f"IPv6 secondary → {v6_secondary}")
                    else:
                        details.append("IPv6 secondary was not applied (adapter may have IPv6 disabled).")
            else:
                details.append("IPv6 DNS skipped (adapter may have IPv6 disabled).")

        SHELL.ipconfig("/flushdns", timeout=15)

        verified = primary in active
        if verified:
            details.append(f"Verified active DNS: {', '.join(active)}")
            LOG.info("DNS applied on %s: %s", adapter.name, ", ".join(active))
        else:
            errors.append("Windows did not report the new primary DNS after applying it.")

        if not verified:
            LOG.error("DNS change failed for %s: %s", adapter.name, " | ".join(errors))
            return OperationResult.error(
                f"Could not apply {provider.short_name} DNS to {adapter.name}.",
                errors + details,
            )
        if set(active) != expected_v4 or errors:
            return OperationResult(
                success=True,
                message=f"{provider.short_name} DNS partially applied to {adapter.name}.",
                details=details + errors,
            )
        return OperationResult.ok(
            f"{provider.short_name} DNS applied to {adapter.name}.",
            details,
        )

    def _set_with_powershell(
        self,
        adapter: AdapterInfo,
        servers: Iterable[str],
        family: str,
    ) -> OperationResult:
        addresses = ", ".join(powershell_quote(_validate_address(item)) for item in servers)
        script = (
            f"Set-DnsClientServerAddress -InterfaceIndex {int(adapter.index)} "
            f"-ServerAddresses @({addresses}) -ErrorAction Stop"
        )
        result = SHELL.powershell(script, label=f"{family} DNS fallback")
        if result.ok:
            LOG.info("PowerShell DNS fallback succeeded on %s", adapter.name)
            return OperationResult.ok(
                f"{family} DNS set with the PowerShell fallback.",
                [f"{family} → {', '.join(servers)}"],
            )
        return OperationResult.error(
            f"{family} PowerShell fallback failed.",
            [result.error_text],
        )


def provider_choices() -> list[DNSProvider]:
    return list(DNS_PROVIDER_BY_KEY.values())
