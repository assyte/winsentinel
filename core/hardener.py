"""One-click remediation pipeline that repairs failed audit findings."""

from __future__ import annotations

from core.auditor import Auditor
from core.constants import BROWSERS
from core.dns_manager import DNSManager
from core.firewall_manager import FirewallManager
from core.logger import get_logger
from core.models import AuditReport, HardenResult, OperationResult, Status
from core.policy_manager import PolicyManager
from core.winapi import is_admin

LOG = get_logger("hardener")


class Hardener:
    """Applies safe, reversible-or-documented fixes for audit findings."""

    def __init__(
        self,
        auditor: Auditor | None = None,
        dns_manager: DNSManager | None = None,
        firewall_manager: FirewallManager | None = None,
        policy_manager: PolicyManager | None = None,
    ) -> None:
        self.auditor = auditor or Auditor()
        self.dns_manager = dns_manager or DNSManager()
        self.firewall_manager = firewall_manager or FirewallManager()
        self.policy_manager = policy_manager or self.auditor.policy_manager

    def harden(self, report: AuditReport | None = None) -> HardenResult:
        result = HardenResult()
        if not is_admin():
            result.steps.append(
                OperationResult.error(
                    "Administrator rights are required. Restart WinSentinel elevated."
                )
            )
            return result

        LOG.info("One-click hardening started")
        finding_map = {finding.key: finding for finding in report.findings} if report else {}

        result.steps.append(self._harden_defender(finding_map.get("defender")))
        result.steps.append(self._harden_firewall(finding_map.get("firewall")))
        result.steps.append(self._harden_dns(finding_map.get("dns")))
        result.steps.append(self._harden_browser(finding_map.get("browser")))
        result.steps.append(self._harden_uac(finding_map.get("uac")))
        result.steps.append(self._wifi_advice(finding_map.get("wifi")))

        result.reboot_required = any(step.reboot_required for step in result.steps)
        result.warnings = [
            step.message
            for step in result.steps
            if not step.success and not step.skipped
        ]
        LOG.info(
            "Hardening finished: %s step(s) applied, %s failed, reboot=%s",
            result.changed,
            sum(1 for step in result.steps if not step.success and not step.skipped),
            result.reboot_required,
        )
        return result

    # ------------------------------------------------------------------
    def _harden_defender(self, finding) -> OperationResult:
        if finding is not None and finding.status is Status.PASS:
            return self._skipped("Windows Defender is already protected.")
        status = self.firewall_manager.get_defender_status()
        if not status.available:
            return OperationResult.error(
                "Windows Defender is unavailable. Install or repair Microsoft Defender.",
                [status.raw_error],
            )
        if status.realtime_enabled and status.antivirus_enabled:
            return self._skipped("Windows Defender is already protected.")
        LOG.info("Enabling Defender real-time protection")
        result = self.firewall_manager.set_realtime_protection(True)
        if not result.success:
            result.details.append(
                "If Tamper Protection is blocking this, enable real-time protection in Windows Security."
            )
        return result

    def _harden_firewall(self, finding) -> OperationResult:
        if finding is not None and finding.status is Status.PASS:
            return self._skipped("Windows Firewall is already hardened.")
        details: list[str] = []
        success = True
        profiles = self.firewall_manager.get_profiles()
        if not all(profile.enabled for profile in profiles):
            LOG.info("Enabling all firewall profiles")
            enable_result = self.firewall_manager.set_all_enabled(True)
            details.extend(enable_result.details or [enable_result.message])
            success = success and enable_result.success
        else:
            details.append("All firewall profiles already enabled.")

        if not all(profile.inbound_is_blocked for profile in profiles):
            LOG.info("Setting inbound firewall default to Block")
            inbound_result = self.firewall_manager.block_inbound(True)
            details.extend(inbound_result.details or [inbound_result.message])
            success = success and inbound_result.success
        else:
            details.append("Inbound traffic already blocked by default.")

        if success:
            return OperationResult.ok(
                "Windows Firewall profiles are enabled with inbound blocking.",
                details,
            )
        return OperationResult.error(
            "Some firewall settings could not be applied.",
            details,
        )

    def _harden_dns(self, finding) -> OperationResult:
        if finding is not None and finding.status is Status.PASS:
            return self._skipped("A secure DNS resolver is already configured.")
        LOG.info("Applying Cloudflare DNS to active adapters")
        return self.dns_manager.apply_to_active("cloudflare")

    def _harden_browser(self, finding) -> OperationResult:
        if finding is not None and finding.status is Status.PASS:
            return self._skipped("Browser ad blockers are already enforced.")
        states = self.policy_manager.get_all_browser_states()
        installed = [state.browser for state in states if state.installed]
        if not installed:
            return OperationResult.ok(
                "No supported browser was detected; browser policy was skipped.",
                ["Chrome and Microsoft Edge were not found."],
                skipped=True,
            )
        LOG.info("Enforcing ad blocker policies for %s", ", ".join(browser.name for browser in installed))
        return self.policy_manager.enforce_browser_extensions(installed)

    def _harden_uac(self, finding) -> OperationResult:
        if finding is not None and finding.status is Status.PASS:
            return self._skipped("UAC already uses the recommended level.")
        LOG.info("Restoring recommended UAC policy")
        return self.policy_manager.harden_uac()

    def _wifi_advice(self, finding) -> OperationResult:
        if finding is None or finding.status in (Status.PASS, Status.INFO):
            return self._skipped("No Wi-Fi remediation is needed.")
        return OperationResult.ok(
            "Wi-Fi encryption and WPS are router settings and cannot be changed from Windows.",
            [
                "Open Security Tools → Wi-Fi Security Helper for a router checklist.",
                finding.recommendation,
            ],
            skipped=True,
        )

    @staticmethod
    def _skipped(message: str) -> OperationResult:
        return OperationResult.ok(message, skipped=True)
