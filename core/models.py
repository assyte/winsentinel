"""Domain models shared by the audit and remediation engines."""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Status(str, Enum):
    """Result of a single security control check."""

    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    INFO = "info"
    UNKNOWN = "unknown"

    @property
    def score(self) -> float | None:
        if self is Status.PASS:
            return 100.0
        if self is Status.WARN:
            return 50.0
        if self is Status.UNKNOWN:
            return 35.0
        if self is Status.FAIL:
            return 0.0
        return None  # INFO does not affect the score.

    @property
    def is_issue(self) -> bool:
        return self in (Status.WARN, Status.FAIL, Status.UNKNOWN)


@dataclass(slots=True)
class Finding:
    """One audited security control."""

    key: str
    title: str
    status: Status
    summary: str
    detail: str = ""
    recommendation: str = ""
    fix_action: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    weight: float = 1.0

    @property
    def is_issue(self) -> bool:
        return self.status.is_issue


@dataclass(slots=True)
class AuditReport:
    """Aggregate result of a full security scan."""

    findings: list[Finding]
    started_at: datetime
    finished_at: datetime
    is_admin: bool
    hostname: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def score(self) -> int:
        weighted = 0.0
        total_weight = 0.0
        for finding in self.findings:
            value = finding.status.score
            if value is None or finding.weight <= 0:
                continue
            weighted += value * finding.weight
            total_weight += finding.weight
        if total_weight == 0:
            return 0
        return max(0, min(100, round(weighted / total_weight)))

    @property
    def counts(self) -> dict[str, int]:
        result = {"pass": 0, "warn": 0, "fail": 0, "info": 0, "unknown": 0}
        for finding in self.findings:
            result[finding.status.value] += 1
        return result

    @property
    def issues(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.is_issue]

    @property
    def risk_label(self) -> str:
        counts = self.counts
        if counts["fail"]:
            return "Action required"
        if counts["warn"] or counts["unknown"]:
            return "Almost secure"
        if counts["pass"]:
            return "Protected"
        return "Not scanned"

    @property
    def grade(self) -> str:
        score = self.score
        if score >= 90:
            return "Excellent"
        if score >= 75:
            return "Good"
        if score >= 60:
            return "Needs attention"
        if score >= 40:
            return "At risk"
        return "Critical"

    @property
    def grade_letter(self) -> str:
        score = self.score
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"

    @property
    def duration_seconds(self) -> float:
        return max(0.0, (self.finished_at - self.started_at).total_seconds())

    @property
    def headline(self) -> str:
        fail_count = self.counts["fail"]
        warn_count = self.counts["warn"] + self.counts["unknown"]
        if fail_count and warn_count:
            return f"{fail_count} critical and {warn_count} advisory issues found"
        if fail_count:
            return f"{fail_count} critical issue{'s' if fail_count != 1 else ''} found"
        if warn_count:
            return f"{warn_count} advisory issue{'s' if warn_count != 1 else ''} found"
        return "All core protections are enabled"

    def finding(self, key: str) -> Finding | None:
        return next((item for item in self.findings if item.key == key), None)


@dataclass(slots=True)
class OperationResult:
    """Result returned by a remediation or network operation."""

    success: bool
    message: str
    details: list[str] = field(default_factory=list)
    reboot_required: bool = False
    skipped: bool = False

    @classmethod
    def ok(
        cls,
        message: str,
        details: list[str] | None = None,
        reboot_required: bool = False,
        skipped: bool = False,
    ) -> "OperationResult":
        return cls(
            True,
            message,
            details or [],
            reboot_required=reboot_required,
            skipped=skipped,
        )

    @classmethod
    def error(
        cls,
        message: str,
        details: list[str] | None = None,
    ) -> "OperationResult":
        return cls(False, message, details or [])


@dataclass(slots=True)
class AdapterInfo:
    name: str
    description: str
    index: int
    dns_servers: list[str]
    dhcp_enabled: bool
    ipv4_address: str = ""
    gateway: str = ""
    status: str = "Up"


@dataclass(slots=True)
class FirewallProfile:
    name: str
    enabled: bool
    default_inbound: str
    default_outbound: str

    @property
    def inbound_is_blocked(self) -> bool:
        return self.default_inbound.lower() == "block"


@dataclass(slots=True)
class DefenderStatus:
    available: bool
    antivirus_enabled: bool = False
    realtime_enabled: bool = False
    am_service_enabled: bool = False
    tamper_protection: str = ""
    signature_version: str = ""
    signature_age_days: int | None = None
    raw_error: str = ""

    @property
    def healthy(self) -> bool:
        return self.available and self.antivirus_enabled and self.realtime_enabled


@dataclass(slots=True)
class UACState:
    enable_lua: int
    consent_prompt_behavior: int
    prompt_on_secure_desktop: int

    @property
    def enabled(self) -> bool:
        return self.enable_lua == 1

    @property
    def level_label(self) -> str:
        if self.enable_lua != 1:
            return "Disabled"
        if self.consent_prompt_behavior == 0:
            return "Elevate without prompting"
        if self.prompt_on_secure_desktop != 1:
            return "Prompting (secure desktop off)"
        return "Default / secure desktop"


@dataclass(slots=True)
class HardenResult:
    steps: list[OperationResult] = field(default_factory=list)
    reboot_required: bool = False
    warnings: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return bool(self.steps) and all(step.success or step.skipped for step in self.steps)

    @property
    def changed(self) -> int:
        return sum(1 for step in self.steps if step.success and not step.skipped)


def entropy_bits(word_count: int, wordlist_size: int, extras_bits: float = 0.0) -> float:
    """Approximate passphrase entropy in bits."""

    if word_count <= 0 or wordlist_size <= 1:
        return extras_bits
    return word_count * math.log2(wordlist_size) + extras_bits
