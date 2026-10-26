"""Tests for scoring, audit models, and entropy helpers."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta

from core.models import (
    AuditReport,
    DefenderStatus,
    Finding,
    FirewallProfile,
    HardenResult,
    OperationResult,
    Status,
    UACState,
    entropy_bits,
)


def make_report(*findings: Finding) -> AuditReport:
    started = datetime(2026, 1, 1, 12, 0, 0)
    return AuditReport(
        findings=list(findings),
        started_at=started,
        finished_at=started + timedelta(seconds=4),
        is_admin=True,
        hostname="TEST-PC",
    )


class StatusTests(unittest.TestCase):
    def test_status_scores(self) -> None:
        self.assertEqual(Status.PASS.score, 100.0)
        self.assertEqual(Status.WARN.score, 50.0)
        self.assertEqual(Status.UNKNOWN.score, 35.0)
        self.assertEqual(Status.FAIL.score, 0.0)
        self.assertIsNone(Status.INFO.score)

    def test_issue_classification(self) -> None:
        self.assertTrue(Status.WARN.is_issue)
        self.assertTrue(Status.FAIL.is_issue)
        self.assertTrue(Status.UNKNOWN.is_issue)
        self.assertFalse(Status.PASS.is_issue)
        self.assertFalse(Status.INFO.is_issue)


class AuditReportTests(unittest.TestCase):
    def test_weighted_score_ignores_info(self) -> None:
        report = make_report(
            Finding("a", "A", Status.PASS, "ok"),
            Finding("b", "B", Status.FAIL, "bad"),
            Finding("c", "C", Status.INFO, "note", weight=0.0),
        )
        self.assertEqual(report.score, 50)
        self.assertEqual(report.counts["pass"], 1)
        self.assertEqual(report.counts["fail"], 1)
        self.assertEqual(report.counts["info"], 1)
        self.assertEqual(report.grade, "At risk")
        self.assertEqual(report.risk_label, "Action required")

    def test_weights_change_the_score(self) -> None:
        report = make_report(
            Finding("a", "A", Status.PASS, "ok", weight=3.0),
            Finding("b", "B", Status.FAIL, "bad", weight=1.0),
        )
        self.assertEqual(report.score, 75)
        self.assertEqual(report.grade, "Good")
        self.assertEqual(report.grade_letter, "C")

    def test_perfect_and_empty_reports(self) -> None:
        perfect = make_report(Finding("a", "A", Status.PASS, "ok"))
        self.assertEqual(perfect.score, 100)
        self.assertEqual(perfect.headline, "All core protections are enabled")
        self.assertEqual(perfect.grade_letter, "A")

        empty = make_report()
        self.assertEqual(empty.score, 0)
        self.assertEqual(empty.headline, "All core protections are enabled")

    def test_headline_and_lookup(self) -> None:
        report = make_report(
            Finding("firewall", "Firewall", Status.FAIL, "off"),
            Finding("dns", "DNS", Status.WARN, "ISP"),
        )
        self.assertEqual(report.headline, "1 critical and 1 advisory issues found")
        self.assertIsNotNone(report.finding("dns"))
        self.assertIsNone(report.finding("missing"))

    def test_duration(self) -> None:
        report = make_report(Finding("a", "A", Status.PASS, "ok"))
        self.assertAlmostEqual(report.duration_seconds, 4.0)


class OperationResultTests(unittest.TestCase):
    def test_ok_and_error_helpers(self) -> None:
        ok = OperationResult.ok("done", ["detail"], reboot_required=True)
        self.assertTrue(ok.success)
        self.assertEqual(ok.message, "done")
        self.assertEqual(ok.details, ["detail"])
        self.assertTrue(ok.reboot_required)

        skipped = OperationResult.ok("nothing to do", skipped=True)
        self.assertTrue(skipped.success)
        self.assertTrue(skipped.skipped)

        error = OperationResult.error("failed", ["why"])
        self.assertFalse(error.success)
        self.assertEqual(error.details, ["why"])

    def test_harden_result_aggregates_steps(self) -> None:
        result = HardenResult(
            steps=[
                OperationResult.ok("changed"),
                OperationResult.ok("skipped", skipped=True),
            ]
        )
        self.assertTrue(result.success)
        self.assertEqual(result.changed, 1)

        failed = HardenResult(steps=[OperationResult.error("nope")])
        self.assertFalse(failed.success)

        empty = HardenResult()
        self.assertFalse(empty.success)


class EntropyTests(unittest.TestCase):
    def test_entropy_bits(self) -> None:
        self.assertEqual(entropy_bits(0, 100), 0.0)
        self.assertEqual(entropy_bits(4, 1), 0.0)
        self.assertAlmostEqual(entropy_bits(2, 4), 4.0)
        self.assertAlmostEqual(entropy_bits(2, 4, extras_bits=3.0), 7.0)


class UACStateTests(unittest.TestCase):
    def test_labels(self) -> None:
        self.assertEqual(UACState(0, 5, 1).level_label, "Disabled")
        self.assertEqual(
            UACState(1, 0, 1).level_label,
            "Elevate without prompting",
        )
        self.assertEqual(
            UACState(1, 5, 0).level_label,
            "Prompting (secure desktop off)",
        )
        self.assertEqual(
            UACState(1, 5, 1).level_label,
            "Default / secure desktop",
        )


class StatusObjectTests(unittest.TestCase):
    def test_defender_health(self) -> None:
        healthy = DefenderStatus(
            available=True,
            antivirus_enabled=True,
            realtime_enabled=True,
        )
        self.assertTrue(healthy.healthy)
        self.assertFalse(
            DefenderStatus(
                available=True,
                antivirus_enabled=True,
                realtime_enabled=False,
            ).healthy
        )
        self.assertFalse(
            DefenderStatus(
                available=False,
                antivirus_enabled=True,
                realtime_enabled=True,
            ).healthy
        )

    def test_firewall_inbound(self) -> None:
        self.assertTrue(
            FirewallProfile("Public", True, "Block", "Allow").inbound_is_blocked
        )
        self.assertFalse(
            FirewallProfile("Public", True, "Allow", "Allow").inbound_is_blocked
        )


if __name__ == "__main__":
    unittest.main()
