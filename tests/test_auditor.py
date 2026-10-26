"""Parsing and audit-decision tests using deterministic fake shell output."""

from __future__ import annotations

import unittest
from dataclasses import dataclass
from types import SimpleNamespace
from unittest.mock import patch

from core.auditor import (
    Auditor,
    WifiInfo,
    assess_wifi,
    classify_dns_servers,
    parse_wifi_interfaces,
)
from core.constants import BROWSER_BY_KEY
from core.models import Finding, Status
from core.policy_manager import BrowserPolicyState, ForcedExtension


@dataclass
class FakeResult:
    stdout: str = ""
    stderr: str = ""
    ok: bool = True
    error_text: str = ""


class FakeShell:
    def __init__(self, json_data=None, netsh_output: str = "") -> None:
        self.json_data = json_data
        self.netsh_output = netsh_output

    def powershell_json(self, script: str, *, timeout=None, label: str = ""):
        if isinstance(self.json_data, Exception):
            raise self.json_data
        return self.json_data

    def netsh(self, arguments, *, timeout: int = 30, label: str = "netsh"):
        return FakeResult(stdout=self.netsh_output)


WIFI_SAMPLE = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    GUID                   : 11111111-2222-3333-4444-555555555555
    State                  : connected
    SSID                   : Office-5G
    BSSID                  : aa:bb:cc:dd:ee:ff
    Network type           : Infrastructure
    Radio type             : 802.11ax
    Authentication         : WPA3-Personal
    Cipher                 : CCMP
    Connection mode        : Auto Connect
    Signal                 : 88%
    Profile                : Office-5G
"""

WIFI_DISCONNECTED = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    State                  : disconnected
    Radio status           : Hardware On
                             Software On
"""

WIFI_WPS_ENABLED = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    State                  : connected
    SSID                   : OldRouter
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    WPS                    : Enabled
    Signal                 : 51%
"""

WIFI_LOCALIZED = """
Sistemde 1 arabirim var:

    Ad                     : Wi-Fi
    Durum                  : connected
    SSID                   : Ev-Agi
    Kimlik Doğrulama       : WPA2-Kişisel
    Şifre                  : CCMP
    Sinyal                 : 72%
"""


class WifiParserTests(unittest.TestCase):
    def test_connected_interface(self) -> None:
        info = parse_wifi_interfaces(WIFI_SAMPLE)
        self.assertTrue(info.available)
        self.assertTrue(info.connected)
        self.assertEqual(info.interface_name, "Wi-Fi")
        self.assertEqual(info.ssid, "Office-5G")
        self.assertEqual(info.authentication, "WPA3-Personal")
        self.assertEqual(info.cipher, "CCMP")
        self.assertEqual(info.signal, "88%")
        self.assertEqual(info.wps_status, "not_exposed")

    def test_disconnected_is_not_treated_as_connected(self) -> None:
        info = parse_wifi_interfaces(WIFI_DISCONNECTED)
        self.assertTrue(info.available)
        self.assertFalse(info.connected)
        self.assertEqual(info.ssid, "")

    def test_no_wireless_interface(self) -> None:
        info = parse_wifi_interfaces("There is no wireless interface on the system.")
        self.assertFalse(info.available)
        self.assertFalse(info.connected)

    def test_wps_state_is_detected(self) -> None:
        info = parse_wifi_interfaces(WIFI_WPS_ENABLED)
        self.assertTrue(info.connected)
        self.assertEqual(info.wps_status, "enabled")

    def test_localized_labels(self) -> None:
        info = parse_wifi_interfaces(WIFI_LOCALIZED)
        self.assertTrue(info.connected)
        self.assertEqual(info.ssid, "Ev-Agi")
        self.assertEqual(info.authentication, "WPA2-Kişisel")
        self.assertEqual(info.cipher, "CCMP")

    def test_empty_output(self) -> None:
        info = parse_wifi_interfaces("")
        self.assertFalse(info.available)
        self.assertEqual(info.raw_error, "No WLAN output.")


class WifiAssessmentTests(unittest.TestCase):
    def test_wpa3_and_wpa2_pass(self) -> None:
        for auth, cipher in (
            ("WPA3-Personal", "CCMP"),
            ("WPA2-Personal", "CCMP"),
            ("WPA2-Enterprise", "GCMP"),
        ):
            status, _summary, _detail = assess_wifi(
                WifiInfo(True, True, authentication=auth, cipher=cipher)
            )
            self.assertIs(status, Status.PASS, auth)

    def test_open_and_wep_fail(self) -> None:
        for auth, cipher in (("Open", "None"), ("WEP", "WEP"), ("WPA-Personal", "")):
            status, _summary, _detail = assess_wifi(
                WifiInfo(True, True, authentication=auth, cipher=cipher)
            )
            self.assertIs(status, Status.FAIL, auth)

    def test_tkip_is_advisory(self) -> None:
        status, _summary, detail = assess_wifi(
            WifiInfo(True, True, authentication="WPA2-Personal", cipher="TKIP")
        )
        self.assertIs(status, Status.WARN)
        self.assertIn("TKIP", detail)

    def test_wps_enabled_fails(self) -> None:
        status, summary, _detail = assess_wifi(
            WifiInfo(
                True,
                True,
                authentication="WPA2-Personal",
                cipher="CCMP",
                wps_status="enabled",
            )
        )
        self.assertIs(status, Status.FAIL)
        self.assertIn("WPS", summary)

    def test_disconnected_and_unavailable_are_info(self) -> None:
        disconnected = assess_wifi(WifiInfo(True, False))
        self.assertIs(disconnected[0], Status.INFO)
        unavailable = assess_wifi(WifiInfo(False, False))
        self.assertIs(unavailable[0], Status.INFO)

    def test_unknown_encryption_is_advisory(self) -> None:
        status, _summary, _detail = assess_wifi(
            WifiInfo(True, True, authentication="SAE", cipher="CCMP")
        )
        self.assertIs(status, Status.WARN)


class DnsClassificationTests(unittest.TestCase):
    def test_known_providers(self) -> None:
        secure, names = classify_dns_servers(["1.1.1.1", "1.0.0.1"])
        self.assertTrue(secure)
        self.assertEqual(names, ["Cloudflare"])

        secure, names = classify_dns_servers(["8.8.8.8", "9.9.9.9"])
        self.assertTrue(secure)
        self.assertEqual(names, ["Google Public DNS", "Quad9"])

    def test_unknown_provider_fails(self) -> None:
        secure, names = classify_dns_servers(["1.1.1.1", "203.0.113.9"])
        self.assertFalse(secure)
        self.assertEqual(names, ["Cloudflare"])

    def test_empty_list(self) -> None:
        self.assertEqual(classify_dns_servers([]), (False, []))
        self.assertEqual(classify_dns_servers(["", "  "]), (False, []))


class SystemCheckTests(unittest.TestCase):
    def test_firewall_all_profiles_enabled(self) -> None:
        rows = [
            {
                "Name": name,
                "Enabled": True,
                "DefaultInboundAction": 2,
                "DefaultOutboundAction": 1,
            }
            for name in ("Domain", "Private", "Public")
        ]
        with patch("core.auditor.SHELL", FakeShell(json_data=rows)):
            finding = Auditor().audit_firewall()
        self.assertIs(finding.status, Status.PASS)
        self.assertIn("inbound blocked", finding.summary)

    def test_firewall_reports_disabled_profile(self) -> None:
        rows = [
            {"Name": "Domain", "Enabled": False, "DefaultInboundAction": 2},
            {"Name": "Private", "Enabled": True, "DefaultInboundAction": 2},
            {"Name": "Public", "Enabled": True, "DefaultInboundAction": 2},
        ]
        with patch("core.auditor.SHELL", FakeShell(json_data=rows)):
            finding = Auditor().audit_firewall()
        self.assertIs(finding.status, Status.FAIL)
        self.assertIn("2/3", finding.summary)
        self.assertIn("Domain", finding.detail)

    def test_firewall_accepts_string_enum_values(self) -> None:
        rows = [
            {
                "Name": name,
                "Enabled": True,
                "DefaultInboundAction": "Block",
                "DefaultOutboundAction": "Allow",
            }
            for name in ("Domain", "Private", "Public")
        ]
        with patch("core.auditor.SHELL", FakeShell(json_data=rows)):
            finding = Auditor().audit_firewall()
        self.assertIs(finding.status, Status.PASS)
        self.assertIn("inbound blocked", finding.summary)

    def test_defender_status(self) -> None:
        data = {
            "available": True,
            "antivirus": True,
            "realtime": True,
            "am_service": True,
            "tamper": "Windows Defender",
            "signature_version": "1.415.0.0",
            "signature_age": 2,
        }
        with patch("core.auditor.SHELL", FakeShell(json_data=data)):
            finding = Auditor().audit_defender()
        self.assertIs(finding.status, Status.PASS)
        self.assertIn("Real-time protection is active", finding.summary)

    def test_defender_realtime_disabled(self) -> None:
        data = {
            "available": True,
            "antivirus": True,
            "realtime": False,
            "am_service": True,
            "signature_age": 1,
        }
        with patch("core.auditor.SHELL", FakeShell(json_data=data)):
            finding = Auditor().audit_defender()
        self.assertIs(finding.status, Status.FAIL)
        self.assertIn("Real-time", finding.summary)

    def test_dns_secure_and_unknown(self) -> None:
        secure_rows = [
            {
                "Name": "Ethernet",
                "DNS": ["1.1.1.1", "1.0.0.1"],
                "DNS6": [],
                "DHCP": False,
            }
        ]
        with patch("core.auditor.SHELL", FakeShell(json_data=secure_rows)):
            secure = Auditor().audit_dns()
        self.assertIs(secure.status, Status.PASS)
        self.assertIn("Cloudflare", secure.summary)

        unknown_rows = [
            {"Name": "Ethernet", "DNS": ["203.0.113.9"], "DNS6": [], "DHCP": False}
        ]
        with patch("core.auditor.SHELL", FakeShell(json_data=unknown_rows)):
            unknown = Auditor().audit_dns()
        self.assertIs(unknown.status, Status.WARN)
        self.assertIn("unverified", unknown.summary)

        with patch("core.auditor.SHELL", FakeShell(json_data=[])):
            missing = Auditor().audit_dns()
        self.assertIs(missing.status, Status.INFO)
        self.assertEqual(missing.weight, 0.0)

    def test_wifi_audit_uses_netsh_output(self) -> None:
        with patch("core.auditor.SHELL", FakeShell(netsh_output=WIFI_SAMPLE)):
            finding = Auditor().audit_wifi()
        self.assertIs(finding.status, Status.PASS)
        self.assertEqual(finding.evidence["ssid"], "Office-5G")

    def test_browser_policy_compliance(self) -> None:
        browser = BROWSER_BY_KEY["chrome"]
        adblock, privacy = browser.extensions
        entries = [
            ForcedExtension(
                browser.key,
                "HKLM",
                "1",
                f"{adblock.extension_id};{browser.update_url}",
                adblock.extension_id,
                adblock.name,
            ),
            ForcedExtension(
                browser.key,
                "HKLM",
                "2",
                f"{privacy.extension_id};{browser.update_url}",
                privacy.extension_id,
                privacy.name,
            ),
        ]
        manager = SimpleNamespace(
            get_all_browser_states=lambda: [
                BrowserPolicyState(browser=browser, installed=True, entries=entries)
            ],
            get_uac_state=lambda: None,
        )
        finding = Auditor(policy_manager=manager).audit_browser_privacy()
        self.assertIs(finding.status, Status.PASS)

        manager.get_all_browser_states = lambda: [
            BrowserPolicyState(browser=browser, installed=True, entries=[])
        ]
        finding = Auditor(policy_manager=manager).audit_browser_privacy()
        self.assertIs(finding.status, Status.FAIL)


class ScanResilienceTests(unittest.TestCase):
    def test_broken_check_does_not_abort_the_scan(self) -> None:
        class StubAuditor(Auditor):
            def audit_defender(self) -> Finding:
                return Finding("defender", "Defender", Status.PASS, "ok")

            def audit_firewall(self) -> Finding:
                raise RuntimeError("simulated failure")

            def audit_dns(self) -> Finding:
                return Finding("dns", "DNS", Status.PASS, "ok")

            def audit_wifi(self) -> Finding:
                return Finding("wifi", "Wi-Fi", Status.INFO, "wired", weight=0.0)

            def audit_browser_privacy(self) -> Finding:
                return Finding("browser", "Browser", Status.PASS, "ok")

            def audit_uac(self) -> Finding:
                return Finding("uac", "UAC", Status.PASS, "ok")

        progress: list[tuple[int, int, str]] = []
        report = StubAuditor().scan(
            progress=lambda done, total, label: progress.append((done, total, label))
        )
        firewall = report.finding("firewall")
        self.assertIsNotNone(firewall)
        self.assertIs(firewall.status, Status.UNKNOWN)
        self.assertEqual(len(report.findings), 6)
        self.assertTrue(report.errors)
        self.assertIn("simulated failure", report.errors[0])
        self.assertEqual(progress[-1][0], 6)


if __name__ == "__main__":
    unittest.main()
