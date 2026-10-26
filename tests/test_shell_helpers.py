"""Tests for hardened shell helpers and shared value coercion."""

from __future__ import annotations

import json
import unittest

from core.dns_manager import _as_list as dns_as_list
from core.dns_manager import _validate_address
from core.firewall_manager import _bool, _enum_label, _INBOUND_MAP, status_label
from core.shell import parse_json_output, powershell_quote


class ShellHelperTests(unittest.TestCase):
    def test_powershell_quote(self) -> None:
        self.assertEqual(powershell_quote("plain"), "'plain'")
        self.assertEqual(powershell_quote("O'Brien"), "'O''Brien'")
        self.assertEqual(powershell_quote(42), "'42'")

    def test_parse_json_tolerates_bom_and_noise(self) -> None:
        self.assertEqual(parse_json_output('\ufeff{"a": 1}'), {"a": 1})
        self.assertEqual(parse_json_output('warning\n[1, 2]'), [1, 2])
        self.assertEqual(parse_json_output('noise\n{"ok": true}\n'), {"ok": True})

    def test_parse_json_empty_and_null(self) -> None:
        self.assertIsNone(parse_json_output(""))
        self.assertIsNone(parse_json_output("   "))
        self.assertIsNone(parse_json_output("null"))

    def test_parse_json_rejects_garbage(self) -> None:
        with self.assertRaises(json.JSONDecodeError):
            parse_json_output("this is not json")


class DnsHelperTests(unittest.TestCase):
    def test_as_list(self) -> None:
        self.assertEqual(dns_as_list(None), [])
        self.assertEqual(dns_as_list("1.1.1.1"), ["1.1.1.1"])
        values = ["1.1.1.1", "1.0.0.1"]
        self.assertIs(dns_as_list(values), values)

    def test_validate_address(self) -> None:
        self.assertEqual(_validate_address("1.1.1.1"), "1.1.1.1")
        self.assertEqual(
            _validate_address("2606:4700:4700:0:0:0:0:1111"),
            "2606:4700:4700::1111",
        )
        with self.assertRaises(ValueError):
            _validate_address("999.1.1.1")
        with self.assertRaises(ValueError):
            _validate_address("not-an-ip")


class FirewallHelperTests(unittest.TestCase):
    def test_bool_coercion(self) -> None:
        for value in (True, 1, 1.0, "true", "TRUE", "yes", "enabled", "1"):
            self.assertTrue(_bool(value), repr(value))
        for value in (False, 0, "false", "no", "disabled", "random"):
            self.assertFalse(_bool(value), repr(value))

    def test_enum_label(self) -> None:
        self.assertEqual(_enum_label(2, _INBOUND_MAP), "Block")
        self.assertEqual(_enum_label("2", _INBOUND_MAP), "Block")
        self.assertEqual(_enum_label(1, _INBOUND_MAP), "Allow")
        self.assertEqual(_enum_label("Block", _INBOUND_MAP), "Block")
        self.assertEqual(_enum_label("Custom", _INBOUND_MAP), "Custom")

    def test_status_label(self) -> None:
        self.assertEqual(status_label(True), "Active")
        self.assertEqual(status_label(False), "Disabled")


if __name__ == "__main__":
    unittest.main()
