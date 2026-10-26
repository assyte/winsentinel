"""Tests for browser policy parsing, compliance, and UAC rules."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from core.constants import BROWSER_BY_KEY
from core.models import UACState
from core.policy_manager import (
    BrowserPolicyState,
    ForcedExtension,
    PolicyManager,
    parse_force_value,
)


def forced(browser_key: str, extension_id: str, name: str = "Extension") -> ForcedExtension:
    return ForcedExtension(
        browser_key=browser_key,
        hive="HKLM",
        value_name="1",
        raw_value=f"{extension_id};https://example.test/crx",
        extension_id=extension_id,
        name=name,
    )


class ForceValueTests(unittest.TestCase):
    def test_id_and_update_url(self) -> None:
        self.assertEqual(
            parse_force_value(" cjpalhdlnbpafiamejdnhcphjbkeiagm ; https://x.test/crx "),
            ("cjpalhdlnbpafiamejdnhcphjbkeiagm", "https://x.test/crx"),
        )
        self.assertEqual(parse_force_value("ABC123"), ("abc123", ""))

    def test_forced_extension_property(self) -> None:
        entry = forced(
            "chrome",
            "cjpalhdlnbpafiamejdnhcphjbkeiagm",
            "uBlock Origin",
        )
        self.assertEqual(entry.update_url, "https://example.test/crx")
        self.assertEqual(entry.extension_id, "cjpalhdlnbpafiamejdnhcphjbkeiagm")


class BrowserStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.chrome = BROWSER_BY_KEY["chrome"]
        self.ublock, self.badger = self.chrome.extensions

    def test_no_entries_is_not_compliant(self) -> None:
        state = BrowserPolicyState(browser=self.chrome, installed=True)
        self.assertFalse(state.compliant)
        self.assertFalse(state.adblock_found)
        self.assertFalse(state.privacy_found)
        self.assertEqual(state.extension_names, [])

    def test_only_adblock_is_partial(self) -> None:
        state = BrowserPolicyState(
            browser=self.chrome,
            installed=True,
            entries=[forced("chrome", self.ublock.extension_id, "uBlock Origin")],
        )
        self.assertTrue(state.adblock_found)
        self.assertFalse(state.privacy_found)
        self.assertFalse(state.compliant)
        self.assertEqual(state.extension_names, ["uBlock Origin"])

    def test_both_blockers_is_compliant(self) -> None:
        state = BrowserPolicyState(
            browser=self.chrome,
            installed=True,
            entries=[
                forced("chrome", self.ublock.extension_id, "uBlock Origin"),
                forced("chrome", self.badger.extension_id, "Privacy Badger"),
            ],
        )
        self.assertTrue(state.compliant)
        self.assertEqual(state.extension_ids, set(self.chrome.extension_ids))
        self.assertEqual(state.extension_names, ["uBlock Origin", "Privacy Badger"])

    def test_alternative_managed_ids_count(self) -> None:
        state = BrowserPolicyState(
            browser=BROWSER_BY_KEY["edge"],
            installed=True,
            entries=[
                forced("edge", "ddkjiahejlhfcafbddmgiahcphecmpfh", "uBlock Origin Lite"),
                forced("edge", "mlomiejdfkolichcflejclcbmpeaniij", "Ghostery"),
            ],
        )
        self.assertTrue(state.compliant)


class UacRuleTests(unittest.TestCase):
    def test_compliant_state(self) -> None:
        self.assertTrue(PolicyManager.uac_is_compliant(UACState(1, 5, 1)))
        self.assertTrue(PolicyManager.uac_is_compliant(UACState(1, 2, 1)))

    def test_disabled_or_weakened_state(self) -> None:
        self.assertFalse(PolicyManager.uac_is_compliant(UACState(0, 5, 1)))
        self.assertFalse(PolicyManager.uac_is_compliant(UACState(1, 0, 1)))
        self.assertFalse(PolicyManager.uac_is_compliant(UACState(1, 5, 0)))


class AdminGuardTests(unittest.TestCase):
    def test_policy_writes_require_elevation(self) -> None:
        manager = PolicyManager()
        with patch("core.policy_manager.is_admin", return_value=False):
            enforce = manager.enforce_browser_extensions([BROWSER_BY_KEY["chrome"]])
            remove = manager.remove_browser_extensions([BROWSER_BY_KEY["chrome"]])
            uac = manager.harden_uac()

        for result in (enforce, remove, uac):
            self.assertFalse(result.success)
            self.assertIn("Administrator rights", result.message)


if __name__ == "__main__":
    unittest.main()
