"""Command-shape tests for the firewall control plane."""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from core.firewall_manager import FirewallManager
from core.models import FirewallProfile
from core.shell import SHELL


def profiles(enabled: bool = True) -> list[FirewallProfile]:
    return [
        FirewallProfile(name, enabled, "Not configured", "Not configured")
        for name in ("Domain", "Private", "Public")
    ]


class FirewallCommandTests(unittest.TestCase):
    def test_all_profiles_use_enum_friendly_enabled_literals(self) -> None:
        for enabled, expected in ((True, "-Enabled True"), (False, "-Enabled False")):
            with self.subTest(enabled=enabled):
                with (
                    patch("core.firewall_manager.is_admin", return_value=True),
                    patch.object(
                        SHELL,
                        "powershell",
                        return_value=SimpleNamespace(ok=True, error_text=""),
                    ) as powershell,
                    patch.object(
                        FirewallManager,
                        "get_profiles",
                        return_value=profiles(enabled),
                    ),
                ):
                    result = FirewallManager().set_all_enabled(enabled)
                self.assertTrue(result.success)
                self.assertIn(expected, powershell.call_args.args[0])
                self.assertNotIn("$true", powershell.call_args.args[0])
                self.assertNotIn("$false", powershell.call_args.args[0])

    def test_single_profile_uses_enum_friendly_literal(self) -> None:
        with (
            patch("core.firewall_manager.is_admin", return_value=True),
            patch.object(
                SHELL,
                "powershell",
                return_value=SimpleNamespace(ok=True, error_text=""),
            ) as powershell,
            patch.object(
                FirewallManager,
                "get_profiles",
                return_value=profiles(True),
            ),
        ):
            result = FirewallManager().set_profile_enabled("Domain", True)
        self.assertTrue(result.success)
        self.assertIn("-Enabled True", powershell.call_args.args[0])
