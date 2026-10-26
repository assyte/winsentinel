"""Tests for the passphrase generator and Wi-Fi helper content."""

from __future__ import annotations

import math
import unittest

from core.security_tools import (
    ROUTER_CHECKLIST,
    PassphraseGenerator,
    build_wifi_hardening_script,
    current_wifi_help_text,
)


def synthetic_wordlist(size: int = 256) -> tuple[str, ...]:
    return tuple(f"word{index}" for index in range(size))


class PassphraseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.generator = PassphraseGenerator(synthetic_wordlist())

    def test_default_shape_and_entropy(self) -> None:
        passphrase = self.generator.generate(7)
        self.assertEqual(passphrase.word_count, 7)
        self.assertEqual(len(passphrase.text.split(" ")), 8)  # 7 words + number
        self.assertEqual(passphrase.length, len(passphrase.text))
        # 7 * log2(256) + symbol + 3-digit number + case randomisation.
        expected = 7 * math.log2(256) + 3.585 + 9.814 + 2.0
        self.assertAlmostEqual(passphrase.entropy, expected, places=3)
        self.assertEqual(passphrase.strength, "Strong")

    def test_word_count_is_clamped(self) -> None:
        short = self.generator.generate(1)
        self.assertEqual(short.word_count, 4)
        self.assertEqual(len(short.text.split(" ")), 5)

        long = self.generator.generate(99)
        self.assertEqual(long.word_count, 12)
        self.assertEqual(len(long.text.split(" ")), 13)

    def test_optional_extras(self) -> None:
        passphrase = self.generator.generate(
            4,
            include_number=False,
            include_symbol=False,
        )
        self.assertEqual(passphrase.word_count, 4)
        self.assertEqual(len(passphrase.text.split(" ")), 4)
        self.assertAlmostEqual(passphrase.entropy, 4 * 8 + 2.0, places=3)
        self.assertEqual(passphrase.strength, "Weak")

    def test_passphrases_are_unique(self) -> None:
        values = {self.generator.generate(6).text for _ in range(25)}
        self.assertGreater(len(values), 20)

    def test_tiny_wordlist_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            PassphraseGenerator(("only", "two", "words"))

    def test_strength_boundaries(self) -> None:
        # 333-word list, 7 words, no extras and no extra case entropy is not
        # directly reachable, so verify through generated values instead.
        strong = PassphraseGenerator(synthetic_wordlist(1024)).generate(
            10, include_number=False, include_symbol=False
        )
        self.assertEqual(strong.strength, "Excellent")
        self.assertGreaterEqual(strong.entropy, 80)


class WifiHelperTests(unittest.TestCase):
    def test_script_contains_context_and_checklist(self) -> None:
        script = build_wifi_hardening_script(
            ssid="TestNet",
            authentication="WPA2-Personal",
            cipher="CCMP",
            gateway="192.168.1.1",
        )
        self.assertIn("TestNet", script)
        self.assertIn("WPA2-Personal / CCMP", script)
        self.assertIn('$gateway = "192.168.1.1"', script)
        self.assertIn('Start-Process "http://$gateway"', script)
        self.assertIn("netsh wlan show interfaces", script)
        self.assertIn("Disable WPS", script)
        self.assertIn("router firmware", script)
        self.assertIn("Start-Process", script)

    def test_script_handles_missing_context(self) -> None:
        script = build_wifi_hardening_script()
        self.assertIn("No active Wi-Fi association detected", script)
        self.assertIn("Client-negotiated security: unknown", script)
        self.assertIn('$gateway = ""', script)

    def test_checklist_and_help_text(self) -> None:
        self.assertGreaterEqual(len(ROUTER_CHECKLIST), 4)
        self.assertTrue(all(item.strip() for item in ROUTER_CHECKLIST))
        self.assertIn("router", current_wifi_help_text().lower())


if __name__ == "__main__":
    unittest.main()
