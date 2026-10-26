"""Offline cyber utilities: passphrase generation and Wi-Fi hardening help."""

from __future__ import annotations

import random
import secrets
from dataclasses import dataclass

from core.models import entropy_bits
from core.wordlist import WORDS

_SYMBOLS = ("!", "@", "#", "$", "%", "&", "*", "?", "+", "=", "-", "_")
_SEPARATOR = " "


@dataclass(slots=True)
class Passphrase:
    text: str
    word_count: int
    entropy: float
    wordlist_size: int

    @property
    def strength(self) -> str:
        if self.entropy >= 80:
            return "Excellent"
        if self.entropy >= 68:
            return "Strong"
        if self.entropy >= 55:
            return "Good"
        return "Weak"

    @property
    def length(self) -> int:
        return len(self.text)


class PassphraseGenerator:
    """Creates long, sentence-style passphrases using a CSPRNG."""

    def __init__(self, wordlist: tuple[str, ...] | None = None) -> None:
        self.words = tuple(wordlist or WORDS)
        if len(self.words) < 128:
            raise ValueError("Passphrase word list is unexpectedly small.")
        self._rng = random.SystemRandom()

    def generate(
        self,
        word_count: int = 7,
        *,
        include_number: bool = True,
        include_symbol: bool = True,
    ) -> Passphrase:
        word_count = max(4, min(12, int(word_count)))
        selected = self._rng.sample(self.words, k=min(word_count, len(self.words)))

        # Sentence-like mixed case: capitalise the opening word and one other.
        selected[0] = selected[0].capitalize()
        if len(selected) > 2:
            second_capital = self._rng.randrange(1, len(selected))
            selected[second_capital] = selected[second_capital].capitalize()

        extras_bits = 0.0
        if include_symbol:
            symbol = self._rng.choice(_SYMBOLS)
            symbol_index = self._rng.randrange(len(selected))
            selected[symbol_index] = f"{selected[symbol_index]}{symbol}"
            extras_bits += 3.585  # log2(12)

        if include_number:
            number = f"{secrets.randbelow(900) + 100}"
            number_index = self._rng.randrange(1, len(selected))
            selected.insert(number_index, number)
            extras_bits += 9.814  # log2(900)

        text = _SEPARATOR.join(selected)
        # Case randomisation adds a little entropy; report it conservatively.
        extras_bits += 2.0
        # Use the chosen word count, not the token count: the inserted number is
        # already accounted for in extras_bits.
        bits = entropy_bits(word_count, len(self.words), extras_bits)
        return Passphrase(
            text=text,
            word_count=word_count,
            entropy=bits,
            wordlist_size=len(self.words),
        )


ROUTER_CHECKLIST: tuple[str, ...] = (
    "Sign in to the router using its LAN address, then change the default admin password.",
    "Open Wireless Security and choose WPA3-Personal or WPA2-AES (CCMP).",
    "Avoid WEP, open networks, WPA1, and TKIP. Use a long unique Wi-Fi passphrase.",
    "Disable WPS entirely — both the PIN and push-button methods.",
    "Disable remote administration and UPnP unless you specifically need them.",
    "Install router firmware updates and turn off cloud/remote access you do not use.",
)


def build_wifi_hardening_script(
    *,
    ssid: str = "",
    authentication: str = "",
    cipher: str = "",
    gateway: str = "",
) -> str:
    """Build an honest, copyable PowerShell helper.

    WPS and WPA mode are router firmware settings. Windows exposes no supported
    netsh command that can change them, so the helper audits the client and
    opens the router console instead of pretending to disable WPS.
    """

    ssid_line = f"# Current SSID: {ssid}" if ssid else "# No active Wi-Fi association detected"
    security_line = (
        f"# Client-negotiated security: {authentication or 'unknown'}"
        f"{f' / {cipher}' if cipher else ''}"
    )
    gateway_value = gateway or ""
    return f"""# WinSentinel — Wi-Fi Security Helper
# Run in an elevated PowerShell window. Read-only except for opening the router UI.
{ssid_line}
{security_line}

Write-Host "`n[1] Wireless interface and negotiated security" -ForegroundColor Cyan
netsh wlan show interfaces

Write-Host "`n[2] Saved wireless profiles" -ForegroundColor Cyan
netsh wlan show profiles

Write-Host "`n[3] Current network profile" -ForegroundColor Cyan
Get-NetConnectionProfile | Format-Table Name, InterfaceAlias, NetworkCategory -AutoSize

# WPS and WPA2/WPA3 are configured in the router firmware. Windows has no
# supported netsh/PowerShell command to change those router-side settings.
$gateway = "{gateway_value}"
if (-not $gateway) {{
    $gateway = (Get-NetIPConfiguration |
        Where-Object {{ $_.IPv4DefaultGateway -ne $null }} |
        Select-Object -First 1 -ExpandProperty IPv4DefaultGateway).NextHop
}}
if ($gateway) {{
    Write-Host "`n[4] Opening router admin page: http://$gateway" -ForegroundColor Cyan
    Start-Process "http://$gateway"
}}

Write-Host @"

Router hardening checklist
--------------------------
1. Change the default router admin password.
2. Wireless security: WPA3-Personal or WPA2-AES (CCMP). Never WEP/open.
3. Disable WPS (PIN and push-button).
4. Use a long, unique Wi-Fi passphrase.
5. Disable remote management and unnecessary UPnP.
6. Install firmware updates.
"@ -ForegroundColor Yellow
"""


def current_wifi_help_text() -> str:
    return (
        "Wi-Fi encryption and WPS live on the router, not in Windows. "
        "Use the helper to inspect the active association and open your router."
    )
