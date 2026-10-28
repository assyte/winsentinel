"""Application-wide constants, colours, and security provider definitions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

APP_NAME: Final = "WinSentinel"
APP_TAGLINE: Final = "Your Windows security copilot"
APP_VERSION: Final = "1.1.1"

# ---------------------------------------------------------------------------
# Visual language — neutral graphite, muted by design, with light/dark modes
# ---------------------------------------------------------------------------
DARK_COLORS: Final[dict[str, str]] = {
    "bg": "#111317",
    "bg_elevated": "#15181c",
    "sidebar": "#15171a",
    "card": "#1a1d21",
    "card_hover": "#23272c",
    "card_muted": "#1f2227",
    "input": "#15171a",
    "border": "#292e34",
    "border_bright": "#3a414a",
    "text": "#f1f4f7",
    "text_muted": "#abb3bd",
    "text_dim": "#77808b",
    "accent": "#96a9bd",
    "accent_hover": "#b0c2d4",
    "accent_soft": "#27313a",
    "accent_text": "#12161b",
    "success": "#6fbf94",
    "success_soft": "#16291f",
    "warning": "#d9a85c",
    "warning_soft": "#2a2113",
    "danger": "#e07a7a",
    "danger_soft": "#2a1618",
    "danger_hover": "#3a1d1f",
    "danger_border": "#5c2a2d",
    "info": "#82b4e4",
    "info_soft": "#172432",
    "select_bg": "#2f4050",
}

LIGHT_COLORS: Final[dict[str, str]] = {
    "bg": "#f3f4f6",
    "bg_elevated": "#f8f9fa",
    "sidebar": "#e9ebef",
    "card": "#ffffff",
    "card_hover": "#f4f6f8",
    "card_muted": "#f7f8fa",
    "input": "#ffffff",
    "border": "#d9dde3",
    "border_bright": "#bfc7d1",
    "text": "#1b2027",
    "text_muted": "#59626d",
    "text_dim": "#8a939e",
    "accent": "#526d86",
    "accent_hover": "#405a72",
    "accent_soft": "#e7edf3",
    "accent_text": "#ffffff",
    "success": "#2f7d57",
    "success_soft": "#e8f4ed",
    "warning": "#946415",
    "warning_soft": "#fbf3e4",
    "danger": "#b44343",
    "danger_soft": "#fbeaea",
    "danger_hover": "#f5dada",
    "danger_border": "#dfb4b4",
    "info": "#2e6da4",
    "info_soft": "#e8f1f9",
    "select_bg": "#d7e3ee",
}

THEMES: Final[dict[str, dict[str, str]]] = {
    "dark": DARK_COLORS,
    "light": LIGHT_COLORS,
}

COLORS: Final[dict[str, str]] = dict(DARK_COLORS)

STATUS_META: Final[dict[str, dict[str, str]]] = {
    "pass": {
        "label": "Protected",
        "color": COLORS["success"],
        "soft": COLORS["success_soft"],
        "glyph": "✓",
    },
    "warn": {
        "label": "Attention",
        "color": COLORS["warning"],
        "soft": COLORS["warning_soft"],
        "glyph": "!",
    },
    "fail": {
        "label": "At risk",
        "color": COLORS["danger"],
        "soft": COLORS["danger_soft"],
        "glyph": "×",
    },
    "info": {
        "label": "Info",
        "color": COLORS["info"],
        "soft": COLORS["info_soft"],
        "glyph": "i",
    },
    "unknown": {
        "label": "Unknown",
        "color": COLORS["text_dim"],
        "soft": COLORS["card_muted"],
        "glyph": "?",
    },
}

CHECK_ICONS: Final[dict[str, str]] = {
    "defender": "DEF",
    "firewall": "FW",
    "dns": "DNS",
    "wifi": "WIFI",
    "browser": "WEB",
    "uac": "UAC",
}

FONT_UI: Final = "Segoe UI"
FONT_DISPLAY: Final = "Segoe UI Variable Display"
FONT_MONO: Final = "Cascadia Mono"
FONT_MONO_FALLBACK: Final = "Consolas"


# ---------------------------------------------------------------------------
# DNS providers
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class DNSProvider:
    """A DNS resolver preset that can be applied with netsh."""

    key: str
    name: str
    short_name: str
    description: str
    tag: str
    primary: str
    secondary: str
    ipv6_primary: str | None = None
    ipv6_secondary: str | None = None
    accent_key: str = "accent"

    @property
    def accent(self) -> str:
        return COLORS.get(self.accent_key, COLORS["accent"])

    @property
    def ipv4_servers(self) -> tuple[str, ...]:
        return (self.primary, self.secondary)

    @property
    def ipv6_servers(self) -> tuple[str, ...]:
        return tuple(
            address
            for address in (self.ipv6_primary, self.ipv6_secondary)
            if address
        )

    @property
    def address_label(self) -> str:
        return f"{self.primary}  ·  {self.secondary}"


DNS_PROVIDERS: Final[tuple[DNSProvider, ...]] = (
    DNSProvider(
        key="cloudflare",
        name="Cloudflare Privacy",
        short_name="Cloudflare",
        description="Fast, privacy-first resolver. Cloudflare promises not to sell data or use it for targeted ads.",
        tag="RECOMMENDED",
        primary="1.1.1.1",
        secondary="1.0.0.1",
        ipv6_primary="2606:4700:4700::1111",
        ipv6_secondary="2606:4700:4700::1001",
        accent_key="accent",
    ),
    DNSProvider(
        key="cloudflare_family",
        name="Cloudflare Family",
        short_name="Family",
        description="Cloudflare's family-safe resolver. Blocks malware and adult content on this device.",
        tag="CHILD SAFE",
        primary="1.1.1.3",
        secondary="1.0.0.3",
        ipv6_primary="2606:4700:4700::1113",
        ipv6_secondary="2606:4700:4700::1003",
        accent_key="success",
    ),
    DNSProvider(
        key="google",
        name="Google Public DNS",
        short_name="Google",
        description="A reliable global resolver with strong performance. Logs are retained for debugging and abuse.",
        tag="FAST",
        primary="8.8.8.8",
        secondary="8.8.4.4",
        ipv6_primary="2001:4860:4860::8888",
        ipv6_secondary="2001:4860:4860::8844",
        accent_key="info",
    ),
    DNSProvider(
        key="opendns",
        name="OpenDNS Home",
        short_name="OpenDNS",
        description="Cisco's phishing-aware resolver with content filtering and parental controls.",
        tag="PHISHING FILTER",
        primary="208.67.222.222",
        secondary="208.67.220.220",
        ipv6_primary="2620:119:35::35",
        ipv6_secondary="2620:119:53::53",
        accent_key="warning",
    ),
)

DNS_PROVIDER_BY_KEY: Final[dict[str, DNSProvider]] = {
    provider.key: provider for provider in DNS_PROVIDERS
}

# Servers that count as a deliberate privacy-preserving DNS choice during an
# audit. The advisory list is intentionally broader than the presets we apply.
KNOWN_SECURE_DNS: Final[dict[str, str]] = {
    "1.1.1.1": "Cloudflare",
    "1.0.0.1": "Cloudflare",
    "1.1.1.2": "Cloudflare Security",
    "1.0.0.2": "Cloudflare Security",
    "1.1.1.3": "Cloudflare Family",
    "1.0.0.3": "Cloudflare Family",
    "2606:4700:4700::1111": "Cloudflare",
    "2606:4700:4700::1001": "Cloudflare",
    "2606:4700:4700::1112": "Cloudflare Security",
    "2606:4700:4700::1002": "Cloudflare Security",
    "2606:4700:4700::1113": "Cloudflare Family",
    "2606:4700:4700::1003": "Cloudflare Family",
    "8.8.8.8": "Google Public DNS",
    "8.8.4.4": "Google Public DNS",
    "2001:4860:4860::8888": "Google Public DNS",
    "2001:4860:4860::8844": "Google Public DNS",
    "9.9.9.9": "Quad9",
    "149.112.112.112": "Quad9",
    "2620:fe::fe": "Quad9",
    "2620:fe::9": "Quad9",
    "208.67.222.222": "OpenDNS",
    "208.67.220.220": "OpenDNS",
    "2620:119:35::35": "OpenDNS",
    "2620:119:53::53": "OpenDNS",
}


# ---------------------------------------------------------------------------
# Browser extension policy catalogue
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ExtensionSpec:
    name: str
    extension_id: str
    description: str

    @property
    def force_value(self) -> str:
        return self.extension_id


@dataclass(frozen=True)
class BrowserPolicy:
    key: str
    name: str
    executable_names: tuple[str, ...]
    policy_root: str
    force_list_key: str
    update_url: str
    extension_ids: tuple[str, ...]
    extensions: tuple[ExtensionSpec, ...]
    install_locations: tuple[str, ...] = field(default_factory=tuple)


CHROME_UPDATER: Final = "https://clients2.google.com/service/update2/crx"
EDGE_UPDATER: Final = "https://edge.microsoft.com/extensionwebstorebase/v1/crx"

BROWSERS: Final[tuple[BrowserPolicy, ...]] = (
    BrowserPolicy(
        key="chrome",
        name="Google Chrome",
        executable_names=("chrome.exe",),
        policy_root=r"SOFTWARE\Policies\Google\Chrome",
        force_list_key=r"SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist",
        update_url=CHROME_UPDATER,
        extension_ids=(
            "cjpalhdlnbpafiamejdnhcphjbkeiagm",  # uBlock Origin
            "pkehgijcmpdhfbdbbnkijodmdjhbjlgp",  # Privacy Badger
        ),
        extensions=(
            ExtensionSpec(
                "uBlock Origin",
                "cjpalhdlnbpafiamejdnhcphjbkeiagm",
                "Wide-spectrum content and tracker blocker.",
            ),
            ExtensionSpec(
                "Privacy Badger",
                "pkehgijcmpdhfbdbbnkijodmdjhbjlgp",
                "Automatically learns and blocks invasive trackers.",
            ),
        ),
    ),
    BrowserPolicy(
        key="edge",
        name="Microsoft Edge",
        executable_names=("msedge.exe",),
        policy_root=r"SOFTWARE\Policies\Microsoft\Edge",
        force_list_key=r"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist",
        update_url=EDGE_UPDATER,
        extension_ids=(
            "odfafepnkmbhccpbejgmiehpchacaeak",  # uBlock Origin (Edge Add-ons)
            "mkejgcgkdlddbggjhhflekkondicpnop",  # Privacy Badger (Edge Add-ons)
        ),
        extensions=(
            ExtensionSpec(
                "uBlock Origin",
                "odfafepnkmbhccpbejgmiehpchacaeak",
                "Wide-spectrum content and tracker blocker.",
            ),
            ExtensionSpec(
                "Privacy Badger",
                "mkejgcgkdlddbggjhhflekkondicpnop",
                "Automatically learns and blocks invasive trackers.",
            ),
        ),
    ),
)

BROWSER_BY_KEY: Final[dict[str, BrowserPolicy]] = {
    browser.key: browser for browser in BROWSERS
}

ALL_MANAGED_EXTENSION_IDS: Final[frozenset[str]] = frozenset(
    extension_id
    for browser in BROWSERS
    for extension_id in browser.extension_ids
)

# Friendly names used by the audit when it discovers an extension in a policy.
EXTENSION_NAME_BY_ID: Final[dict[str, str]] = {
    "cjpalhdlnbpafiamejdnhcphjbkeiagm": "uBlock Origin",
    "ddkjiahejlhfcafbddmgiahcphecmpfh": "uBlock Origin Lite",
    "odfafepnkmbhccpbejgmiehpchacaeak": "uBlock Origin",
    "cimighlppcgcoapaliogpjjdehbnofhn": "uBlock Origin Lite",
    "pkehgijcmpdhfbdbbnkijodmdjhbjlgp": "Privacy Badger",
    "mkejgcgkdlddbggjhhflekkondicpnop": "Privacy Badger",
    "mlomiejdfkolichcflejclcbmpeaniij": "Ghostery",
}

ADBLOCK_EXTENSION_IDS: Final[frozenset[str]] = frozenset(
    {
        "cjpalhdlnbpafiamejdnhcphjbkeiagm",
        "ddkjiahejlhfcafbddmgiahcphecmpfh",
        "odfafepnkmbhccpbejgmiehpchacaeak",
        "cimighlppcgcoapaliogpjjdehbnofhn",
    }
)

PRIVACY_EXTENSION_IDS: Final[frozenset[str]] = frozenset(
    {
        "pkehgijcmpdhfbdbbnkijodmdjhbjlgp",
        "mkejgcgkdlddbggjhhflekkondicpnop",
        "mlomiejdfkolichcflejclcbmpeaniij",
    }
)

# ---------------------------------------------------------------------------
# UAC
# ---------------------------------------------------------------------------
UAC_POLICY_KEY: Final = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

FIREWALL_PROFILES: Final[tuple[str, ...]] = ("Domain", "Private", "Public")

APP_DATA_DIRNAME: Final = "WinSentinel"
