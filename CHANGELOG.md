# Changelog

All notable changes to WinSentinel are documented here. The project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Planned

- Headless JSON scan mode
- DNS-over-HTTPS detection
- Additional browser policy coverage
- Localization
- Signed release builds

## [1.1.0] - 2026-10-28

### Added

- Light/dark appearance switch with a remembered local preference
- Neutral graphite and soft gray palettes with a muted steel accent
- Muted gray shield mark and matching Windows application icon
- Full firewall disable/enable controls for all Windows profiles, with confirmation
- Clearer "Full Scan" and "Health Score" labels across the dashboard

### Changed

- Replaced the AMOLED-only visual language with readable light and dark themes
- Made DNS provider colors and raw Tk widgets follow the active theme
- Added Pillow as a runtime dependency for the logo asset

## [1.0.0] - 2026-10-26

### Added

- Six-control Windows security audit: Defender, firewall, DNS, Wi-Fi, browser policy,
  and UAC
- Weighted security score, letter grade, risk headline, and per-control evidence
- One-click hardening pipeline with post-remediation verification
- DNS presets for Cloudflare, Cloudflare Family, Google Public DNS, OpenDNS, and DHCP
- Live firewall and Defender controls
- Chrome and Edge forced-extension policy management with preservation of unrelated
  entries
- CSPRNG passphrase generator and router/Wi-Fi hardening helper
- AMOLED dark CustomTkinter interface with five pages and a collapsible system log
- Mandatory UAC elevation, single-instance mutex, and local rotating logs
- Deterministic read-only unit test suite
- PyInstaller one-file build with an administrator manifest
- Public README, contributing guide, security policy, and Windows CI workflow
