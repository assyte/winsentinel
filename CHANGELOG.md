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
