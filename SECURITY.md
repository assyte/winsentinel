# Security policy

WinSentinel runs with administrator privileges and changes Windows security settings,
so security reports are taken seriously. Thank you for helping keep users safe.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | Yes |
| Older / unreleased snapshots | Best effort |

## Reporting a vulnerability

Please do **not** open a public issue for a security vulnerability.

Use GitHub's private vulnerability reporting:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability**.
3. Include enough detail to reproduce and assess the issue.

If private reporting is unavailable, open a minimal public issue asking for a private
contact channel. Do not include exploit details, credentials, or personal data in that
issue.

## What to include

- WinSentinel version (`python main.py --version`) and whether you used the source build
  or the packaged executable
- Windows version and build number
- the security impact you believe is possible
- reproduction steps or a proof of concept
- relevant log excerpts with secrets, usernames, and paths redacted
- any suggested fix or mitigation

Please remove tokens, passwords, Wi-Fi credentials, and other sensitive data before
sharing logs. The log is normally at:

```text
%LOCALAPPDATA%\WinSentinel\logs\winsentinel.log
```

## Scope

In scope:

- privilege escalation or unintended privilege retention
- command injection or unsafe argument handling
- a system change that happens without an explicit user action
- accidental overwriting of unrelated browser or Windows policy values
- logging of passphrases, credentials, or other secrets
- a remediation that reports success without changing the intended state
- unsafe handling of adapter names, DNS addresses, registry values, or parsed output
- release or build supply-chain issues

Out of scope:

- issues that require an attacker to already have administrator rights
- issues that require physical access to an unlocked machine
- third-party antivirus, browser-store, router-firmware, or Group Policy behavior
- findings that are already documented as limitations in the README
- social engineering or denial-of-service against a local desktop app without a
  meaningful security boundary

## Safe research

- Test only on systems you own or have explicit permission to test.
- Prefer a disposable virtual machine.
- Do not access, modify, or exfiltrate other people's data.
- Do not run destructive tests against shared or production systems.
- Give the project reasonable time to investigate and release a fix before public
  disclosure.

## Response

Reports will be acknowledged as soon as practical. Valid reports will be investigated,
fixed, and credited in the release notes if the reporter wants credit. Please avoid
public disclosure until a fix or mitigation is available.
