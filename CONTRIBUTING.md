# Contributing to WinSentinel

Thanks for taking the time to improve WinSentinel. This project is a small,
Windows-only security console, so the best contributions are focused, easy to review,
and backed by tests that never change a live machine.

## Before you start

- Read the [README](README.md), especially the security model and limitations.
- Search the [issue tracker](https://github.com/assyte/winsentinel/issues) before
  opening a new issue.
- For a large change, open an issue first so the approach can be agreed on.
- Report vulnerabilities privately using [SECURITY.md](SECURITY.md), not a public issue.

## Development setup

WinSentinel targets Windows 10/11 and Python 3.11 or newer. Python 3.12 is the primary
test version.

```powershell
git clone https://github.com/assyte/winsentinel.git
cd winsentinel

py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Running the app requires administrator rights because it reads and changes system
settings. The test suite does not.

```powershell
python -m unittest discover -s tests -v
python -m compileall -q core ui main.py tests
```

## Project principles

1. **Local first.** No telemetry, cloud account, background service, driver, or startup
   entry. Logs stay under `%LOCALAPPDATA%`.
2. **Read before write.** The audit is read-only. Changes happen only after an explicit
   user action.
3. **Honest results.** If Windows rejects an operation, return an error. Never report a
   change that did not happen.
4. **Small blast radius.** Prefer the narrowest operation, preserve unrelated policy
   values, and document how a change can be reversed.
5. **Standard library first.** Do not add a runtime dependency without a clear reason and
   prior discussion.
6. **The UI thread stays responsive.** Long-running work belongs in `run_task()` or
   another background thread, with callbacks marshalled back to Tk.

## Where changes belong

| Area | File(s) |
| --- | --- |
| Audit decisions | `core/auditor.py` |
| Shared models and scoring | `core/models.py` |
| DNS adapter discovery and changes | `core/dns_manager.py` |
| Firewall and Defender controls | `core/firewall_manager.py` |
| One-click remediation order | `core/hardener.py` |
| Browser and UAC policies | `core/policy_manager.py` |
| Offline tools | `core/security_tools.py` |
| Command execution and quoting | `core/shell.py` |
| UI shell and background tasks | `ui/app.py` |
| Cards, sidebar, gauge, log console | `ui/components.py` |
| Page layout | `ui/dashboard.py`, `ui/*_page.py` |
| Tests | `tests/` |

If you add a system-changing operation, put it behind an existing manager and return an
`OperationResult` with useful details. Add it to the audit only if Windows exposes a
reliable read path for the same state.

## Security-sensitive changes

Changes that touch elevation, command execution, registry writes, DNS, firewall, or
Defender need extra care:

- Do not use `shell=True` or build command strings by concatenation. Use argument lists
  in `core/shell.py` and `powershell_quote()` for values inside PowerShell.
- Validate adapter indices and IP addresses before using them.
- Keep timeouts on every command.
- Do not log passphrases, tokens, or secrets.
- Preserve unrelated browser force-install values and explain how managed entries can
  be removed.
- Document whether a change requires a reboot or sign-out.
- Add tests for parsing, failure handling, and policy preservation.
- Test against a disposable VM when possible; do not test destructive operations on
  someone else's machine.

## Tests

The suite uses only the standard library and deterministic fakes. It must not touch live
firewall, DNS, Defender, UAC, or browser-policy state.

```powershell
python -m unittest discover -s tests -v
```

Please add a test for:

- new parsing or classification logic
- a new audit pass/warn/fail decision
- a new remediation that can be tested without live system changes
- a regression fixed by your change
- failure paths, including rejected commands and malformed output

## Code style

- Follow the existing type-hinted, dataclass-oriented style.
- Keep modules focused and avoid a new abstraction for a single call site.
- Prefer clear names over short names.
- Keep UI text concise and consistent with the existing pages.
- Run `python -m compileall -q core ui main.py tests` before opening a pull request.
- Do not reformat unrelated files.

## Pull requests

1. Fork the repository and create a topic branch from `main`.
2. Make the smallest coherent change.
3. Add or update tests.
4. Update the README if behavior, requirements, or limitations changed.
5. Confirm that tests and compilation pass.
6. Open a pull request that explains the problem, the approach, and the verification.

A good pull request includes:

- a short summary of the user-visible behavior
- the reason for the change
- test evidence
- screenshots for UI changes
- any reversibility or security implications
- follow-up work that is intentionally out of scope

## Commit messages

Use an imperative, present-tense subject. Examples:

```text
Add DNS adapter refresh after a preset change
Preserve unrelated browser force-install entries
Fix Wi-Fi WPS detection on localized Windows
```

Keep commits reviewable. Squash fixup commits before merging if the history is noisy.

## License

By contributing, you agree that your contribution is licensed under the repository's
[MIT License](LICENSE).
