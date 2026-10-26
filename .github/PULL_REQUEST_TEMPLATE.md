## Summary

Describe the user-visible change and why it is needed.

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Security hardening
- [ ] Documentation
- [ ] Packaging / CI
- [ ] Refactor with no behavior change

## Verification

- [ ] `python -m unittest discover -s tests -v`
- [ ] `python -m compileall -q core ui main.py tests`
- [ ] Tested on Windows 10 or Windows 11
- [ ] UI change verified with a screenshot or manual run

## Security and reversibility

- [ ] The startup scan and page navigation remain read-only.
- [ ] New system changes are behind a manager and return `OperationResult`.
- [ ] Unrelated registry/proxy policies are preserved.
- [ ] The change can be reversed or the limitation is documented.
- [ ] No secrets, tokens, or machine-specific data are committed.

## Notes

List follow-up work, limitations, or anything reviewers should pay special attention to.
