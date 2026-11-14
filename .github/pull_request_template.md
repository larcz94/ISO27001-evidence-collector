## What changed and why

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] The collector stays read-only: only `Get`, `List` or `Describe` API calls.
- [ ] Every new API call is in `policies/` and in `infra/github-oidc-role.yaml`.
- [ ] Every new check has a title, a severity, a fix suggestion and a test.
- [ ] `ruff check src tests` and `pytest -q` pass locally.
- [ ] No real account IDs, ARNs, IP addresses, keys or evidence reports are in this change.
- [ ] The README and the samples in `examples/` are updated if the output changed.
