# Contributing to Olaitan

Thanks for considering it. This is a research preview maintained by one person,
so please read this before spending time on a change.

## Before you start

- **Open an issue first** for anything beyond a typo or an obvious bug fix.
  A change that does not fit the architecture is a waste of your evening, and
  it is cheaper to find that out in an issue.
- **No new detection capability without a discussion.** The scoring model and
  the trust ladder are load-bearing for the project's claims, and changes there
  need to be argued, not just implemented.

## The full guide

Development environment, build targets, test layout, the CI gates and the
review bar are documented in **[docs/contributing.md](docs/contributing.md)**.
That is the canonical guide; this file is the front door.

## The short version

```bash
make test          # unit and integration
make lint          # golangci-lint only
make olaitan-lint  # the repo's own canonical-name gate, a SEPARATE target
make e2e-local     # kind-based end-to-end smoke
```

`make lint` does **not** run `olaitan-lint`. They are separate targets and
separate CI steps, deliberately, so a canonical-name failure is attributable.
Running only `make lint` and seeing it pass is not enough.

Your pull request must:

1. **Pass CI.** There are custom gates beyond the usual: a canonical-name
   linter, a schema drift gate, a Helm values drift gate, a dashboard metric
   guard, a Trivy CRITICAL/HIGH gate, and a traceability audit. They exist
   because each one caught a real defect. If one fails, it has probably found
   something.
2. **Fill in the traceability field in the PR template.** The audit gate
   enforces it.
3. **Carry tests.** New behaviour needs a test that fails without the change.

## Reporting bugs

Use the issue templates. For anything security-relevant, follow
[SECURITY.md](SECURITY.md) instead and report it privately.

## Code of conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
