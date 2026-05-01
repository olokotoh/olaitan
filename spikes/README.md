# Spikes

Throwaway investigation code that backs research-spike stories.

## Conventions

- Each subdirectory is its own Go module (its `go.mod` is independent
  of the root `github.com/olokotoh/olaitan` module). Spike dependencies
  therefore never enter the main `go.sum`.
- Spike code is excluded from the main module's lint and test runs.
  See `.golangci.yml` and `Makefile` for the exclusion paths.
- A spike directory may be deleted once the originating story merges
  and the production implementation lands. The story's ADR (under
  `docs/deferred-decisions.md`) carries the durable record of the
  spike outcome.
- A spike's `README.md` documents the expected console output so the
  next reader can verify the spike still works without re-deriving
  the test contract from the source.

## Active spikes

| Directory | Story | Purpose | ADR |
|---|---|---|---|
| `sigma-parser/` | 1.2 | Choose the OLT Sigma parser strategy: wrap an existing Go Sigma parser vs. fork vs. hand-roll a custom parser. | ADR-2026-04-28-01 |
| `calico-flow/` | 1.3 | Choose the Calico flow record export mechanism: Goldmane gRPC API vs. custom collector sidecar vs. Falco-syscalls fallback vs. FR4 descope. | ADR-2026-04-30-01 |
