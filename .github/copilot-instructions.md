# Olaitan code review instructions for Copilot

## Project context

Olaitan is a Kubernetes runtime security agent (Go 1.25, distroless DaemonSet) that ingests Falco / K8s audit / containerd CRI / Calico CNI / app-log signals into NATS JetStream, runs correlation and graduated isolation, and produces forensic reports. Five streaming sources feed a single-goroutine adapter pattern under `internal/collector/<source>/`. The architecture / PRD / epic specs live in a separate planning workspace that is NOT in this repo, so do NOT chase `architecture.md:NNN` line refs in code comments — focus on the diff.

Path-scoped instructions in `.github/instructions/` add Go-specific and Helm-specific rules; this file holds the repo-wide ones.

## Hard rules — flag any violation

### Authorship and writing
- **No AI authorship attribution.** Commits, PR descriptions, code comments, and docs MUST NOT contain `Co-Authored-By: Claude`, `Generated with Claude Code`, or any AI-agent identifier.
- **No em-dashes in writing the user owns** (commit messages, PR bodies, `docs/`, `README.md`, code comments authored in this PR). Existing em-dashes outside the PR scope are not in scope. Use ` - ` or `, ` instead.
- **British English** in writing-the-user-owns: behaviour, organisation, serialise, recognise. Identifiers and standard library names stay as-is.

### Source health (FR8)
- `internal/collector/<source>/health.go` owns the in-process tracker (single `atomic.Pointer[healthState]` snapshot). `Adapter.Health()` returns the narrow `HealthReader` interface (`Status() (bool, error)`), NOT `*SourceHealth`. Callers outside the package must NOT reach `MarkHealthy` / `MarkUnhealthy`.
- The unified Prometheus surface `source_healthy{source="..."}` is owned by `cmd/olaitan/metrics.go` and lands in Story 1.12. Per-source stories MUST NOT introduce a Prometheus client dependency or pre-empt the unified metric naming.

### Tests (NFR35)
- Integration tests use real dependency boundaries: embedded `nats-server/v2` for JetStream, `bufconn` for in-process gRPC. Mock-only ring boundaries are forbidden for AC5 satisfaction. Flag any test that asserts AC behaviour by inspecting a mock-internal slice rather than driving the system through a real boundary.
- `t.Logf` does NOT fail a test; `t.Errorf` / `t.Fatalf` do. Flag AC-relevant assertions written as `t.Logf`.
- Prefer table-driven tests; one `t.Run(name, ...)` per case.

### Traceability (NFR42)
- Every PR that adds or changes a code package MUST update `docs/traceability.md` with a row tying the package to FRs, NFRs, and test files. The CI `traceability` job enforces `traceability_updated: yes` in the PR body. Flag PRs missing the update unless they add no claim and explain in `### Traceability rationale`.

### Latency budget (NFR1)
- Per-source per-node throughput target: 1000 events/sec; end-to-end p99 from sensor receipt to NATS PubAck: 50 ms. Flag bench changes that quote `ns/op` as a per-event latency claim — `ns/op` from a `b.N`-driven loop with polling `waitDelivered` conflates send-rate, gRPC throughput, and poll resolution. The meaningful AC3 metric is `b.ReportMetric(p99, "p99-ms")` from a per-publish wall-clock capture.

## Style preferences
- Default to writing no comments. Add a comment only when the WHY is non-obvious: a hidden constraint, a workaround for a specific bug, behaviour that would surprise a reader.
- Don't reference the current task / fix / PR / issue in code comments — those belong in the commit message or PR body.
- Don't add error handling or fallback paths for scenarios that can't happen. Trust framework guarantees. Validate at system boundaries only.

## Out of scope
- Pre-existing code outside the PR diff. Comment only on lines the PR changes.
- Architectural decisions deferred to a future story (look for `Story X.Y` references in nearby comments).
