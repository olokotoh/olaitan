# Olaitan documentation index

This is the in-repo index of Olaitan's documentation. It is also the
canonical home of the project's Architectural Decision Records (ADRs):
the load-bearing decisions and reusable patterns are recorded here so
their rationale survives the people who made them.

## Architecture Decision Records

Each ADR follows a consistent Context / Decision / Consequences /
Alternatives structure.

- [Schema versioning](schema-versioning.md) - the `schema_version` semver
  convention, the schema-on-read MINOR rule, and the dual-publish MAJOR
  migration policy (7-day window), plus the per-change history table.
- [Deferred decisions](deferred-decisions.md) - the consolidated spike
  outcomes (Sigma parser strategy, Calico flow-record export, CRIU
  forensic checkpointing) and other deferred or reconciled decisions,
  each with the chosen path, the rejected alternatives, and the affected
  stories.
- [Architectural patterns](patterns.md) - the patterns a contributor
  must reuse rather than reinvent: NATS-subject and Redis-key constants,
  the self-describing envelope wrapper, the transient/permanent error
  taxonomy, the redaction reuse contract, idempotency keys, structured
  logging, and the single-goroutine-per-source concurrency model.
- [Contributing](contributing.md) - the build, test, lint, PR, and
  traceability conventions, and the forbidden patterns.

## Operator and reference documentation

- [Runbook](runbook.md) - operational scenarios, evaluation arms, and
  deployment notes.
- [Metrics](metrics.md) - the Prometheus metric surface (names, types,
  labels, PromQL).
- [IAM](iam.md) - identity and access notes.
- [Sigma extensions](sigma-extensions.md) - the OLT Sigma dialect
  specification.
- [Prompt changelog](prompt-changelog.md) - the NFR41 prompt-content
  audit trail.
- [Traceability matrix](traceability.md) - the NFR42 code-to-thesis
  claim chain.
- [Schemas](schemas/) - the committed JSON/YAML schema artefacts for the
  wire, persisted, and role contracts.

## The canonical architecture document

The full system architecture (rings, data flow, subject contract,
trust-bound design) is the project's planning artefact `architecture.md`.
That document lives in the planning workspace, not in this code
repository, so it is referenced from the in-repo docs by section anchors
(for example `architecture.md:130` in
[schema-versioning.md](schema-versioning.md)) rather than committed here.
This index is the in-repo ADR surface those references point back to: the
ADRs above are the code-grounded record of the decisions the
architecture document describes at the design level.
