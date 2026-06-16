# Olaitan documentation index

This is the in-repo index of Olaitan's documentation. It is also the
canonical home of the project's Architectural Decision Records (ADRs):
the load-bearing decisions and reusable patterns are recorded here so
their rationale survives the people who made them.

## Architecture Decision Records

Each ADR follows a consistent decision-record structure. The
schema-versioning, patterns, and contributing records use the
Context / Decision / Consequences / Alternatives shape; the
deferred-decisions spike records use an extended shape
(Status / Context / Decision / Why this direction / Risks /
Alternatives considered and rejected / Hand-off), where the
"Why this direction" and "Risks" sections stand in for Consequences.

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

- [Runbook](runbook.md) - the operator reference: Section 1 is the Prometheus
  metric catalogue and Section 2 is the ten NFR34 operational scenarios (Helm
  install, state-override + TTL, per-source health, missed-detection
  investigation, rule corpus hot-reload, air-gapped Ollama, rules-only mode,
  S3 forensic queries, metric interpretation, SIEM via the AUDIT.* subjects),
  each with steps, expected metric responses, expected audit-subject signals,
  and troubleshooting, plus the evaluation arms and deployment notes.
- [Metrics](metrics.md) - the Prometheus metric surface (names, types,
  labels, PromQL).
- [Pre-built Grafana dashboards](../deploy/grafana/README.md) - six
  importable Grafana dashboards (`deploy/grafana/dashboards/`) covering
  source health, detection, FSM state, the LLM tier, and forensic
  reporting, with `schemaVersion` pinned to Grafana 11.1.x; every panel
  PromQL is grounded in a real exported metric, mechanically enforced by
  `make dashboard-lint` (Story 6.7).
- [IAM](iam.md) - identity and access notes.
- [NATS subjects](nats-subjects.md) - the per-subject integrator
  reference (producer, consumers, payload schema, retention, and a
  sample `nats sub` invocation) for building an external SIEM consumer.
- [Sigma extensions](sigma-extensions.md) - the OLT Sigma dialect
  specification: the `k8s.*` field references, the `attack:` annotation,
  the severity and false-positive conventions, worked examples from the
  rule corpus, and how to validate a rule against the SIGMA-HQ reference
  parser.
- [Helm values reference](helm-values.md) - the operator-facing FR47
  reference for every tunable chart value (name, type, default, valid
  range, effect, FR/NFR reference), auto-generated from the `# @schema`
  annotations in `deploy/helm/olaitan/values.yaml` by
  `make helm-values-doc`; CI fails any un-regenerated drift.
- Deployment-posture overlays (`deploy/helm/olaitan/`) - three
  ready-made values overlays so an operator picks a posture without
  composing the configuration by hand (Story 6.6):
  - `values-production.yaml` - production hardening (365 d audit / settling
    / report-archive retention, scrape annotations on; the chart already
    enforces `runAsNonRoot` / `readOnlyRootFilesystem` / seccomp / cap-drop
    unconditionally). `helm install olaitan deploy/helm/olaitan
    --set secrets.redisPassword=<pw> -f deploy/helm/olaitan/values-production.yaml`.
    The header documents the AC1 knobs with no chart surface (NATS/Redis
    mTLS, AppArmor, Trivy, log level, the Prometheus-server-owned scrape
    interval) as honest gaps rather than fabricated keys.
  - `values-airgapped.yaml` - the FR48 air-gapped posture (in-cluster
    Ollama Deployment + Service + NetworkPolicy with empty egress, provider
    `local`, notifications off, no external egress).
    `... -f deploy/helm/olaitan/values-airgapped.yaml`.
  - `values-eval.yaml` - the common evaluation BASE (faster settling
    window, lower per-source rate-limit threshold, faster baseline warm-up)
    that the six `values-eval-<arm>.yaml` arm overlays reference as their
    base. Layer it under an arm:
    `... -f deploy/helm/olaitan/values-eval.yaml -f deploy/helm/olaitan/values-eval-rs.yaml`.
  Every overlay renders to a committed golden (`deploy/helm/testdata/golden/`)
  and a `-tags=helm` knob test; the air-gapped posture's operator-experience
  commitments are also verified live by the label-gated `e2e-overlays` kind
  smoke (`make e2e-local-overlays`).
- [Prompt changelog](prompt-changelog.md) - the NFR41 prompt-content
  audit trail.
- [Traceability matrix](traceability.md) - the NFR42 code-to-thesis
  claim chain.
- [Schemas](schemas/) - the committed JSON/YAML schema artefacts for the
  wire, persisted, and role contracts, so an external consumer can
  validate and parse Olaitan's outputs without the Go module (NFR40). The
  three plain wire/persisted carriers (`olt_event`, `evidence_package`,
  `workload_posture`) are reflection-generated from the `internal/schema`
  Go structs by `make schemas` and CI fails any drift (NFR33); the
  hand-curated, model-facing schemas (`l1_hypothesis`, `l2_verification`,
  `threat_assessment`, `forensic_report`, the FSM and `audit/` subjects)
  stay hand-authored because they encode bounds and rules reflection
  cannot reproduce.

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
