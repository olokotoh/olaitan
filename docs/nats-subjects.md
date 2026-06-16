# NATS subjects reference

This document enumerates every NATS subject in Olaitan's inter-ring
subject contract, with its producer component, primary consumers,
payload schema reference, retention policy, and a sample `nats sub`
invocation. It is the integrator's reference for building an external
SIEM consumer or a downstream tool without reading the source tree.

The canonical subject set is defined as named constants and validated
builders in `internal/subjects/subjects.go`. Every subject below maps
back to that file; the retention figures are grounded in the JetStream
stream configs in `internal/nats/streams.go`; the producer and consumer
call sites are the real `PublishJS` and `FilterSubject` sites in the
code (cited inline).

## Orientation

Olaitan moves a signal through five rings: collection (Ring 1) into
correlation (Ring 2), through deterministic and LLM-assisted decision
(Ring 3), into graduated response and finalisation (Ring 4), and out to
forensic reporting (Ring 5). The subject names fall into two naming
families:

- **Lower-case `olaitan.*` operational subjects** carry the in-flight
  per-source and per-pod hops (`olaitan.events.raw.*`,
  `olaitan.evidence.packages`, and so on).
- **Dotted-UPPER published-contract subjects** carry the durable,
  externally-consumable contracts (`OVERRIDES.applied`, `AUDIT.*`,
  `INCIDENTS.finalised`, `REPORTS.generated`,
  `INVESTIGATIONS.{id}.{l1,l2}`). These are the subjects an external
  SIEM or operator tool is most likely to subscribe.

Per-id and per-pod subjects are never string-built. They are produced
by validated builder functions (`Correlated`, `State`, `Health`,
`Evidence`, `InvestigationL1`, `InvestigationL2`) that reject the
NATS-reserved characters (`.`, `*`, `>`) and whitespace via
`validateToken` (`internal/subjects/subjects.go:134`), so a hostile
token cannot inject extra subject levels. See
[Dynamic (templated) subjects](#dynamic-templated-subjects) below.

### Reading the retention column

Each durable subject rides a JetStream stream defined in
`internal/nats/streams.go`. Every stream uses `LimitsPolicy` retention:
messages expire by `MaxAge` (and `MaxBytes`/`MaxMsgsPerSubject` caps)
regardless of consumer acknowledgement. `LimitsPolicy` is the
deliberate choice for the audit-grade subjects (`AUDIT.*`,
`OVERRIDES.applied`, `INCIDENTS.finalised`, `REPORTS.generated`)
because it is append-only by construction: a consumer cannot delete an
event by acking it (NFR16). Subjects with no stream ride core NATS and
are ephemeral (no retention).

### Payload schema references

Where a committed JSON/YAML schema exists under
[`docs/schemas/`](schemas/), the entry points at it. Several subjects
(the raw events, `olaitan.events.normalised`, and
`olaitan.evidence.packages`) do not yet have a committed YAML schema:
their wire shape is defined by the in-Go schema under `internal/schema/`
and the committed YAML lands in Story 6.3 ("YAML JSON-Schema files for
external consumers"). Those entries say so explicitly rather than cite a
file that does not exist.

## Live subjects

These subjects have an active producer and (where the wiring calls for
one) an active consumer in the current build.

### Ring 1 to Ring 2: raw events

The five per-source raw subjects share the `olaitan.events.raw.` prefix
(`RawPrefix`, `internal/subjects/subjects.go:16`). Each source adapter
publishes its events under its own subject; a single correlator consumer
subscribes the whole hierarchy via the `olaitan.events.raw.>` wildcard.

| Subject | Constant | Producer | Consumer |
|---|---|---|---|
| `olaitan.events.raw.falco` | `RawFalco` | Falco adapter, `internal/collector/falco/falco.go:499` | `olaitan-correlator`, `internal/correlator/correlator.go:165` (FilterSubject `olaitan.events.raw.>`, `:167`) |
| `olaitan.events.raw.audit` | `RawAudit` | K8s-audit adapter, `internal/collector/audit/audit.go:767` | `olaitan-correlator` (same) |
| `olaitan.events.raw.runtime` | `RawRuntime` | CRI adapter, `internal/collector/cri/cri.go:501` | `olaitan-correlator` (same) |
| `olaitan.events.raw.network` | `RawNetwork` | CNI adapter, `internal/collector/cni/cni.go:861` | `olaitan-correlator` (same) |
| `olaitan.events.raw.applog` | `RawAppLog` | App-log adapter, `internal/collector/applog/applog.go:597` | `olaitan-correlator` (same) |

- **Payload schema:** the per-source event shape is defined by
  `internal/schema/`. No committed YAML schema yet; Story 6.3 adds it.
- **Retention:** stream `EVENTS_RAW` (`internal/nats/streams.go:36`),
  `LimitsPolicy`, `MaxAge` 6h, `MaxBytes` 50 GiB, `MaxMsgSize` 256 KiB,
  `Duplicates` 2m. The stream covers the whole hierarchy with one
  `olaitan.events.raw.>` subject token.
- **Sample subscription:**

  ```sh
  nats sub "olaitan.events.raw.falco" --raw
  nats sub "olaitan.events.raw.>" --raw   # all five sources at once
  ```

### Ring 2 to Ring 3: evidence packages

The correlator assembles per-pod evidence and publishes one
`EvidencePackage` per correlated group. This is the central fan-out: a
single producer feeds three parallel decision consumers (the
deterministic FSM, the rule engine, and the baseline engine).

| Subject | Constant | Producer | Consumers |
|---|---|---|---|
| `olaitan.evidence.packages` | `EvidencePackages` | Correlator, `internal/correlator/correlator.go:292` (`WithMsgID(pkg.PackageID)`) | `olaitan-response-fsm`, `cmd/olaitan/main.go:1718`; `olaitan-rules-engine`, `internal/decision/rules/engine.go:314`; `olaitan-baseline-engine`, `internal/decision/baseline/engine.go:315` |

- **Payload schema:** `internal/schema/` `EvidencePackage`. No committed
  YAML schema yet; Story 6.3 adds it.
- **Retention:** stream `EVIDENCE` (`internal/nats/streams.go:67`),
  `LimitsPolicy`, `MaxAge` 0 (never auto-expire), `MaxBytes` 100 GiB
  safety cap. The stream covers `olaitan.evidence.>`.
- **Sample subscription:**

  ```sh
  nats sub "olaitan.evidence.packages" --raw
  ```

### Ring 4 to Ring 5: incident finalisation and forensic reports

| Subject | Constant | Producer | Consumer |
|---|---|---|---|
| `INCIDENTS.finalised` | `IncidentFinalised` | Settling-window controller, `internal/response/settling/nats_publisher.go:36` (`WithMsgID(FinalisedMsgID(evt))`) | `olaitan-dfir-agent`, `internal/report/dfir/consumer.go:51` (FilterSubject `INCIDENTS.finalised`, `:53`) |
| `REPORTS.generated` | `ReportsGenerated` | DFIR forensic-report agent, `internal/report/dfir/publisher.go:37` (`WithMsgID(incident_id + ":" + report_sha256)`) | Notification webhook, `internal/report/notify/webhook.go:193` (FilterSubject `REPORTS.generated`, `:195`) |

- **Payload schema:** `INCIDENTS.finalised` ->
  [`docs/schemas/incidents/finalised.yaml`](schemas/incidents/finalised.yaml);
  `REPORTS.generated` ->
  [`docs/schemas/forensic_report.yaml`](schemas/forensic_report.yaml)
  (the announcement carries the report SHA256 and the content-addressed
  URL; the report body conforms to the forensic-report schema).
- **Retention:** `INCIDENTS.finalised` rides stream `INCIDENTS`
  (`internal/nats/streams.go:226`), `LimitsPolicy`, `MaxAge` 365d
  (tunable), `Duplicates` 2m. `REPORTS.generated` rides stream `REPORTS`
  (`internal/nats/streams.go:250`), `LimitsPolicy`, `MaxAge` 365d.
- **Sample subscription:**

  ```sh
  nats sub "INCIDENTS.finalised" --raw
  nats sub "REPORTS.generated" --raw
  ```

### Operator overrides

| Subject | Constant | Producer | Consumer |
|---|---|---|---|
| `OVERRIDES.applied` | `OverridesApplied` | Override controller, `internal/response/override/publisher.go:81` (`WithMsgID`, one event per applied AND per rejected override) | No in-process durable consumer; the `OVERRIDES` stream (`internal/nats/streams.go:82`) is the operator/SIEM audit surface |

- **Payload schema:** operator-override applied/rejected event. No
  committed `docs/schemas/` file yet.
- **Retention:** stream `OVERRIDES` (`internal/nats/streams.go:82`),
  `LimitsPolicy`, `MaxAge` 365d, `Duplicates` 2m. Append-only by
  retention (FR38/FR39).
- **Sample subscription:**

  ```sh
  nats sub "OVERRIDES.applied" --raw
  ```

### SIEM audit subjects

The five append-only audit subjects form the SIEM surface (FR40/FR41,
NFR16). Each is published by a dedicated sink and rides its own
`LimitsPolicy` stream; none has an in-process durable consumer, because
they exist to be consumed by an external SIEM or auditor, not by an
internal orchestrator loop.

| Subject | Constant | Producer | Stream / retention | Payload schema |
|---|---|---|---|---|
| `AUDIT.transitions` | `AuditTransitions` | `internal/response/audit/transition_sink.go:48` | `AUDIT_TRANSITIONS`, `LimitsPolicy`, `MaxAge` 90d (tunable), `Duplicates` 2m (`internal/nats/streams.go:101`) | [`docs/schemas/audit/transitions.yaml`](schemas/audit/transitions.yaml) |
| `AUDIT.overrides` | `AuditOverrides` | `internal/response/override/audit.go:103` | `AUDIT_OVERRIDES`, `LimitsPolicy`, `MaxAge` 365d (tunable), `Duplicates` 2m (`internal/nats/streams.go:115`) | [`docs/schemas/audit/overrides.yaml`](schemas/audit/overrides.yaml) |
| `AUDIT.policies` | `AuditPolicies` | `internal/response/audit/policy_sink.go:45` | `AUDIT_POLICIES`, `LimitsPolicy`, `MaxAge` 365d (tunable), `Duplicates` 2m (`internal/nats/streams.go:126`) | [`docs/schemas/audit/policies.yaml`](schemas/audit/policies.yaml) |
| `AUDIT.redactions` | `AuditRedactions` | `internal/report/redact/audit.go:116` | `AUDIT_REDACTIONS`, `LimitsPolicy`, `MaxAge` 365d (tunable), `Duplicates` 2m (`internal/nats/streams.go:144`) | [`docs/schemas/audit/redactions.yaml`](schemas/audit/redactions.yaml) |
| `AUDIT.assessments` | `AuditAssessments` | `internal/response/audit/assessment_sink.go:167` (`WithMsgID(evt.PackageID)`) | `AUDIT_ASSESSMENTS`, `LimitsPolicy`, `MaxAge` 365d (tunable), `Duplicates` 2m (`internal/nats/streams.go:167`) | [`docs/schemas/audit/assessments.yaml`](schemas/audit/assessments.yaml) |

Each audit event records WHERE and WHY (never the secret value, NFR18,
for `AUDIT.redactions`). Sample subscription:

```sh
nats sub "AUDIT.transitions" --raw
nats sub "AUDIT.>" --raw   # every audit subject at once
```

### Investigation checkpoints (dynamic)

The L1 hypothesis and L2 verification of an in-flight investigation
chain are checkpointed under per-package subjects so a controller
restart can resume from the last completed step (FR29, Story 3.9). These
are dynamic (templated) subjects; see
[Dynamic (templated) subjects](#dynamic-templated-subjects).

| Subject | Builder | Producer | Reader |
|---|---|---|---|
| `INVESTIGATIONS.{package_id}.l1` | `subjects.InvestigationL1(packageID)` | `internal/decision/analyst/checkpoint/store.go:48` (`WithMsgID(packageID + ":l1")`) | Self-consumed on restart-resume via `GetLastMsgForSubject` (`internal/decision/analyst/checkpoint/store.go:69`); no durable consumer |
| `INVESTIGATIONS.{package_id}.l2` | `subjects.InvestigationL2(packageID)` | `internal/decision/analyst/checkpoint/store.go:60` (`WithMsgID(packageID + ":l2")`) | Self-consumed on restart-resume (`internal/decision/analyst/checkpoint/store.go:80`) |

- **Payload schema:** L1 ->
  [`docs/schemas/l1_hypothesis.yaml`](schemas/l1_hypothesis.yaml); L2 ->
  [`docs/schemas/l2_verification.yaml`](schemas/l2_verification.yaml).
- **Retention:** stream `INVESTIGATIONS` (`internal/nats/streams.go:185`),
  `LimitsPolicy`, `MaxAge` 6h (tunable), `MaxMsgsPerSubject` 1 (one L1
  and one L2 retained per package so the resume read is the last
  checkpoint, never an accumulation), `Duplicates` 2m.
- **Sample subscription:** substitute a real package id for `{id}`:

  ```sh
  nats sub "INVESTIGATIONS.abc123.l1" --raw
  nats sub "INVESTIGATIONS.*.l1" --raw   # all L1 checkpoints
  ```

## Dynamic (templated) subjects

Per-id and per-pod subjects are built by validated functions rather than
string concatenation. Each builder validates every token with
`validateToken` (`internal/subjects/subjects.go:134`), which rejects an
empty token, the NATS-reserved characters (`.`, `*`, `>`), and
whitespace, then returns `(string, error)`. This is the canonical guard
against a hostile namespace, pod name, or package id injecting extra
subject levels.

The investigation checkpoint builders, verified by name and signature:

```go
// internal/subjects/subjects.go:204
func InvestigationL1(packageID string) (string, error)
// returns "INVESTIGATIONS." + packageID + ".l1"

// internal/subjects/subjects.go:213
func InvestigationL2(packageID string) (string, error)
// returns "INVESTIGATIONS." + packageID + ".l2"
```

Usage (the producer side, `internal/decision/analyst/checkpoint/store.go`):

```go
subj, err := subjects.InvestigationL1(packageID)
if err != nil {
    return err // packageID carried a reserved character
}
// publish the L1 hypothesis checkpoint under subj, deduplicated by
// the package id so a replay is server-side suppressed:
_, err = nc.PublishJS(ctx, subj, hypothesis, jetstream.WithMsgID(packageID+":l1"))
```

So for a package id `abc123`, `subjects.InvestigationL1("abc123")`
yields `INVESTIGATIONS.abc123.l1` and
`subjects.InvestigationL2("abc123")` yields
`INVESTIGATIONS.abc123.l2`.

The same validated-builder pattern backs the other templated subjects.
These builders exist in the subject contract and are validated, but are
not wired to an active producer in the current build (see
[Reserved subjects](#reserved-subjects)):

```go
func Correlated(namespace, pod string) (string, error) // olaitan.correlated.{ns}.{pod}  (subjects.go:151)
func State(namespace, pod string) (string, error)      // olaitan.state.{ns}.{pod}        (subjects.go:162)
func Health(ring string) (string, error)               // olaitan.health.{ring}            (subjects.go:175, rejects the reserved "heartbeat" token)
func Evidence(kind string) (string, error)             // olaitan.evidence.{kind}          (subjects.go:186)
```

## Reserved subjects

These subjects are defined in the subject contract (and several already
have a provisioned JetStream stream) but have no active producer and no
active consumer in the current wiring. They are documented here as a
reserved architectural contract so an integrator does not subscribe a
subject that will never receive traffic in this build. The payload-schema
and `nats sub` sample columns are intentionally omitted from the table
below: a reserved subject has no producer, so there is no payload to
schematise and no traffic to sample (the sample subscription for any
reserved subject is therefore "no producer in this build"). These
columns are populated for every live subject in the sections above.

| Subject / builder | Constant or builder | Status | Stream (if any) |
|---|---|---|---|
| `olaitan.events.normalised` | `Normalised` (subjects.go:31) | Stream provisioned; no producer or consumer in the current build (the correlator consumes raw events and publishes evidence packages directly) | `EVENTS`, `LimitsPolicy`, `MaxAge` 24h, `MaxBytes` 10 GiB (`internal/nats/streams.go:28`) |
| `olaitan.correlated.{ns}.{pod}` | `Correlated` builder (subjects.go:151) | Builder defined and validated; never called | none |
| `olaitan.threats.{watch,alert,act,isolate}` | `ThreatsWatch` / `ThreatsAlert` / `ThreatsAct` / `ThreatsIsolate` (subjects.go:39-43) | Stream provisioned for the severity-band routing contract; no producer or consumer (the FSM is driven directly off the evidence consumer) | `THREATS`, `LimitsPolicy`, `MaxAge` 7d (`internal/nats/streams.go:60`, covers `olaitan.threats.>`) |
| `olaitan.state.{ns}.{pod}` | `State` builder (subjects.go:162) | Builder defined and validated; never called. FSM state currently persists to Redis, not NATS | none |
| `olaitan.health.heartbeat`, `olaitan.health.{ring}` | `HealthHeartbeat` (subjects.go:123), `Health` builder (subjects.go:175) | Core NATS, no JetStream stream; ephemeral by design; no active producer or consumer in the current build | none (ephemeral) |
| `olaitan.evidence.{kind}` | `Evidence` builder (subjects.go:186) | Generic per-kind builder; never called. Only the `EvidencePackages` constant (`olaitan.evidence.packages`) is live | covered by the `EVIDENCE` stream (`olaitan.evidence.>`) |

`RawPrefix`, `CorrelatedPrefix`, `ThreatsPrefix`, `StatePrefix`,
`EvidencePrefix`, `HealthPrefix`, and `InvestigationPrefix` are prefix
constants, not published subjects: they are consumed by the per-source
constants and the builders above.

## Related references

- [Sigma extensions](sigma-extensions.md) - the OLT Sigma dialect and the
  payloads the rule engine produces from `olaitan.evidence.packages`.
- [Schemas](schemas/) - the committed JSON/YAML payload schemas the
  subject entries above reference.
- [Schema versioning](schema-versioning.md) - the `schema_version`
  convention and the dual-publish MAJOR migration policy that governs how
  these subject payloads evolve.
- [Architectural patterns](patterns.md) - the canonical NATS-subject
  constants pattern and the idempotency-key convention these producers
  follow.
- The canonical system architecture (rings, dataflow, the full subject
  contract) is the planning artefact `architecture.md`, referenced by
  the in-repo docs through `architecture.md:NNN` section anchors.
