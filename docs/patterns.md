# Architectural Patterns

This document records the load-bearing code patterns a contributor must
reuse rather than reinvent. Each pattern is grounded in the actual
source that implements it (cited by file path) so the document cannot
drift from the code. Architecture reference: the canonical design lives
in the planning workspace `architecture.md` (see `docs/README.md` for
the link rationale); this file is the in-repo, code-grounded view.

Each entry follows a Context / Decision / Consequences / Alternatives
shape so the rationale, not just the rule, is preserved.

## 1. Canonical NATS-subject constants

**Context.** Every ring talks to every other ring over NATS subjects
only. A subject typed as a string literal at a call site is invisible
to a rename, can silently diverge from the stream binding, and (for the
per-pod and per-id subjects) can be poisoned by a hostile token that
injects extra subject segments.

**Decision.** All subjects live in `internal/subjects/subjects.go`.
Fixed subjects are named constants (`RawPrefix`, `Normalised`,
`OverridesApplied`, the `AUDIT.*` family, `INCIDENTS.finalised`,
`REPORTS.generated`, and so on). Parameterised subjects are produced by
validating builders, never by string concatenation at the call site:

```go
func Correlated(namespace, pod string) (string, error)
func State(namespace, pod string) (string, error)
func Health(ring string) (string, error)
func Evidence(kind string) (string, error)
func InvestigationL1(packageID string) (string, error)
func InvestigationL2(packageID string) (string, error)
```

Each builder calls `validateToken` (`subjects.go:132-148`), which
rejects the NATS-reserved characters `.`, `*`, `>` and any whitespace,
so a token can never inject an extra subject segment and the builder
output is never an accidental wildcard.

**Consequences.** A subject rename flows through one constant. The
JetStream coverage tests in `internal/subjects/subjects_test.go` pin
every constant to its expected string. Hostile per-pod or per-package
tokens fail closed at the builder rather than reaching the broker.

**Alternatives.** String-literal subjects at call sites were rejected
(invisible to rename, no injection guard). A reflection-based registry
was rejected as over-engineered for a fixed subject space.

## 2. Canonical Redis-key constants

**Context.** Redis keys span several families (baseline, checkpoint,
per-pod state, durable FSM state, operator overrides) with different
TTL policies. A literal key string risks colliding with a neighbouring
namespace or accidentally forming a Redis match pattern.

**Decision.** All keys live in `internal/keys/keys.go` and
`internal/keys/workload.go`. Each family has a prefix constant
(`BaselinePrefix = "baseline:"`, `CheckpointPrefix`, `StatePrefix`,
`EvidencePrefix`, `HealthPrefix`, `FSMStatePrefix = "fsm:"`,
`OverridePrefix = "override:"`) and a validating builder
(`FSMState(workloadID)`, `Override(workloadID)`, `FSMHistory(workloadID)`,
`BaselineMetrics(namespace, pod)`, `State(namespace, pod)`, and so on).
The package-level `validateToken` allows only `[A-Za-z0-9_.-]` (and
rejects the `-`/`+` XRANGE sentinels), so the Redis-reserved `:`, `*`,
`?`, `[` and whitespace can never appear in a token; a built key is
therefore never a pattern and never crosses a namespace boundary.
(Note this is an allowlist, unlike the NATS denylist in the subjects
pattern above.) A `Family` enum
(`keys.go:47-59`) drives TTL-policy enforcement per family (for
example the no-TTL `fsm:` family versus the natively-TTL'd `override:`
family).

**Consequences.** Every key carries a known prefix, so a `SCAN` over a
family is safe and a TTL policy attaches to a family rather than a
guessed key shape. Builder output cannot be a wildcard.

**Alternatives.** Literal key strings were rejected for the same
collision and pattern-injection reasons as literal subjects.

## 3. The self-describing envelope wrapper

**Context.** The evaluation capture harness drains several NATS
subjects, each carrying a differently-shaped payload, into a uniform
artefact set the analysis pipeline reads with one parser.

**Decision.** A self-describing envelope stamps each line with its
source contract and wraps the verbatim source payload. The canonical
implementation is `capture.Envelope` in
`internal/eval/capture/capture.go:79-84`:

```go
type Envelope struct {
    SchemaVersion string          `json:"schema_version"`
    PublishedAt   string          `json:"published_at"`
    Subject       string          `json:"subject"`
    Payload       json.RawMessage `json:"payload"`
}
```

`SchemaVersion` identifies the source contract (for example
`event.v1`, `evidence_package.v1`, `audit.assessments.v1`); `Payload`
is the raw decoded body, preserved byte-for-byte as `json.RawMessage`
so the wrapper never re-shapes or re-validates the producer's payload
(that is the producer's contract). The wrapper contract itself is
versioned by `EnvelopeSchemaVersion = "olaitan.eval.capture.envelope.v1"`
(`capture.go:39`).

A note on naming: the envelope is a concrete, non-generic struct, not a
Go generic `Envelope[T any]`. It deliberately carries `json.RawMessage`
rather than a type parameter so a single drain loop can wrap any source
payload without knowing its Go type. The same self-describing idea
appears in the deferred-queue envelope in
`internal/report/deferq/deferred.go:61` (`type envelope struct`, stamped
with an integer `envelopeSchemaVersion = 1`), which dead-letters an
undecodable or unknown-version head rather than blocking the drain.

**Consequences.** The analysis pipeline reads one shape across every
run. A new source subject is added by registering a new
`(subject, schema_version)` drain spec, not by changing the wrapper.

**Alternatives.** A generic `Envelope[T]` was not needed: the payload
is never unmarshalled inside the harness, so a type parameter would add
ceremony with no benefit. Re-validating the payload at capture time was
rejected (the producer already owns validation).

## 4. Error taxonomy: transient versus permanent

**Context.** The pipeline retries operations that can succeed on a
retry (a 5xx from an LLM provider, a throttled S3 PUT) but must fail
fast on operations that cannot (a 4xx misconfiguration, a malformed
request). A retry loop needs a single, consistent classification.

**Decision.** The operational error taxonomy is two-class: **transient**
(retryable) versus **permanent** (fail-fast). It is implemented
consistently across the tree:

- `internal/retry`: `retry.Permanent(err error) error` wraps an error as
  non-retryable, and `Strategy.Do` bails out immediately when it sees a
  `*PermanentError` via `errors.As`. Everything not so wrapped is treated
  as transient and retried under the backoff strategy.
- The LLM providers classify HTTP failures with `isPermanent`
  (`internal/agent/provider/claude/claude.go:399`, and the matching
  functions in `ollama` and `openai_compat`): a 4xx (except 408 request
  timeout and 429 rate limit) is permanent; 5xx, 408, 429, and transport
  errors are transient.
- The S3 report archive classifies with
  `IsTransientS3` (`internal/report/archive/s3.go:293`): 5xx, 408, 429,
  and `net.Error` timeouts are transient; 4xx misconfiguration is
  permanent.
- The source adapters classify publish failures with
  `isPermanentPublishError` (one per collector, for example
  `internal/collector/falco/falco.go:588`).

The observable surface of this taxonomy is a four-value metric status
enum (`internal/agent/provider/transport.go:25-28`):
`StatusSuccess = "success"`, `StatusTransient = "transient_failure"`,
`StatusPermanent = "permanent_failure"`, `StatusTimeout = "timeout"`.
The "four classes" a reader sees on the metrics are these four outcome
labels; the underlying retry decision is the two-class transient/permanent
split above (a timeout is a transient cause that exhausts its budget; a
success is the absence of an error).

Alongside the transient/permanent axis, each tier defines sentinel
errors for precondition failures that must fail fast regardless of
retry (`internal/decision/analyst`): `ErrNoCitableEvents`,
`ErrNoHypothesis`, `ErrProviderUnavailable`, `ErrCapViolation`,
`ErrSchemaViolation`. These are wrapped with `retry.Permanent` where a
retry would be pointless.

**Consequences.** One classification drives every retry loop, so a new
caller inherits the right behaviour by reusing `retry.Permanent` and the
per-tier `isPermanent`/`IsTransientS3` helpers rather than re-deciding.
The metric labels let an operator distinguish a misconfiguration
(permanent) from a flaky upstream (transient) on the dashboard.

**Alternatives.** A flat "retry everything N times" policy was rejected
because it would hammer a 4xx misconfiguration pointlessly and mask it
as a flake. A richer multi-class taxonomy was rejected as more than the
retry decision needs.

## 5. The redaction layer reuse contract

**Context.** Secrets can appear in evidence, in an LLM response, and in
a persisted forensic report. Redaction must be identical at every
boundary, and the audit trail of a redaction must never itself leak the
secret.

**Decision.** There is ONE pattern engine in `internal/report/redact/`,
reused at every boundary rather than re-implemented. The exported entry
points are:

```go
func Redact(pkg schema.EvidencePackage) (schema.EvidencePackage, []RedactionEvent)            // redact.go:288
func RedactAndAudit(pkg schema.EvidencePackage, sink *RedactionAuditSink) (...)               // redact.go:422
func RedactText(s string) (string, []RedactionEvent)                                          // redact.go:573
```

`Redact` walks an `EvidencePackage` and is called pre-LLM by the Ring-3
decision tier (Stories 3.5-3.7) and pre-persistence by the report path.
`RedactText` is the same engine applied to a single string (the DFIR
report narrative, Story 4.5). Both share the identical helper engine
(secret-key regex, JWT scan, key=value and colon-value scans), so the
redaction decision is single-source-of-truth and deterministic across
the pipeline. The audit contract (NFR15/NFR18): a `RedactionEvent`
records WHERE (`field_path`) and WHY (`reason`) a redaction happened,
never the redacted value, so the `AUDIT.redactions` trail is safe to
ship to a SIEM.

**Consequences.** A new boundary that needs redaction calls the existing
entry point; it never copies the patterns. The audit trail is safe by
construction because the engine never emits the secret value.

**Alternatives.** Per-boundary redaction implementations were rejected
(they would drift and risk one boundary leaking what another caught).
Logging the redacted value for debugging was rejected outright (NFR18).

## 6. Idempotency keys (JetStream dedup)

**Context.** A publish may be retried after a transient failure, and a
controller restart may replay a retained message. A consumer must not
double-process the same logical event.

**Decision.** Every publish that must be exactly-once carries a stable
`Nats-Msg-Id` via `PublishJS(..., natsjs.WithMsgID(id))`, and JetStream
deduplicates a re-publish of the same id within the stream's dedup
window. The id is a stable, content-derived key:

- The source adapters forward the event's own id, for example
  `natsjs.WithMsgID(ev.ID)` (`internal/collector/cni/cni.go:862`), so a
  retry the server already persisted is deduplicated within the 2-minute
  dedup window.
- The higher tiers compose a deterministic id from the logical identity
  of the event: `INCIDENTS.finalised` uses `package_id + ":" + finalised_at_ns`
  (so a drainer re-publish of the same finalisation is suppressed but a
  new incident after a CLEAN cycle is not); `REPORTS.generated` uses
  `incident_id + ":" + report_sha256`; the investigation checkpoints use
  `package_id + step`.

**Consequences.** A retry or a restart-replay of the same logical event
is a server-side no-op; a genuinely new event (a distinct id) is never
suppressed. Idempotency lives in one composable key per publisher, not
in consumer-side dedup state.

**Alternatives.** Consumer-side dedup tables were rejected as redundant
given JetStream's built-in `Msg-Id` dedup. A random message id was
rejected because it would defeat the dedup on retry.

## 7. Structured logging

**Context.** Logs are machine-consumed (a SIEM, a dashboard), so they
must be structured key-value records, not formatted prose.

**Decision.** The standard library `log/slog` is used directly with a
JSON handler. The root logger is built once in `cmd/olaitan/main.go:160`
and tagged with the ring and version:

```go
log := slog.New(slog.NewJSONHandler(stderr, nil))
log = log.With("ring", ring, "version", version)
```

Every log call passes structured fields as alternating key-value pairs,
for example `log.Error("startup: load config", "path", *cfgPath, "err", err)`.
Sub-components derive a child logger with `.With(...)` rather than
re-formatting context into the message string. There is no custom
logging abstraction over `slog`.

**Consequences.** Every record is queryable by field. The ring and
version are present on every line for free. A new component logs by
taking a `*slog.Logger` and calling it with fields.

**Alternatives.** A third-party logger (zerolog, zap) was rejected in
favour of the standard library `slog` (no dependency, structured by
default). Free-text log messages were rejected (not machine-queryable).

## 8. Source concurrency: one goroutine per source

**Context.** The architecture's per-source per-node throughput budget is
1000 events/sec (NFR1). A reader expects either a worker pool or an
explicit single-goroutine choice; the codebase makes a deliberate
choice and documents it.

**Decision.** Each source adapter under `internal/collector/<source>/`
runs a single goroutine per `Adapter` that handles connect, stream
consumption, translation, and publish, in order. See
`internal/collector/falco/falco.go:9-13` for the stated model and
`Adapter.Run(ctx context.Context) error` for the loop. The 1000
events/sec/source budget fits comfortably in one serialised goroutine,
which also preserves deterministic ordering within a source.
Parallelism, if it is ever warranted, is deferred to a future story and
would be measured first.

Concurrency in the system therefore happens at the ring level (several
independent source adapters, the FSM consumer goroutine, the durable
JetStream consumers, the buffered audit and redaction sinks), not via a
bounded worker pool inside a single source. There is no generic
worker-pool primitive in the tree, and adding one without a profiling
result that demands it is out of scope.

**Consequences.** Within-source ordering is deterministic and the
concurrency story is simple to reason about. A new source adapter
follows the same single-goroutine `Run` shape.

**Alternatives.** A bounded per-source worker pool was rejected as
premature: it would add ordering and back-pressure complexity for
throughput the single goroutine already meets (NFR1). The decision is
revisitable if profiling ever shows a single source saturating a core.
