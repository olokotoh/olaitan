# Traceability matrix

This file is the single source of truth for the code-to-thesis claim chain
required by NFR42. Every functional requirement, non-functional requirement,
and Chapter 3 methodology claim that lands in the codebase must be reflected
here with a row that points readers from the chapter to the package, the
tests that exercise it, and (where applicable) the evaluation runs that
produced its empirical numbers.

## Column schema (NFR42, verbatim)

The matrix table below carries exactly six columns, matching NFR42:

| Column          | Meaning |
|-----------------|---------|
| `claim_id`      | Stable slug of the form `c<chapter>.<section>[.<sub>]-<short-slug>`, e.g. `c3.8-helm-chart-skel`. The chapter and section anchor must match a real heading in `report/chapter-N-*.md`. The slug must be unique within the matrix and stable across re-renders. |
| `ch3_section`   | The Chapter 3 section heading the claim attaches to, prefixed with the section sign (e.g. `§3.8`). The matrix is currently scoped to Chapter 3; if Chapter 4 (Implementation and Results) lands its own claims they extend this column with `§4.x`. |
| `code_package`  | The Go package (or non-Go directory) that implements the claim, relative to the repository root and ending with a trailing slash. Single package per row keeps the diff narrow. If a claim spans multiple packages, split it into multiple rows under the same `claim_id` family or pick the canonical owner. |
| `test_files`    | Comma-separated list of test files that exercise the claim, relative to the repository root. Helm-chart Go tests, integration tests, and spike tests are all valid here. Empty cell is **not** allowed (use `n/a` only for rows that are intentionally test-free, with the rationale recorded in *Provenance* below). |
| `test_ids`      | Comma-separated list of `Test*` function names inside `test_files` that assert the claim. Names must be byte-equal to the `func Test...` line in source so `grep` finds them deterministically. |
| `eval_run_ids`  | Comma-separated identifiers from `_bmad-output/implementation-artifacts/eval-runs/` once the evaluation harness lands (Epic 5). Substrate, infrastructure, and spike rows that pre-date the harness use `n/a` and the rationale is recorded in *Provenance*. |

The schema is self-documenting in the sense NFR42 requires: a reader can pick
any row and trace the claim to ground without consulting an external
glossary.

## How rows are added

Every PR carries a `traceability_updated:` field in its body (enforced by
[`.github/PULL_REQUEST_TEMPLATE.md`](../.github/PULL_REQUEST_TEMPLATE.md))
and is gated by the
[`traceability` job](../.github/workflows/ci.yml) on every pull request.

- `traceability_updated: yes` requires that **this file** appears in the
  PR's changed-file list. Add a row (or amend an existing one) whose
  `claim_id` is unique, sort the table by `claim_id`, and update the
  *Provenance* annex below the table with the PR number, merge SHA, and the
  FRs/NFRs the PR satisfies or informs.
- `traceability_updated: no` requires a non-empty *Traceability rationale*
  section in the PR body explaining why the matrix is unaffected (typical
  cases: docs-only PRs that touch no FR/NFR, build-system tweaks already
  traced under an infrastructure NFR, code-review patch passes that reuse
  an existing row).

The CI gate is implemented at
[`.github/scripts/check-traceability.sh`](../.github/scripts/check-traceability.sh)
and unit-tested at `.github/scripts/check-traceability.bats`. See the
*Conventions* footer for the slug grammar and provenance conventions.

## Matrix

| claim_id | ch3_section | code_package | test_files | test_ids | eval_run_ids |
|---|---|---|---|---|---|
| `c3-traceability-bootstrap` | §3-meta | `docs/` | `.github/scripts/check-traceability.bats` | `AC6a: yes path with matrix change passes`, `AC6b: yes path without matrix change fails`, `AC6c: no path with non-empty rationale passes`, `AC6d: no path with HTML-comment-only rationale fails`, `AC6e: missing traceability_updated field fails`, `Invalid traceability_updated value fails` | n/a |
| `c3.4-audit-webhook-receiver` | §3.4 | `internal/collector/audit/` | `internal/collector/audit/translate_test.go`, `internal/collector/audit/audit_test.go`, `internal/collector/audit/audit_integration_test.go`, `internal/collector/audit/audit_bench_test.go`, `internal/sourcehealth/sourcehealth_test.go`, `deploy/helm/helm_test.go` | `TestTranslate_HappyPath`, `TestTranslate_RejectsZeroTimestamp`, `TestTranslate_RejectsFutureTimestamp`, `TestTranslate_RejectsEmptyAuditID`, `TestTranslate_NonResponseCompleteStage_ReturnsSentinel`, `TestTranslate_PodResource_PopulatesPodRef`, `TestTranslate_NonPodResource_ZeroesPodNameUID`, `TestTranslate_ClusterScopedResource_ZeroesNamespace`, `TestTranslate_StripsLargeRequestObject`, `TestTranslate_DeterministicEventID`, `TestTranslate_TagsCopied_NotAlias`, `TestTranslate_ForbidDecisionTagged`, `TestTranslate_AnonymousUser`, `TestTranslate_NilObjectRef`, `TestTranslate_NilEvent`, `TestTranslate_SecretsAccessIsWarning`, `TestTranslate_PodsExecIsWarning`, `TestTranslate_RawIsValidJSON`, `TestReceiver_HappyPath_Publishes_204`, `TestReceiver_Rejects_NonPOST`, `TestReceiver_Rejects_NonJSON`, `TestReceiver_Rejects_OversizePayload`, `TestReceiver_Rejects_NoClientCert`, `TestReceiver_Rejects_UnknownClientCA`, `TestReceiver_5xx_When_AllPublishesFailTransiently`, `TestReceiver_204_When_AllPublishesFailPermanently`, `TestReceiver_Health_FlipsHealthyOnFirstPublish`, `TestReceiver_Health_StalenessFlipsUnhealthy`, `TestNew_RejectsMissingFields`, `TestIntegration_HappyPath_PublishesToJetStream`, `TestIntegration_RetryDedup_AtLeastOnce`, `TestIntegration_TLSHandshakeWithCorrectCert`, `BenchmarkAdapter_PublishLatency`, `TestTracker_ZeroValueReportsUnhealthy`, `TestTracker_MarkHealthyClearsError`, `TestTracker_MarkUnhealthyRetainsError`, `TestTracker_MarkUnhealthyNilErr`, `TestTracker_LastWriterWins`, `TestTracker_Concurrent`, `TestAuditPolicyConfigMapRenders_WhenEnabled`, `TestAuditWebhookKubeconfigSecretRenders_WhenEnabled`, `TestAuditWebhookTLSSecretRenders_WhenEnabled`, `TestAuditWebhookFailsFast_WhenApiserverClientCertEmpty`, `TestAuditWebhookFailsFast_WhenClusterCADataEmpty`, `TestAuditWebhookGate_AllResourcesGated`, `TestDaemonsetMountsAuditTLSSecret_WhenEnabled`, `TestValidatingWebhookConfigurationUntouched` | n/a |
| `c3.4-calico-flow-spike` | §3.4 | `spikes/calico-flow/` | `spikes/calico-flow/main_test.go` | `TestTranslateContract`, `TestRoundTripJSON`, `TestTimestampStability` | n/a |
| `c3.4-containerd-cri-adapter` | §3.4 | `internal/collector/cri/` | `internal/collector/cri/translate_test.go`, `internal/collector/cri/cri_test.go`, `internal/collector/cri/cri_integration_test.go`, `internal/collector/cri/cri_bench_test.go`, `internal/nats/nats_test.go`, `deploy/helm/helm_test.go` | `TestTranslate_HappyPath_Started`, `TestTranslate_HappyPath_Created`, `TestTranslate_HappyPath_Stopped`, `TestTranslate_HappyPath_Deleted`, `TestTranslate_RejectsNilEvent`, `TestTranslate_RejectsZeroTimestamp`, `TestTranslate_RejectsNegativeTimestamp`, `TestTranslate_RejectsPreEpochTimestamp`, `TestTranslate_RejectsFutureTimestamp`, `TestTranslate_RejectsEmptyContainerID`, `TestTranslate_RejectsUnknownEventType`, `TestTranslate_NilSandboxStatus_GracefulDegradation`, `TestTranslate_NilMetadata_GracefulDegradation`, `TestTranslate_DeterministicEventID`, `TestTranslate_DeterministicEventID_SurvivesStrip`, `TestTranslate_ShortContainerID_NoPanic`, `TestTranslate_StripsLargeRawPayload`, `TestTranslate_AttemptZero_NoTag`, `TestTranslate_AttemptNonZero_TaggedRestart`, `TestTranslate_SandboxNotReady_TagApplied`, `TestTranslate_LabelsCopied_NotAlias`, `TestTranslate_NonAllowlistedLabelsDropped`, `TestTranslate_AllowlistedLabelsForwarded`, `TestTranslate_RawIsValidJSON`, `TestTranslate_DifferentEventsYieldDifferentIDs`, `TestNew_RejectsNilPublisher`, `TestNew_RejectsEmptySocketPath`, `TestNew_RejectsEmptyHostname`, `TestNew_RejectsNegativeDialTimeout`, `TestNew_RejectsNegativeStaleness`, `TestNew_DefaultsApplied`, `TestRun_ContextCancelExitsCleanly`, `TestRun_HealthFlipsOnConnectError`, `TestRun_PublishesTranslateableEvent`, `TestRun_DropsTranslateError_NoCrash`, `TestRun_TerminalPublishErrorIsDropped`, `TestRun_StalenessWatchdog_QuietButConnected_DoesNotFlipUnhealthy`, `TestRun_StalenessWatchdog_DisconnectedAndStale_FlipsUnhealthy`, `TestAdapter_EndToEnd_Bufconn`, `TestAdapter_DropsTranslateError_RealBoundary`, `BenchmarkAdapter_PublishLatency`, `TestStreamConfigsCoversContainerdLifecycleSubject`, `TestContainerdSensorAbsent_WhenDisabled`, `TestContainerdSensorRenders_WhenEnabled`, `TestContainerdSocketPathConfigurable`, `TestContainerdSensorMountsParentDirectoryNotFile`, `TestContainerdSensorEmptySocketPathFails` | n/a |
| `c3.4-falco-syscall-adapter` | §3.4 | `internal/collector/falco/` | `internal/collector/falco/falco_test.go`, `internal/collector/falco/falco_integration_test.go`, `internal/collector/falco/translate_test.go`, `internal/collector/falco/health_test.go`, `internal/retry/retry_test.go` | `TestNew_RejectsNilPublisher`, `TestNew_RejectsEmptyEndpoint`, `TestNew_RejectsEmptyHostname`, `TestNew_AppliesDefaultRetryWhenZeroValued`, `TestNew_PreservesCallerSuppliedRetry`, `TestHealth_ReturnsTrackerInZeroState`, `TestAdapter_EndToEnd_Bufconn`, `TestAdapter_RetriesOnDialFailure`, `TestTranslate_HappyPath`, `TestTranslate_DeterministicIDFallback`, `TestTranslate_DifferentInputsYieldDifferentIDs`, `TestTranslate_HostEventWithoutPodFields`, `TestTranslate_MissingTimeReturnsError`, `TestTranslate_NilResponseReturnsError`, `TestTranslate_EmptyOutputFields`, `TestTranslate_PrioritySeverityMapping`, `TestSourceHealth_ZeroValueIsUnhealthy`, `TestSourceHealth_MarkHealthy`, `TestSourceHealth_MarkUnhealthyCarriesError`, `TestSourceHealth_MarkUnhealthyNilErrorIsAllowed`, `TestSourceHealth_HealthyClearsLastError`, `TestSourceHealth_ConcurrentReadersAndWriters`, `TestSourceHealth_StatusReturnsConsistentSnapshot`, `TestStrategyDo_SuccessOnFirstAttempt`, `TestStrategyDo_SuccessAfterTransientFailures`, `TestStrategyDo_MaxAttemptsExhaustionReturnsLastErrorWrapped`, `TestStrategyDo_ContextCancelMidBackoff`, `TestStrategyDo_ContextAlreadyCancelled`, `TestStrategyDo_ZeroValueReturnsConfigError`, `TestStrategyDo_InvalidConfigVariants`, `TestStrategyDo_BackoffProgressionRespectsMultiplier`, `TestStrategyDo_BackoffCappedAtMax`, `TestStrategyDo_JitterBoundsRespected`, `TestStrategyDo_UnlimitedAttemptsTerminateOnSuccess`, `BenchmarkAdapter_PublishLatency` | n/a |
| `c3.6.1-sigma-parser-spike` | §3.6.1 | `spikes/sigma-parser/` | `spikes/sigma-parser/wrap/main_test.go`, `spikes/sigma-parser/custom/main_test.go` | `TestFixturesAgainstRule`, `TestRuleMatchShape`, `TestParseOLTExtrasRejectsViolations`, `TestSeverityFallbackFromLevel`, `TestBuildCorpusFailsOnAnchorDrift`, `TestLintID`, `TestPatternMatchesModifiers`, `TestPatternMatchesErrors`, `TestEmptyPatternRejected`, `TestParseAndCondition`, `TestValidateRejectsDialectViolations`, `TestEvaluateExercisesParseAndCondition` | n/a |
| `c3.7.4-criu-checkpoint-spike` | §3.7.4 | `spikes/criu-checkpoint/` | `spikes/criu-checkpoint/main_test.go` | `TestKubeletCheckpointURL`, `TestTruncate` | n/a |
| `c3.8-helm-chart-skel` | §3.8 | `deploy/helm/olaitan/` | `deploy/helm/helm_test.go` | `TestDefaultPermutation`, `TestSubchartsDisabled`, `TestRedisDisabledOnly`, `TestRBACVerbs`, `TestPodSecurityContext`, `TestReplicasGuard`, `TestRedisAuthGuard`, `TestAuditWebhookCABundleGuard`, `TestEndpointsTemplated`, `TestAggregatorIsSingletonRecreate`, `TestNetworkPolicyDefault`, `TestKubeconform` | n/a |

## Provenance (bootstrap rows, in arrears)

Per AC4, the four bootstrap rows above carry their merged-PR coordinates here
(rather than as extra table columns) so the matrix remains schema-pure to
NFR42 while the auditable chain is preserved row-for-row. New PRs from Story
1.6 onward append their own provenance block here whenever they add a row.

### `c3-traceability-bootstrap`

- **Story:** 1.5 (Traceability matrix bootstrap and PR template). Self-row, back-filled from Story 1.6 because PR number and merge SHA were not knowable at Story 1.5 PR-open time (chicken-and-egg).
- **Merge SHA:** `215f36e` (PR #12, 2026-05-04). Three commits on the merged branch: `21206dd` (initial), `2f310b0` (CI permissions fix on the new traceability job), `26d579c` (Copilot review patches: PR template wording aligned with gate, `strip_html_comments` docstring corrected).
- **FRs/NFRs:** NFR42 (satisfied; the matrix-or-rationale CI gate is now active on every PR). NFR34 (forward reference only; runbook sample row lands with Story 6.8).
- **ADRs:** none (cross-cutting infrastructure; no deferred decisions recorded).
- **eval_run_ids rationale:** infrastructure / process gate, not evaluation-bearing.

### `c3.4-audit-webhook-receiver`

- **Story:** 1.7 (Kubernetes audit webhook receiver).
- **Merge SHA:** *pending* (this PR).
- **FRs/NFRs:** FR2 (satisfied; the receiver ingests `audit.k8s.io/v1` `EventList` batches from the kube-apiserver and produces canonical `schema.Event` records of `Source=SourceAudit` + `Category=CategoryAudit`). FR6 (satisfied; per-event publish to `subjects.RawAudit` via `jetstream.WithMsgID(ev.ID)` for at-least-once with server-side dedup over the JetStream 2-minute window). FR8 (partially satisfied; the in-process `sourcehealth.Tracker` is wired and Story 1.12 will bind `Adapter.Health()` to the Prometheus gauge `source_healthy{source="kube_audit"}`). NFR1 (informed; the bench `BenchmarkAdapter_PublishLatency` measures p50/p99 receive→PubAck on a real embedded NATS server -- production-class measurement under load awaits Story 5.1 eval harness). NFR11 (informed; mTLS `RequireAndVerifyClientCert` is enforced on the receiver, with rejection counters for `method_not_allowed` / `unsupported_media_type` / `payload_too_large` / `decode_error`). NFR35 (satisfied; ≥80% line coverage on hand-written files in `internal/collector/audit/` and `internal/sourcehealth/`, integration test uses real boundaries (embedded NATS server + real HTTPS+mTLS handshake against synthetic CA)). NFR36 (informed; integration test exercises the receiver against the real `audit.k8s.io/v1` parser path and the real JetStream publish path -- apiserver-side audit policy enforcement is operator configuration, not part of the receiver contract; full envtest-driven flow deferred per Story 1.7 Task 8.5).
- **Architecture reconciliation:** The architecture document and the AC text use the phrase "ValidatingWebhookConfiguration audit-webhook variant". This is incorrect Kubernetes terminology -- admission webhook backends and audit webhook backends are distinct features. Story 1.7 implements the audit webhook backend (configured via the apiserver `--audit-webhook-config-file` flag pointing at a kubeconfig Secret); the existing `templates/validatingwebhookconfiguration.yaml` admission stub from Story 1.1 is left alone. See `deploy/helm/olaitan/AUDIT.md` for the full reconciliation and operator wiring.
- **ADRs:** none. The Path A vs Path B TLS choice (operator-supplied static cert vs cert-manager) is documented inline in Task 7 and `AUDIT.md`; a future ADR may capture the cert-manager migration if and when that hardening story lands.
- **Audit-policy filter scope:** `omitStages: [RequestReceived]`; `level: None` for high-volume kubelet/controller-manager read paths (events, endpoints, leases, nodes); `level: RequestResponse` for `secrets`, `configmaps`, RBAC and NetworkPolicy mutations; `level: Request` for `pods/exec`, `pods/portforward`, `pods/attach`; `level: Metadata` everywhere else. Documented in `deploy/helm/olaitan/files/audit-policy-default.yaml` and tunable via `auditWebhook.policy.custom`.
- **eval_run_ids rationale:** infrastructure adapter; the bench is for AC4 verification, not for the Epic 5 evaluation harness's per-scenario runs.

### `c3.4-containerd-cri-adapter`

- **Story:** 1.8 (containerd CRI lifecycle adapter).
- **Merge SHA:** `b1a80c4` (PR #17, merged 2026-05-08). Story 1.8 follow-up commit `97728e2` ("Story 1.8 follow-up: address bmad-code-review on PR #17") applied 28 patches (2 decisions resolved + 26 quality patches) on top of the main commit `8da123d` and is covered by this row.
- **FRs/NFRs:** FR3 (satisfied; the adapter ingests containerd CRI `ContainerEventResponse` messages via `RuntimeService.GetContainerEvents` server-streaming RPC and produces canonical `schema.Event` records of `Source=SourceRuntime` + `Category=CategoryLifecycle`). FR6 (satisfied; per-event publish to `subjects.RawRuntime` via `jetstream.WithMsgID(ev.ID)` for at-least-once with server-side dedup over the JetStream 2-minute window). FR8 (partially satisfied; the in-process `sourcehealth.Tracker` is wired and Story 1.12 will bind `Adapter.Health()` to the Prometheus gauge `source_healthy{source="runtime"}`). FR18 (prepared; the adapter emits `attempt:N` tags for sandbox restarts so the Welford engine in Story 1.17 can invalidate per-workload baselines on restart -- the consumer logic is owned by Story 1.17). NFR1 (informed; the bench `BenchmarkAdapter_PublishLatency` measures p50/p99 receive→PubAck on a real embedded NATS server with the AC3 50ms p99 gate baked in via `b.Fatalf` -- production-class measurement under load awaits Story 5.1 eval harness). NFR11 (informed; the host-socket mount is documented in `deploy/helm/olaitan/CRI.md` as privilege-equivalent to the existing Falco socket mount; threat model unchanged from the post-Story-1.6 baseline). NFR35 (satisfied; 85.1% line coverage on `internal/collector/cri/`, measured on the unit-test build only -- integration paths exercised separately under `-tags=integration` and not included in the headline figure -- with the integration test substrate using real boundaries (embedded NATS server + bufconn-backed real `runtime.v1.RuntimeService` gRPC server)). NFR36 (informed; integration test exercises the real protobuf decoder, the real JetStream publish path, and the real CRI gRPC client -- only the runtime-service implementation is in-process via bufconn, mirroring Story 1.6's Falco pattern. Kind-cluster e2e test deferred per Story 1.8 Task 7.6 to a future hardening pass).
- **Architecture / naming reconciliation:** The story epic and ACs read "source containerd / category lifecycle". The schema package (`internal/schema/event.go`) was bootstrapped with `SourceRuntime = "runtime"` (and `CategoryLifecycle = "lifecycle"`) so the adapter axis identifies the architectural layer rather than the specific implementation -- a future CRI-O adapter would publish on the same `RawRuntime` subject. The binding interpretation: `SourceRuntime` + `CategoryLifecycle` satisfies the AC's intent, and downstream correlators read by `Source` rather than by implementation, so the polymorphism is preserved. AC2's "payload includes the workload identity (`namespace/owner-kind/owner-name`)" is satisfied by populating `PodRef{Name, Namespace, UID, Node}` from `pod_sandbox_status.metadata` -- the canonical workload-id resolver (`internal/keys.WorkloadID`, lands in Story 1.11) computes `namespace/owner-kind/owner-name` from `PodRef` plus a K8s API call only at the moment workload-identity is needed, not in the adapter's hot path. Mirrors Stories 1.6 and 1.7.
- **ADRs:** none. The `SourceRuntime` vs `SourceContainerd` naming choice is documented in the package docstring (`internal/collector/cri/translate.go`) and in the PR description rather than as a separate ADR. The host-socket mount security boundary is documented in `deploy/helm/olaitan/CRI.md` rather than as a separate ADR; a future ADR may capture a `containerdSensor.runAsRoot` toggle if/when the chart adds one to lift the nonroot UID issue documented in CRI.md's troubleshooting section.
- **Watchdog design difference vs Stories 1.6/1.7:** CRI lifecycle events are sparse by design (a stable cluster with no Pod churn can go hours without an event). The staleness watchdog therefore only flips `MarkUnhealthy` when staleness AND a non-Ready connection state coincide -- "no events for an hour on a connected stream" is healthy. Locked in by `TestRun_StalenessWatchdog_QuietButConnected_DoesNotFlipUnhealthy`.
- **eval_run_ids rationale:** infrastructure adapter; the bench is for AC3 verification, not for the Epic 5 evaluation harness's per-scenario runs.

### `c3.4-calico-flow-spike`

- **Story:** 1.3 (Calico flow record export feasibility spike).
- **Merge SHA:** `ce9f9ca` (squash on `main`, 2026-05-01).
- **PR:** none (single-PR squash directly on `main`; ADR carries the durable record).
- **FRs/NFRs:** FR4 (informed, not satisfied; production wiring lands with Story 1.10).
- **ADRs:** ADR-2026-04-30-01 (Calico Goldmane gRPC API).
- **eval_run_ids rationale:** spike, pre-dates the Epic 5 evaluation harness.

### `c3.4-falco-syscall-adapter`

- **Story:** 1.6 (Falco gRPC sensor adapter).
- **Merge SHA:** `7d1d732` (PR #13, merged 2026-05-06). Story 1.6 follow-up commit `c358eed` ("Story 1.6 follow-up: address bmad-code-review on PR #13") landed alongside the main commit `3397791` and is also covered by this row.
- **FRs/NFRs:** FR1 (satisfied; the adapter ingests Falco gRPC syscall events and produces canonical `schema.Event` records of `Source: SourceFalco` + `Category: CategorySyscall`). FR8 (partially satisfied; the in-process `SourceHealth` tracker is wired and Story 1.12 will bind it to the Prometheus gauge `source_healthy{source="falco"}` per `architecture.md:946`). NFR1 (informed; the bufconn benchmark measured ~100 microseconds per event mean throughput, well inside the 50ms p99 budget; production-class measurement awaits Story 5.1 eval harness). NFR35 (satisfied; ≥80% line coverage on hand-written files in `internal/collector/falco/` and `internal/retry/`, integration test uses real boundaries (embedded NATS server + bufconn gRPC server)). NFR42 (satisfied; this row plus the back-filled `c3-traceability-bootstrap` row close the gate's first-PR onward contract).
- **ADRs:** none for the adapter itself. The Falco gRPC client choice (vendored protos at `internal/collector/falco/falcopb/` rather than the archived upstream `falcosecurity/client-go`) is documented in `internal/collector/falco/falcopb/README.md` rather than as a separate ADR; the deprecation of the upstream module is a pure circumstance, not a project decision worth ADR-ing.
- **eval_run_ids rationale:** infrastructure adapter; the bufconn benchmark is for AC3 verification, not for the Epic 5 evaluation harness's per-scenario runs.

### `c3.6.1-sigma-parser-spike`

- **Story:** 1.2 (Sigma parser strategy spike + OLT dialect spec).
- **Merge SHAs:** `c9acb45` (PR #8, initial spike, 2026-04-29) and `3b4bc34` (PR #9, Round 1 audit follow-up, 2026-04-30).
- **FRs/NFRs:** FR14, FR15 (informed, not satisfied; production engine lands with Story 1.15).
- **ADRs:** ADR-2026-04-28-01 (Sigma parser strategy: wrap upstream `sigma-go` + thin OLT validator).
- **eval_run_ids rationale:** spike, pre-dates the Epic 5 evaluation harness.

### `c3.7.4-criu-checkpoint-spike`

- **Story:** 1.4 (CRIU forensic checkpoint feasibility spike).
- **Merge SHA:** `205d7ff` (PR #11, 2026-05-04T08:10:23Z).
- **FRs/NFRs:** FR36 (informed, not satisfied; documented infeasible on the pinned containerd 1.7 runtime so Story 4.2 ships the kubectl-checkpoint Path A fallback by default).
- **ADRs:** ADR-2026-05-02-01 (CRIU infeasible on containerd 1.7; Path A default in Story 4.2).
- **eval_run_ids rationale:** spike, pre-dates the Epic 5 evaluation harness.

### `c3.8-helm-chart-skel`

- **Story:** 1.1 (Helm chart skeleton and cluster bootstrap, brownfield carry-over of the v1 Story 1.7 work).
- **Merge SHA:** `d269861` (PR #7, 2026-04-27).
- **FRs/NFRs:** FR46, FR47, NFR13 (satisfied).
- **ADRs:** ADR-2026-04-27-01 (Calico v3.29.0 reconciled), ADR-2026-04-27-02 (single distroless base image), ADR-2026-04-27-03 (Bitnami Redis OCI registry, accept current path with `Chart.lock` committed).
- **eval_run_ids rationale:** deployment substrate, pre-dates the Epic 5 evaluation harness; the harness will reference the chart by Helm release name, not by `eval_run_ids`.

## Conventions

- **`claim_id` grammar.** `c<chapter>.<section>[.<sub>]-<short-slug>`. The slug
  is lowercase, ASCII, hyphen-separated, and short (target ≤30 characters).
  It identifies the claim, not the implementing artefact, so a refactor that
  moves a package does **not** churn the `claim_id` (only `code_package`
  changes). Slugs are write-once and never renamed; if a claim is retired,
  the row is annotated and kept for audit, not deleted.
- **`eval_run_ids: n/a`.** Used for substrate (Helm chart, NATS subjects,
  Redis schema), infrastructure (CI gates, build pipelines), and feasibility
  spikes that pre-date the Epic 5 evaluation harness. Once the harness lands
  (Story 5.1), every row whose claim has empirical numbers in Chapter 4
  must back-fill this column with the canonical run identifier(s).
- **One ADR per row when one applies.** ADRs are recorded in
  `docs/deferred-decisions.md`. The matrix references them by ID
  (`YYYY-MM-DD-NN`) in the *Provenance* annex above. Multiple ADRs are
  comma-separated.
- **Sorting.** Rows are sorted by `claim_id` lexicographically. This makes
  the table byte-stable across re-renders and gives a natural §-order layout
  because the chapter prefix sorts first.
- **Provenance discipline.** Every new row added by a PR adds a
  *Provenance* sub-section (### `claim_id`) carrying the PR number, merge
  SHA, FRs/NFRs satisfied or informed, and any ADRs. The `traceability` CI
  gate does not parse this annex; it is for humans, but it is required by
  AC4 of the bootstrap story (Story 1.5) for every row.
- **Forward reference to NFR34.** Per NFR34, the operator runbook
  (`docs/runbook.md`, owned by Story 6.8) must include a sample matrix row
  in its on-boarding section so an operator copying the runbook can see the
  claim chain in situ. This file holds that obligation in trust until the
  runbook lands.
