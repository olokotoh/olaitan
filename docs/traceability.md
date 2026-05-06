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
| `c3.4-calico-flow-spike` | §3.4 | `spikes/calico-flow/` | `spikes/calico-flow/main_test.go` | `TestTranslateContract`, `TestRoundTripJSON`, `TestTimestampStability` | n/a |
| `c3.4-falco-syscall-adapter` | §3.4 | `internal/collector/falco/` | `internal/collector/falco/falco_test.go`, `internal/collector/falco/falco_integration_test.go`, `internal/collector/falco/translate_test.go`, `internal/collector/falco/health_test.go`, `internal/retry/retry_test.go` | `TestNew_RejectsNilPublisher`, `TestNew_RejectsEmptyEndpoint`, `TestNew_RejectsEmptyHostname`, `TestNew_AppliesDefaultRetryWhenZeroValued`, `TestNew_PreservesCallerSuppliedRetry`, `TestHealth_ReturnsTrackerInZeroState`, `TestAdapter_EndToEnd_Bufconn`, `TestAdapter_RetriesOnDialFailure`, `TestTranslate_HappyPath`, `TestTranslate_DeterministicIDFallback`, `TestTranslate_DifferentInputsYieldDifferentIDs`, `TestTranslate_HostEventWithoutPodFields`, `TestTranslate_MissingTimeReturnsError`, `TestTranslate_NilResponseReturnsError`, `TestTranslate_EmptyOutputFields`, `TestTranslate_PrioritySeverityMapping`, `TestSourceHealth_ZeroValueIsUnhealthy`, `TestSourceHealth_MarkHealthy`, `TestSourceHealth_MarkUnhealthyCarriesError`, `TestSourceHealth_MarkUnhealthyNilErrorIsAllowed`, `TestSourceHealth_HealthyClearsLastError`, `TestSourceHealth_ConcurrentReadersAndWriters`, `TestSourceHealth_StatusReturnsConsistentSnapshot`, `TestStrategyDo_SuccessOnFirstAttempt`, `TestStrategyDo_SuccessAfterTransientFailures`, `TestStrategyDo_MaxAttemptsExhaustionReturnsLastErrorWrapped`, `TestStrategyDo_ContextCancelMidBackoff`, `TestStrategyDo_ContextAlreadyCancelled`, `TestStrategyDo_ZeroValueReturnsConfigError`, `TestStrategyDo_InvalidConfigVariants`, `TestStrategyDo_BackoffProgressionRespectsMultiplier`, `TestStrategyDo_BackoffCappedAtMax`, `TestStrategyDo_JitterBoundsRespected`, `TestStrategyDo_UnlimitedAttemptsTerminateOnSuccess`, `BenchmarkAdapter_PublishLatency` | n/a |
| `c3.6.1-sigma-parser-spike` | §3.6.1 | `spikes/sigma-parser/` | `spikes/sigma-parser/wrap/main_test.go`, `spikes/sigma-parser/custom/main_test.go` | `TestFixturesAgainstRule`, `TestRuleMatchShape`, `TestParseOLTExtrasRejectsViolations`, `TestSeverityFallbackFromLevel`, `TestBuildCorpusFailsOnAnchorDrift`, `TestLintID`, `TestPatternMatchesModifiers`, `TestPatternMatchesErrors`, `TestEmptyPatternRejected`, `TestParseAndCondition`, `TestValidateRejectsDialectViolations`, `TestEvaluateExercisesParseAndCondition` | n/a |
| `c3.7.4-criu-checkpoint-spike` | §3.7.4 | `spikes/criu-checkpoint/` | `spikes/criu-checkpoint/main_test.go` | `TestKubeletCheckpointURL`, `TestTruncate` | n/a |
| `c3.8-helm-chart-skel` | §3.8 | `deploy/helm/olaitan/` | `deploy/helm/helm_test.go` | `TestDefaultPermutation`, `TestSubchartsDisabled`, `TestRedisDisabledOnly`, `TestRBACVerbs`, `TestPodSecurityContext`, `TestReplicasGuard`, `TestRedisAuthGuard`, `TestAuditWebhookCABundleGuard`, `TestEndpointsTemplated`, `TestAggregatorIsSingletonRecreate`, `TestNetworkPolicyDefault`, `TestAuditWebhookGate`, `TestKubeconform` | n/a |

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
