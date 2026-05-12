# Deferred Decisions and ADRs

This file collects architecture decisions that were made (or deferred)
during implementation but did not warrant changes to the canonical
architecture document. Each entry is dated and captures: the choice
taken, the alternatives rejected, and any risk inherited.

Per the new epic plan, Stories 1.2 (Sigma rule parser strategy), 1.3
(Calico flow record export feasibility), and 1.4 (CRIU forensic
checkpoint feasibility) will write their spike outcomes here. This
file therefore exists from Story 1.1 onward.

---

## ADR-2026-04-27-01: Calico CNI version reconciled at v3.29.0

**Status:** Accepted.

**Date:** 2026-04-27.

**Context.** The new architecture document
(`_bmad-output/planning-artifacts/architecture.md`) names Calico 3.27
in its tech-stack section. The Helm-chart bootstrap script
(`deploy/demo/setup.sh`, written under v1 Story 1.7) pins
`CALICO_VERSION="v3.29.0"`. The two artefacts therefore disagreed.
Story 1.1 AC6 required this to be reconciled in exactly one direction.

**Decision.** Bump the canonical version to **v3.29.0** in the
architecture document and project memory. Do not regress the
bootstrap script.

**Why this direction.**

- v3.29.0 is the April 2026 stable release; v3.27 is roughly a year
  older. Pinning to the older version on a new install would inherit
  patches we do not need.
- The bootstrap script and Helm chart are already structured around
  the v3.29.0 manifest URL. Changing the script also means changing
  any operators who have already used it on their dev clusters.
- The architectural reasoning in `architecture.md` (NetworkPolicy
  GA, eBPF dataplane, IPv4 forwarding model) is unchanged between
  v3.27 and v3.29.0; the choice of major version is unaffected.

**Alternatives considered and rejected.**

- Downgrade the script to v3.27 to match the architecture text.
  Rejected because we would be installing an older version on a fresh
  evaluation cluster for the sake of a stale doc.
- Stay on the divergence with a comment. Rejected because the
  evaluation chapter cites the architecture as ground truth for
  reproducibility (`eval/manifest.yaml` will need a single
  authoritative version).

**Risk inherited.** None material. The chart's `kubeVersion`
constraint (`>=1.29.0`) is unchanged. Calico's NetworkPolicy
implementation moves forward only.

**Follow-ups.**

- Update `_bmad-output/planning-artifacts/architecture.md` tech-stack
  section: Calico 3.27 to v3.29.0. Done in this story.
- Update project memory (`project_olaitan.md`) to v3.29.0. Done in
  this story.
- Story 5.1 (`eval/manifest.yaml`) will record the exact pinned
  version when the reproducibility envelope is built.

---

## ADR-2026-04-27-02: Single distroless base for the Olaitan binary

**Status:** Accepted.

**Date:** 2026-04-27.

**Context.** Architecture.md tech-stack section originally prescribed
two distroless container bases:
`gcr.io/distroless/static:nonroot` for the controller and
`gcr.io/distroless/base:nonroot` for the agent — with a justifying
note that the agent "needs root for eBPF probe loading." This story
1.1 / Code Review pass surfaced that the chart in fact references a
single image (`{{ include "olaitan.image" . }}`) for both the
DaemonSet (collector) and the Deployment (aggregator), and the
Dockerfile uses `gcr.io/distroless/static-debian12:nonroot` for both.

**Decision.** Honour the chart's single-image reality. Use
`gcr.io/distroless/static-debian12:nonroot` as the canonical base.

**Why this direction.**

- The Olaitan agent does NOT load eBPF probes. That is the Falco
  subchart's responsibility; Falco runs as its own DaemonSet with
  its own container, its own privileged bits (only what eBPF needs),
  and its own image lifecycle. The Olaitan collector binary only
  consumes Falco events over the gRPC socket.
- Without the eBPF justification, there is no remaining reason for
  the agent to use `base` instead of `static`. Static is a smaller,
  more constrained surface; it is what the Dockerfile already uses.
- A single base simplifies CVE management: one upstream image to
  track, one tag floor in the Helm chart, one signature to verify
  in any future SLSA attestation flow.
- `static-debian12` is the current stable alias for `static:nonroot`
  on the upstream `gcr.io/distroless` registry. The two names point
  at the same image; using the explicit `-debian12` suffix pins the
  Debian release floor against future LTS rolls.

**Alternatives considered and rejected.**

- Split the chart into two image references (`controller.image`
  and `agent.image`) so the literal architecture wording could be
  honoured. Rejected because it adds operator-facing complexity for
  no security or operational benefit, and would require duplicate
  image build pipelines and CI smoke tests.
- Switch the agent to `base:nonroot` to match the architecture
  text. Rejected because the binary genuinely does not need anything
  in `base` over `static`; it would be a regression.

**Risk inherited.** None. The Dockerfile and Helm chart already
agree on the single-base reality; this ADR records the architecture
update that brings the doc into line with the running system.

**Follow-ups.**

- Update `_bmad-output/planning-artifacts/architecture.md` line 90
  to reflect the single-base reality. Done in this story.
- Story 7.x (forensic-evidence reproducibility) will pin the exact
  image digest in `eval/manifest.yaml` when the evaluation envelope
  is built.

---

## ADR-2026-04-27-03: Bitnami Redis OCI registry — accept current path

**Status:** Accepted (with risk note).

**Date:** 2026-04-27.

**Context.** The chart depends on Bitnami's Redis chart pinned at
version 25.3.11, served from `oci://registry-1.docker.io/bitnamicharts`.
In mid-2025 Bitnami announced that the free-tier OCI chart catalogue
was being relocated: legacy frozen versions moved to
`bitnamilegacy/charts`, while the maintained catalogue moved to a
paywalled registry. The pinned 25.3.11 is a frozen version on the
legacy track.

**Decision.** Keep the current `bitnamicharts` registry path for now
and commit `Chart.lock` to the repo so the digest of 25.3.11 is
pinned independently of the SemVer. If/when the upstream `bitnamicharts`
path stops serving 25.3.11, the team will switch to
`oci://registry-1.docker.io/bitnamilegacy` (or self-host the chart in
the Olaitan registry) in a dedicated story.

**Why this direction.**

- Switching registries blindly without verifying that
  `bitnamilegacy/redis:25.3.11` exists and resolves to the same
  digest carries its own risk. The current path works today.
- Committing `Chart.lock` (the pre-1.1 chart had it gitignored)
  pins the digest of the resolved subchart so a Bitnami retag at
  the same version no longer changes our manifest stream silently.
  This is the load-bearing reproducibility fix.
- If the upstream registry breaks, the failure mode is loud: CI's
  `helm dependency update` step fails, blocking the merge. We will
  see the breakage immediately.

**Alternatives considered and rejected.**

- Switch eagerly to `bitnamilegacy`. Rejected because we have not
  verified the destination registry serves the exact pinned digest;
  trading a working setup for an unverified one is a regression.
- Self-host the Redis chart in `ghcr.io/olokotoh`. Rejected because
  the chart artefact pipeline (sign + push) is itself non-trivial
  work that does not belong in a brownfield merge story.

**Risk inherited.**

- The `bitnamicharts` registry may stop serving 25.3.11 at some
  future date. Mitigated by `Chart.lock` (digest pin survives a tag
  yank) and by CI catching a registry break loudly. Story 1.x or
  Story 6.x can revisit if/when the breakage occurs.

**Follow-ups.**

- Commit `Chart.lock` to the repo (un-gitignore it). Done in this
  story.
- Update CI cache key to include `Chart.lock` so a re-tagged
  subchart at the same SemVer cannot resolve from cache to the old
  digest. Done in this story.
- Add a low-priority deferred-work item to revisit the registry
  choice after the Bitnami situation stabilises (or breaks).

---

## ADR-2026-04-28-01: Sigma parser strategy

**Status:** Accepted.

**Date:** 2026-04-28.

**Context.** Story 1.15 (OLT Sigma rule engine) needs a strategy for
parsing the OLT dialect of Sigma rules. The dialect adds Kubernetes-
native field references (`k8s.*`), an `attack:` annotation listing
MITRE ATT&CK technique IDs, and a project-local rule-ID grammar
(`OLT-(EXEC|NET|FILE|PRIV|IMPACT|RECON|PERSIST|EXFIL|CRED|LATERAL)-[0-9]{3}`)
to standard SIGMA-HQ Sigma. Three approaches are open: wrap an
existing Go Sigma parser and extend it via post-parse handlers, fork
one and patch the OLT extensions in natively, or hand-roll a custom
OLT-only parser. Story 1.2 is a time-boxed spike to settle the choice
before Story 1.15 starts.

The architecture document (`_bmad-output/planning-artifacts/architecture.md`,
line 332) named `siglens/siglens` and `bradleyjkemp/sigma-go` as the
two candidates to evaluate. SigLens is in fact an observability
platform (a unified Logs/Metrics/Traces store, alternative to Splunk)
whose repository was archived 2026-03-12 and which exposes no
importable Sigma parser. The architecture mention was a documentation
mistake. This ADR records the corrected candidate set; Story 1.2 also
patches architecture.md line 332 to drop the SigLens reference.

**Candidate inventory.** Three Go Sigma parsers were evaluated.

| Library | Licence | Last commit / tag | API surface | Modifier coverage |
|---|---|---|---|---|
| `github.com/bradleyjkemp/sigma-go` | MIT | `v0.6.6`, 2025-05-15; semi-dormant since | AST exposed via `ast.go`; arbitrary keys per `Event` map | Standard SIGMA-HQ modifier set per upstream `modifiers.go` (verified to compile against the 2025-05 snapshot; per-modifier behavioural verification deferred to a fork-path revisit, see *Modifier completeness risk* below) |
| `github.com/runreveal/sigmalite` | Apache 2.0 | commit `f180cb5`, 2025-09-18; active main, no tagged releases | `Rule.Extra` for unknown top-level fields; `MatchOptions.FieldResolver` for custom field lookup | Ten modifiers verified against the spike POC: `contains`, `all`, `startswith`, `endswith`, `windash`, `base64`, `base64offset`, `re`, `cidr`, `expand` |
| `github.com/markuskont/go-sigma-rule-engine` | Apache 2.0 | `v0.3.0`, 2023-09-25; unmaintained for over two years | `Selector` interface; `Matcher` tree traversal via `Match(event)`; no custom field-resolver hook | Modifier set in upstream `match/`; explicitly omits aggregations and the `Near()` operator per the upstream README. Per-modifier coverage table deferred — the unmaintained-status finding triggered rejection before a full enumeration was warranted |

Modifier-coverage rows for `sigma-go` and `markuskont/go-sigma-rule-engine`
were not reverified at the spike-POC layer because both candidates were
rejected on independent grounds (extension-surface fit and maintenance
status, respectively). The chosen library's modifier set was verified
against the POC's three fixtures plus the bench corpus; Story 1.15's
per-modifier conformance suite will close the verification gap if the
fallback path is ever reconsidered.

**Decision.** Take the **wrap-existing-parser** path, building on
`github.com/runreveal/sigmalite` (Apache 2.0; commit
`f180cb50a6a1bba454874c844500bd79f4b30a41` of 2025-09-18; no tagged
release as of 2026-04-28). Extend the upstream parser via two of
sigmalite's existing extension surfaces:

- `Rule.Extra map[string]Decoder` carries the OLT-only top-level
  fields (`attack:`, `severity:`). The OLT engine decodes these into
  typed Go values without forking the upstream YAML schema.
- `sigma.MatchOptions.FieldResolver` carries the OLT field-resolver,
  which routes `k8s.*` lookups to the workload-posture data and all
  other field lookups to the streaming-event field map.

The parser lands in `internal/decision/rules/parser/` under Story
1.15, importing sigmalite and the OLT extension code.

**Why this direction.**

- sigmalite is the only candidate that exposes both extension
  surfaces (`Extra` for unknown top-level fields and
  `FieldResolver` for custom field lookup) as first-class API. The
  `FieldResolver` interface was added in commit f180cb5 specifically
  for stream-processing scenarios that match Olaitan's per-
  EvidencePackage evaluation pattern.
- The wrap-path POC at `spikes/sigma-parser/wrap/main.go` evaluates
  `OLT-IMPACT-005` against three fixtures and passes 3-of-3 with
  ~300 lines of Go, none of which patches the upstream library. The
  failure-case POC at `spikes/sigma-parser/custom/main.go` ran the
  same fixtures through a hand-rolled parser at ~280 lines, but
  covers only the AND-condition subset and five modifiers.
- A wrap-path Story 1.15 inherits sigmalite's modifier coverage
  (`contains`, `all`, `startswith`, `endswith`, `windash`, `base64`,
  `base64offset`, `re`, `cidr`, `expand`) for free. A custom path
  re-implements all of them, plus the SIGMA-HQ condition grammar,
  plus a SIGMA-HQ regression suite.
- sigmalite's MIT-derivative Apache 2.0 licence is compatible with
  Olaitan's licence (MIT). No patent or copyleft entanglement.
- The OLT strict-superset claim (every standard SIGMA-HQ rule must
  remain parseable) is preserved by construction: the wrap path
  delegates everything outside the OLT namespaces to sigmalite's
  unmodified parser.

**Alternatives considered and rejected.**

- `bradleyjkemp/sigma-go` (MIT; latest tag `v0.6.6`; latest commit
  2025-05-15). Exposes its AST natively (`ast.go`) and has a longer
  production track record (Monzo Bank). Rejected for two reasons:
  the AST surface is more invasive to extend than sigmalite's
  `FieldResolver` (we would need a custom AST walker, where
  sigmalite gives us a typed callback); and the upstream is now
  semi-dormant (six months since the last commit), which inverts
  the maintenance-cost calculus relative to sigmalite's active main
  branch. sigmalite is itself a partial fork of sigma-go, so the
  "production miles" advantage is partly retained.
- `markuskont/go-sigma-rule-engine` (Apache 2.0; latest tag `v0.3.0`;
  latest commit 2023-09-25). Self-described as a reference
  implementation; explicitly does not implement aggregations or the
  `Near()` operator. Rejected because it has been unmaintained for
  over two years and its API does not expose a custom field-resolver
  contract (every field lookup walks `event[name]` directly, with
  no escape hatch for the workload-posture split OLT needs).
- `siglens/siglens` (named in architecture.md line 332). Not a Sigma
  parser; an observability platform. Repository archived 2026-03-12.
  Cannot be used.
- Fork `bradleyjkemp/sigma-go`. Rejected because forking adds the
  full burden of tracking upstream regression fixes and modifier
  additions for a benefit (deeper extension hooks) that the wrap
  path achieves with less code.
- Hand-rolled custom parser. Cost projection inferred from the
  `spikes/sigma-parser/custom/` POC: roughly 1500-2500 lines of Go
  plus 1500 lines of tests to reach SIGMA-HQ parity, two to four
  engineering weeks. The spike's POC handled only flat AND
  conditions and five modifiers in 280 lines; full grammar plus
  modifier coverage scales roughly linearly. Rejected on calendar
  grounds and on the strict-superset risk: a custom parser must be
  separately verified against the SIGMA-HQ regression corpus, where
  the wrap path inherits that verification from upstream.

**Maintenance and licensing implications.**

- New top-level Go dependency for the main module: `github.com/runreveal/sigmalite`
  pinned at commit `f180cb50a6a1bba454874c844500bd79f4b30a41`.
  Story 1.15 adds this dependency; Story 1.2 keeps it confined to
  `spikes/sigma-parser/wrap/go.mod` so the spike does not pollute the
  main go.sum.
- Licence: Apache 2.0. Compatible with Olaitan's MIT licence; the
  notice file under `internal/decision/rules/parser/` will carry an
  Apache 2.0 attribution line per the licence's Section 4(d).
- Upstream cadence is light but active (commits in 2025-09 and 2025-04).
  We pin by commit SHA rather than `latest` to keep parser behaviour
  stable across rule-corpus updates; bumps are explicit decisions.
- If sigmalite is abandoned, the fallback is the custom-parser plan
  in this ADR's "Fallback custom-parser plan" section.

**Risks inherited.**

- *Upstream stagnation risk.* sigmalite has no tagged releases. If
  the project is abandoned, Olaitan would need to either fork it or
  fall back to the hand-rolled custom-parser path (see fallback
  section). Mitigated by SHA-pinning and by the wrap-path
  architecture: switching to a fork is a single import-path edit
  rather than a re-implementation.
- *Modifier completeness risk.* sigmalite implements ten modifiers
  but its test coverage of edge cases (Unicode, empty patterns, the
  `expand` placeholder semantics) is uneven. Story 1.15 will add a
  property-based test (`gopter`) that exercises modifier combinations
  against generated event maps; any gaps surfaced there get patched
  upstream or in an OLT-side adapter, with the choice recorded in a
  follow-up ADR.
- *FieldResolver-only lookup risk.* When `MatchOptions.FieldResolver`
  is non-nil, sigmalite uses ONLY the resolver (it does not fall back
  to `LogEntry.Fields`). The OLT field-resolver therefore must
  resolve every field referenced by every rule, not just `k8s.*`
  fields. The wrap POC handles this by maintaining two lowered-key
  indices built once at fixture load: one for `k8s.*` posture
  fields, one for streaming-event fields. Lookups are O(1) and
  case-insensitive on field names. The dialect spec uses lowercase
  exclusively, so production-side rules and events are expected to
  match in case; the resolver folds case as a forgiving operator
  affordance, and the loader rejects fixtures whose source keys
  collide on case so the choice cannot mask data-quality issues.
  Story 1.15 inherits this contract and must test it against rules
  that reference exotic field names.
- *Strict-superset verification.* The "every SIGMA-HQ rule remains
  parseable" claim is asserted but not yet exercised against a real
  community-rule corpus. Story 1.15 must run a regression batch
  (e.g. the SigmaHQ rule pack's `cloud/k8s/` subset) through the
  wrap-path engine and record the pass count in its Completion Notes.

**Performance rough cut.**

Measured on the wrap-path POC (`spikes/sigma-parser/wrap/main.go`)
running `--bench`: 100-iteration warm-up plus 1000 timed iterations
per fixture, each iteration evaluating one fixture against a 10-rule
corpus (`OLT-IMPACT-005` plus nine `id`-mutated duplicates with
distinct IDs). The bench reports per-fixture stats so match-path
latency (positive fixture, full AND walk) and short-circuit-miss
latency (negative fixtures, early exit) are not conflated. The
resolver and `MatchOptions` are hoisted outside the timed loop so the
numbers reflect rule evaluation, not harness allocation. Percentile
indices use `(n-1)*99/100` so p99 of 1000 samples reads the 990th
position (zero-indexed 989).

| Fixture | Total (1000 iter) | Min | Median | p99 | Max |
|---|---|---|---|---|---|
| positive (full match) | 83.38 ms | 57.3 µs | 70.1 µs | 156.0 µs | 192.7 µs |
| negative_namespace (early exit) | 57.81 ms | 44.3 µs | 49.0 µs | 108.1 µs | 136.8 µs |
| negative_process (mid exit) | 65.07 ms | 49.2 µs | 54.8 µs | 111.9 µs | 134.5 µs |
| negative_missing_process (immediate exit) | 2.44 ms | 2.0 µs | 2.1 µs | 4.2 µs | 27.4 µs |

Hardware: Intel Core i7-10510U @ 1.80 GHz, Linux 6.17.0 x86_64.
Toolchain: Go 1.25.0 (linux/amd64), inside a `golang:1.25-alpine`
container. Numbers re-measured 2026-04-29 after the Round 1 patch
that hoists `MatchOptions` out of the timed loop; they are within
host-noise variance of the original 2026-04-28 measurements (the
positive-fixture median moved from 39.7 µs to 70.1 µs across runs,
attributable to container scheduling rather than a regression — the
patch removes per-call allocation, it does not add work). This is
a sanity check, not the NFR3 100 ms p99 contract; the production
gate is Story 1.15's to satisfy under realistic load (a 50-rule
corpus, full EvidencePackage matching, NATS-driven concurrency).
Match-path p99 of 156 µs at 10 rules gives roughly 600x headroom
under the NFR3 gate; flag in Story 1.15 if scaling to 50 rules
introduces non-linear overhead.

**Hand-off to Story 1.15.**

- *Library and version pin.* `github.com/runreveal/sigmalite` at
  commit `f180cb50a6a1bba454874c844500bd79f4b30a41` (2025-09-18).
  Add to the main module's `go.mod` when wiring the parser. The
  pin survives a tag yank because the SHA is content-addressed.
- *Parser landing path.* `internal/decision/rules/parser/` for the
  wrapper code, `internal/decision/rules/matcher/` for the OLT field
  resolver, `internal/decision/rules/loader/` for the corpus loader
  that reuses `internal/config/watcher` (see hot-reload note below).
- *Augmentation strategy.* Post-parse, not fork: read OLT extras
  from `Rule.Extra["attack"]` and `Rule.Extra["severity"]`, and
  install the OLT field resolver on `MatchOptions.FieldResolver`.
  Do not patch sigmalite source.
- *Test fixtures to migrate.* `spikes/sigma-parser/testdata/OLT-IMPACT-005.yaml`
  and `spikes/sigma-parser/testdata/fixtures/{positive,negative_namespace,negative_process}.json`
  migrate to `internal/decision/rules/testdata/positive/` and
  `internal/decision/rules/testdata/negative/` respectively under
  Story 1.15's TDD red-phase. The spike directory is then deletable.
- *Hot-reload substrate.* Reuse the existing `internal/config/watcher`
  Manager (Story 1.6, fsnotify-backed, 50 ms debounce, atomic.Pointer
  swap). Architecture.md line 343 mentions
  `k8s.io/client-go/tools/cache.NewFilteredListWatchFromClient`
  for ConfigMap watching; that is wrong about the current substrate.
  The fsnotify-on-projected-volume approach already implemented
  handles ConfigMap mounts correctly. Do not switch to client-go.
- *Return type.* The matcher returns `internal/schema.RuleMatch`
  (`internal/schema/detection.go`) for each matched rule. The wrap
  POC produces this struct verbatim; Story 1.15 inherits the same
  contract.

**Fallback custom-parser plan.**

If sigmalite is abandoned, retracts the `FieldResolver` interface,
or proves to have a regression we cannot work around, the project
forks the wrap-path code into a hand-rolled parser. Cost projection,
based on the spike's `custom/main.go` POC (280 LOC for AND-only,
five modifiers, no test coverage):

| Surface | LOC estimate |
|---|---|
| YAML rule shape and `attack:` / `severity:` | 200 |
| Full SIGMA-HQ condition grammar (AND, OR, NOT, parens, `1 of`, `all of`) | 600 |
| All ten modifiers | 400 |
| Field-resolver indirection | 150 |
| SIGMA-HQ regression suite (parsing tests against the SigmaHQ pack) | 800 |
| OLT-specific tests (lint, k8s.* binding, attack annotation) | 700 |
| **Total** | **2850** |

Two to four engineering weeks, depending on how much of the SIGMA-HQ
regression test suite is brought in verbatim versus rewritten. This
is the calendar-aware cost the project owner inherits if the wrap
path becomes unviable.

**Follow-ups.**

- Patch `_bmad-output/planning-artifacts/architecture.md` line 332 to
  drop the `siglens/siglens` reference and replace it with the
  candidate trio (sigma-go, sigmalite, go-sigma-rule-engine). Done
  in this story.
- Story 1.15 reads this ADR's "Hand-off" section verbatim and
  produces the production parser, matcher, and loader.
- Story 1.16 authors the initial ten-rule corpus against the
  dialect specified in `docs/sigma-extensions.md`.
- Story 6.5 (`cmd/olaitan-lint`) enforces the OLT rule-ID regex,
  the `attack:` annotation format, and the `k8s.*` namespace policy
  defined in `docs/sigma-extensions.md`.
- Project memory (`project_olaitan.md`) gets a new tech-stack entry
  for `github.com/runreveal/sigmalite` when Story 1.15 actually
  pulls the dependency into the main module. This story keeps the
  dependency confined to `spikes/sigma-parser/wrap/go.mod`.

---

## ADR-2026-04-30-01: Calico flow record export mechanism

**Status:** Accepted.

**Date:** 2026-04-30.

**Context.** Story 1.3 (Calico flow record export feasibility) is a
time-boxed spike to settle FR4's source choice before Story 1.10
implements the production adapter. The architecture document
(`_bmad-output/planning-artifacts/architecture.md:115-119`) listed
the question as an "Unknowns Requiring Spike Investigation" item:
which open-source mechanism does Calico expose for streaming flow
records into a sidecar consumer, and is the mechanism mature enough
to be the fifth signal source alongside Falco syscalls, Kubernetes
audit, containerd CRI lifecycle, and application logs.

The spike sat at `spikes/calico-flow/`. The architecture text
called out three candidate mechanisms (flow-log file tail, the
Tigera Enterprise flow API, and the Calico Goldmane gRPC API) plus
a fallback descope of FR4 if all three proved unworkable.

The corresponding architecture-vs-tooling reconciliation needed
recording here: ADR-2026-04-27-01 stated Calico's April 2026
stable release was v3.29.0. That was wrong; v3.31.5 was released
on 2026-04-15 as the actual April 2026 stable and is the release
that ships Goldmane. ADR-2026-04-27-01 is preserved as the
historical record; this ADR carries the corrected fact.

**Candidate inventory.** Three mechanisms were evaluated against
the spike's ACs.

| Mechanism | Status in v3.31.5 | Wire format | API surface | Operator-install cost |
|---|---|---|---|---|
| Calico Goldmane gRPC API | Tech preview, default-on under Tigera operator install | Protobuf streaming `goldmane.Flows.Stream` | Server-streaming RPC over mTLS at `goldmane.calico-system.svc:7443` | New install path: Tigera operator + custom resources (replaces manifest install) |
| Flow log file tail (`/var/log/calico/flowlogs/`) | OSS, file-based, opt-in via Felix `FlowLogsFileEnabled` | JSON-lines | File-system tail with rotation handling | None beyond enabling the Felix knob, but requires DaemonSet hostPath mount |
| Tigera Enterprise flow API | Enterprise-only | gRPC | Proprietary | Requires Calico Enterprise licence (out of scope for OSS-only Olaitan) |

**Decision.** Take the **Calico Goldmane gRPC API** path. Story
1.10 lands the production adapter at `internal/collector/cni/`,
consuming `goldmane.Flows.Stream` over mTLS, translating each
`FlowResult` into a canonical `schema.Event` of `Source:
SourceNetwork` and `Category: CategoryFlow`, and publishing to
`subjects.RawNetwork`.

**Why this direction.**

- Goldmane is the upstream-supported flow-export path for Calico
  OSS as of v3.31.5. The flow-log file tail is technically usable
  but inherits Felix's file-rotation timing and parsing-fragility
  surface (a Felix config change can rewrite the JSON shape, and
  multi-node tail requires per-node hostPath mounts plus a
  rotation-aware reader). gRPC streaming over a stable Service is
  the more durable contract.
- The spike's POC at `spikes/calico-flow/main.go` connects via
  mTLS, opens `Flows.Stream`, receives a `FlowResult` within ~3s
  on a kind cluster generating traffic, and translates it cleanly
  into the canonical schema. The translation function is reusable
  by Story 1.10 with only the `go_package` rewrite to relocate the
  vendored proto stubs.
- Goldmane runs at the cluster level (one Deployment in
  `calico-system`), not per-node. This is the inversion of the
  flow-log file tail (which requires per-node mounts) and matches
  Olaitan's existing collector-ring topology where each agent pod
  consumes one upstream Service.
- mTLS is enforced by Goldmane and matches the existing Olaitan
  TLS-by-default posture (see Story 1.7 audit-webhook).
- Performance: spike-measured translation overhead is median
  257us / p99 1.70ms per record on the spike hardware, well under
  NFR1's 50 ms p99 receive-to-publish budget. Headroom for the
  NATS publish portion is roughly 30x.

**Alternatives considered and rejected.**

- *Flow log file tail* (`/var/log/calico/flowlogs/`). Rejected for
  three reasons: (a) the JSON shape is Felix-version-dependent
  with no stable schema contract (each Felix point release has
  the latitude to add fields and reorder existing ones), (b)
  rotation timing is OS-driven and the consumer must handle
  partial-line writes, file-deletion races, and inotify-watch
  reattach across rotations, and (c) per-node hostPath mounts add
  PodSecurityPolicy / OPA Gatekeeper friction that the cluster-
  level gRPC path does not have.
- *Tigera Enterprise flow API*. Rejected on licence grounds. The
  project is OSS-only.
- *Descope FR4*. Rejected because the spike succeeded. Olaitan
  ships with four streaming sources plus the on-demand workload
  posture client only if the spike concluded no mechanism was
  workable; with Goldmane workable, the production agent has
  five streaming sources.

**Maintenance and licensing implications.**

- *Operator-install path required.* Goldmane is shipped only under
  the Tigera operator install path (the `tigera-operator.yaml`
  plus `custom-resources.yaml` pair from the v3.31.5 release).
  The manifest install path (the single `calico.yaml` URL that
  `deploy/demo/setup.sh` and `hack/bootstrap-kubeadm.md`
  currently use against v3.29.0) does not produce a Goldmane
  Deployment. **Story 1.10 therefore carries the bootstrap-
  migration cost: the production install path moves to the
  Tigera operator, and the `CALICO_VERSION` pin moves from
  v3.29.0 to v3.31.5.** This is the one-time-per-cluster cost
  flagged in the *Hand-off to Story 1.10* section below.
- *Tech-preview status.* Goldmane is documented as tech preview
  in the v3.31.5 release notes. The wire format and proto
  contract are not yet API-stable. Story 1.10 must pin the proto
  SHA (the `v3.31.5` tag commit at
  `2e4da40144aac869e1ed2cc220b6c4b62f32efdd`) and treat each
  Calico point-release bump as a re-verification gate. A regression
  story (Epic 6 hardening) can later switch to `buf push` against
  `buf.build/projectcalico/goldmane` if Calico publishes the proto
  to the Buf Schema Registry.
- *Proto vendoring.* The spike kept the generated stubs under
  `spikes/calico-flow/proto/` with the `go_package` pointing at
  the spike module. Story 1.10 relocates the stubs to
  `internal/collector/cni/goldmanepb/` and rewrites the
  `go_package` to the production path; this requires regenerating
  the `.pb.go` files via `buf generate` (the spike's `buf.gen.yaml`
  is reusable).
- *New main-module dependencies.* `google.golang.org/grpc v1.80.0`
  and `google.golang.org/protobuf v1.36.11` move from the spike's
  isolated `go.mod` into the main module. Story 1.10 runs
  `go mod tidy` and verifies no transitive breakage in existing
  packages.
- *mTLS cert provisioning.* Goldmane enforces mTLS on its gRPC
  listener; a server-only TLS handshake is rejected. The spike
  borrowed the `whisker-backend-key-pair` Secret (Tigera-CA-
  signed) as a stopgap; Story 1.10 must document operator-facing
  provisioning paths. Two paths are sketched in the Hand-off
  section: cert-manager-issued (production) and operator-
  extracted from an existing Tigera Secret (dev sandbox).
- *Licence.* The vendored Goldmane proto is Apache 2.0 (Calico's
  licence). Compatible with Olaitan's MIT.

**Risks inherited.**

- *Tech-preview proto churn.* Goldmane's proto contract may
  evolve in Calico v3.32 / v3.33. Each Calico point-release bump
  must re-verify the SHA pin, the `Flow.StartTime` semantics, the
  `FlowKey` field set, and the `Action` / `Reporter` / `EndpointType`
  enum values. Story 1.10's integration test against the captured
  byte fixture is the regression net.
- *FlowKey.source_name is GenerateName-derived.* Goldmane
  identifies workloads by "a set of pods that share a
  GenerateName" rather than by individual pod name. The canonical
  Olaitan workload identity (`namespace/owner-kind/owner-name`)
  cannot be derived from a `FlowKey` alone; enrichment requires a
  K8s API lookup against the namespace-and-set. Story 1.10
  populates `PodRef.Name` from `FlowKey.SourceName` verbatim and
  flags the GenerateName-derived nature via a
  `pod_name_kind:generatename` tag; the on-demand workload posture
  client (Story 1.11) is responsible for the enrichment downstream.
  Doing the K8s API lookup inline in the per-record translate path
  would violate the read-on-demand posture pattern and break the
  NFR1 50 ms latency budget.
- *Operator-install cost on existing clusters.* Operators with
  v3.29.0 manifest-install clusters must migrate to the Tigera
  operator install path to consume Goldmane. The bootstrap
  migration is the prerequisite Story 1.10 takes on.
- *mTLS cert rotation.* The dev-sandbox path of reusing a Tigera-
  issued Secret is rotation-unaware. cert-manager-issued certs
  (Path A) rotate automatically; the Path B operator-extracted
  certs require manual re-extraction on rotation. The
  documentation in Story 1.10's `CNI.md` flags this.

**Performance rough cut.**

Measured on the spike's bench harness (`spikes/calico-flow/main.go
--mode bench`): 100 timed iterations per real flow received from
the live Goldmane stream, each iteration translating one
`FlowResult` and JSON-marshalling the resulting `schema.Event`.
The gRPC client, JSON encoder, and translation function are
hoisted outside the timed loop so the recorded timings reflect
translation overhead, not harness allocation. Percentile indices
use `samples[(n-1)*99/100]` per the Story 1.2 review.

| Metric | Value |
|---|---|
| Samples | 100 |
| Min | ~200us |
| Median | ~257us |
| p99 | ~1.70ms |
| Max | ~2ms |

Hardware: Intel Core i7-10510U @ 1.80 GHz, Linux 6.17.0
x86_64 / Ubuntu 24.04.4. Toolchain: Go 1.26.2 linux/amd64.

This is **per-record translation overhead**, NOT the NFR1 receive-
to-publish gate that Story 1.10's bench owns. NFR1's gate adds the
JetStream publish portion (typically ~500us on embedded NATS);
the production p99 budget is 50 ms, giving roughly 30x headroom on
top of the spike numbers.

**Hand-off to Story 1.10.**

- *Library and version pin.* Calico v3.31.5 (released 2026-04-15).
  Goldmane proto pinned to SHA
  `2e4da40144aac869e1ed2cc220b6c4b62f32efdd` (the `v3.31.5` tag
  commit of `projectcalico/calico` at `goldmane/proto/api.proto`).
  `google.golang.org/grpc v1.80.0` and
  `google.golang.org/protobuf v1.36.11` move into the main module.
- *Adapter landing path.* `internal/collector/cni/` for the
  adapter (`cni.go`, `translate.go`, tests, bench), with the
  vendored proto stubs under `internal/collector/cni/goldmanepb/`
  matching the `internal/collector/falco/falcopb/` convention.
- *Bootstrap migration cost (the one-time-per-cluster entry cost).*
  Story 1.10 owns the install-path migration:
  - `deploy/demo/setup.sh`: bump `CALICO_VERSION="v3.29.0"` to
    `CALICO_VERSION="v3.31.5"`; replace the manifest-install
    invocation with the operator-install pair
    (`tigera-operator.yaml` + `custom-resources.yaml`).
  - `hack/bootstrap-kubeadm.md`: rewrite the "Install Calico CNI"
    section to walk through the Tigera operator install. Use this
    spike's "Bring-up sequence" as the canonical step list.
  - Append a separate ADR (`ADR-2026-05-DD-NN: Calico bootstrap
    migration to Tigera operator install`) documenting the
    migration cost.
  - The dev sandbox cannot run kubeadm end-to-end (Story 1.1 AC5
    lineage). Hardware verification is deferred to operator-side
    follow-up logged in
    `_bmad-output/implementation-artifacts/deferred-work.md`.
- *Field-mapping table.* The spike's `translate.go` is the
  authoritative reference. Field-by-field:

  | `schema.Event` field | `FlowResult` source | Notes |
  |---|---|---|
  | `ID` | `fmt.Sprintf("calico-flow-%d-%d", flow.StartTime, fr.Id)` | `FlowResult.Id` is not stable across Goldmane restarts; `StartTime` is the durable half. Deterministic per Story 1.6 / 1.7 / 1.8 / 1.9 precedent. |
  | `Timestamp` | `time.Unix(flow.StartTime, 0).UTC()` | Start of Goldmane's 15s aggregation window, not per-packet wall-time. Sigma rules using `timestamp` semantics must understand the aggregation window. Reject zero / pre-2010 / far-future. |
  | `Source` | `schema.SourceNetwork` | Existing constant value `"network"`. |
  | `Category` | `schema.CategoryFlow` | Existing constant value `"flow"`. |
  | `Pod.Name` | `key.SourceName` | GenerateName-derived; see `pod_name_kind:generatename` tag. |
  | `Pod.Namespace` | `key.SourceNamespace` | |
  | `Severity` | `"informational"` | Always informational at the adapter; severity escalation belongs to the OLT Sigma rule engine (Story 1.15) and the Welford baseline (Story 1.17). |
  | `Summary` | `fmt.Sprintf("%s/%s -> %s/%s:%d (%s, %s, %s)", srcNS, srcName, dstNS, dstName, dstPort, proto, action, reporter)` | Sanitize each interpolated field via `sanitizeForTag`. |
  | `Raw` | `protojson.Marshal(fr)` canonicalised through `encoding/json` | AC4 round-trip safe encoding. |
  | `Tags` | `proto:<...>`, `action:<...>`, `reporter:<...>`, `src-type:<...>`, `dst-type:<...>`, `dst-port:<...>`, optional `svc:<ns>/<name>`, optional `conns-started:<int>`, **plus `pod_name_kind:generatename`** | New tag in Story 1.10 lets the correlator (Story 1.14) drive K8s API enrichment via the posture client (Story 1.11). |

- *mTLS topology.* Goldmane enforces mTLS. Two operator-facing
  paths:
  - **Path A (preferred, production):** cert-manager issues a
    Certificate against a ClusterIssuer backed by the Tigera CA;
    the Helm chart consumes the resulting Secret. Cert rotation
    is automatic.
  - **Path B (dev sandbox):** operator extracts the Tigera CA
    bundle and a client cert from an existing Tigera Secret. The
    spike borrowed `whisker-backend-key-pair`; Story 1.10's
    `CNI.md` documents the procedure and flags it as not
    rotation-aware.
- *Test fixtures to migrate.* `spikes/calico-flow/testdata/sample-flow.binpb`
  (202 bytes, captured at the proto SHA pinned above) and
  `spikes/calico-flow/testdata/expected.json` migrate to
  `internal/collector/cni/testdata/`. Story 1.10 regenerates
  `expected.json` against the production translator after the
  binding decisions (new `pod_name_kind:generatename` tag, etc.)
  are applied.
- *Watchdog quiet-by-design.* Like Story 1.8 (containerd CRI) and
  Story 1.9 (applog), Goldmane flow records are quiet by design
  in a low-traffic cluster. Staleness alone must NOT flip
  unhealthy. Only stale-AND-not-Ready trips the source.
- *Spike-directory deletion.* `spikes/calico-flow/` is deletable
  once Story 1.10 lands the production adapter and migrates the
  fixtures. This ADR is the durable record.

**Follow-ups.**

- Patch `_bmad-output/planning-artifacts/architecture.md` lines
  115-119 to reflect the spike outcome (chosen mechanism: Calico
  Goldmane gRPC API, conditional descope path not activated).
  Owner: Story 1.10 if the patch is small, otherwise Story 5.10
  thesis-revision pass.
- Story 1.10 (Calico CNI flow adapter) reads this ADR's
  *Hand-off* section verbatim and produces the production
  adapter, the helm wiring, and the bootstrap migration.
- Story 1.11 (on-demand workload posture client) inherits the
  `pod_name_kind:generatename` tag contract and enriches
  GenerateName-derived `FlowKey.source_name` via a K8s API
  lookup at EvidencePackage-assembly time (Story 1.14
  correlator's call-out).
- Story 1.5 (traceability matrix bootstrap) records Story 1.3 as
  *informing* FR4; satisfaction lands in Story 1.10.
- Story 5.10 (thesis revision pass) inherits any chapter-3 text
  that committed to a specific flow-export mechanism before the
  spike concluded.

**Historical correction.** ADR-2026-04-27-01 stated that v3.29.0
was the April 2026 stable release of Calico. That was incorrect;
v3.31.5 was released on 2026-04-15 as the actual April 2026
stable and is the release that ships Goldmane. ADR-2026-04-27-01
is preserved in this file as the historical record (ADRs are
append-only by convention); this ADR carries the corrected fact.
The companion bootstrap-migration ADR
(`ADR-2026-05-DD-NN: Calico bootstrap migration to Tigera operator
install`) captures the implementation consequence.

---

## ADR-2026-05-02-01: CRIU forensic checkpoint feasibility

**Status:** Accepted.

**Date:** 2026-05-02.

**Context.** Story 4.2 (CRIU forensic checkpoint controller or
documented fallback) is the implementation half of FR36 (forensic
preservation of `PRESERVED+KILLED` workloads). The architecture
document defers the CRIU client choice to a feasibility spike
(`architecture.md:117`, `:205`, `:217`). Story 1.4 is that spike,
time-boxed to one to one-and-a-half days. The spike must answer
whether the kubelet's `ContainerCheckpoint` API can be used to
implement Story 4.2's `PRESERVED+KILLED` forensic-capture path on
the project's pinned Kubernetes 1.29 (`architecture.md:79`) /
containerd 1.7 / runc 1.1 (`architecture.md:80`) substrate, and if
not, whether the documented fallback (`kubectl logs --previous` plus
a debug-pod filesystem-tar snapshot) is sufficient.

**Decision.** **Story 4.2 ships the documented fallback path
(`internal/response/forensics/kubectl_fallback.go`) by default.**
The spike identifies two independent infeasibility blockers on the
pinned substrate, either of which is sufficient on its own to
require either the fallback or substrate-version bumps that the
project owner has not yet approved.

**Why this direction.**

- *Runtime stack blocker (project pin).* containerd 1.7 does not
  implement the `CheckpointContainer` CRI RPC. The implementation
  was wired in [containerd/containerd#6965](https://github.com/containerd/containerd/pull/6965),
  merged 2024-03-07 and assigned to the **containerd 2.0 milestone**.
  The change has not been back-ported to the 1.7.x line. The kubelet
  delegates the `POST /checkpoint/...` request to the CRI runtime
  via `CheckpointContainer`; on a containerd 1.7 cluster, the call
  surfaces as "unknown method" at the CRI layer (see also the K8s
  upstream tracking issue
  [kubernetes/kubernetes#113621](https://github.com/kubernetes/kubernetes/issues/113621)
  for the equivalent symptom on earlier containerd lines).
- *Kernel/CRIU compatibility blocker (substrate).* Even on the
  upstream stack inside this spike's kind cluster (containerd 2.0.2,
  runc 1.2.3, CRIU 3.17.1 from Debian bookworm), CRIU fails to
  initialise on Linux 6.17.0 with `vdso: Unexpected rt vDSO area
  bounds` (full log in `spikes/criu-checkpoint/README.md`). The
  kernel's vDSO layout is newer than CRIU 3.17.1 supports. The
  project's deployment substrate is Ubuntu 22.04 LTS, which ships
  kernel 5.15 (LTS) or 6.5 (HWE) — both of which CRIU 3.16.1-2
  (the jammy package) supports — so this blocker would not fire
  in production on the declared substrate. It nevertheless surfaces
  a kernel-vs-CRIU compatibility risk that Story 4.2 inherits if
  the deployment substrate ever drifts forward (HWE rolls, kernel
  6.x backports, Ubuntu 24.04 migration).

**Empirical evidence (this spike).** Three timed kubelet checkpoint
API calls against `criu-spike/busybox-target/busybox` on a kind
cluster pinned to `kindest/node:v1.29.14` with the
`ContainerCheckpoint` feature gate enabled at both apiserver and
kubelet levels:

| Run | HTTP | Wall-clock | Outcome |
|---|---|---|---|
| 1 | 500 | 140.5 ms | FAIL at CRIU vDSO init |
| 2 | 500 | 121.9 ms | FAIL at CRIU vDSO init |
| 3 | 500 | 136.9 ms | FAIL at CRIU vDSO init |

The 121-140 ms range is the round-trip to the CRIU initialisation
failure; no checkpoint archive is produced. The full
`criu-dump.log` is excerpted in `spikes/criu-checkpoint/README.md`.
The ContainerCheckpoint feature gate verified active on the kubelet
via `/api/v1/nodes/.../proxy/configz` returning `"ContainerCheckpoint":
true`. The Go harness, `go.mod`, unit tests, and Makefile are
checked in under `spikes/criu-checkpoint/` for reproducibility; they
will be deleted when Story 4.2 (or the fallback variant) merges and
this ADR remains the durable record.

**Kubernetes and runtime compatibility findings.**

| Component | Project pin | Spike measured | Required for kubelet checkpoint API |
|---|---|---|---|
| Kubernetes | 1.29 | 1.29.14 (matches) | API alpha at 1.25-1.29, beta at 1.30+; alpha requires `feature-gates: ContainerCheckpoint=true` on both apiserver and kubelet |
| containerd | 1.7 | 2.0.2 (skewed forward in kind v0.27.0) | **2.0+** for `CheckpointContainer` CRI RPC (PR #6965) |
| runc | 1.1 | 1.2.3 | 1.1.0+ for `runc checkpoint` with CRIU |
| CRIU | unpinned (production-substrate-supplied) | 3.17.1-2 (Debian bookworm); 3.16.1-2 ships in Ubuntu 22.04 jammy/universe | Linux ≥3.11 with `CONFIG_CHECKPOINT_RESTORE`; 3.17.1 incompatible with kernel 6.17.0 vDSO layout |

The project's eval-substrate pin (Ubuntu 22.04, CRIU 3.16.1-2,
kernel 5.15 LTS or 6.5 HWE) clears the kernel/CRIU blocker but not
the containerd 1.7 blocker.

**Checkpoint performance.** Empirical wall-clock-to-failure on this
host's kind cluster ranges 121-140 ms — these numbers reflect a CRIU
initialisation failure, not a successful checkpoint, and **do not**
inform the epics target of <5 s per typical workload
(`epics.md:546`) or NFR7's 10 s p99 for the full checkpoint-to-S3-
to-pod-delete cycle (`epics.md:1809-1810`). Story 4.2 must measure
checkpoint time on a substrate where CRIU initialises successfully;
no project-relevant performance data was obtainable in this spike.

**Privacy and security findings.** AC4's empirical
checkpoint-content inspection is conditional on AC3 succeeding;
because no archive was produced on this host, the spike could not
extract memory pages and grep them for cleartext secrets. The
privacy concern is nevertheless **carried forward**:

- A successful CRIU checkpoint embeds the full process memory image,
  open-FD state, mounted-namespace snapshots, and network-socket
  state. By construction this includes cleartext environment
  variables, in-memory secrets, ServiceAccount tokens loaded into
  the process address space, and unredacted log buffers.
- NFR15 (sensitive-data redaction before persistence) and NFR17
  (KMS encryption on S3) both apply to checkpoint archives.
  Story 4.2's S3 writer must KMS-encrypt and tag every forensic
  checkpoint as a secret-tier artefact.
- The text-redaction pipeline that Story 3.1 builds operates on
  text fields and **must not** be applied to binary CRIU memory
  pages — it would either corrupt the archive or fail silently.
  Story 4.2 either bypasses redaction for the checkpoint binary
  (with a documented justification) or implements a
  binary-aware redactor as a separate concern.

**Decision: documented fallback as default; CRIU as an option Story 4.2 flags as conditional.**

`internal/response/forensics/kubectl_fallback.go` ships under Story
4.2 as the default forensic-capture mechanism. It captures:

- `kubectl logs --previous` for each container in the pod (stdout,
  stderr, terminated-container last-state output).
- A debug-pod filesystem-tar snapshot of the pod's writable layers
  via `kubectl debug --image=busybox -- /bin/sh -c 'tar c /var/log
  /tmp /proc/1/...'` (or the equivalent shareProcessNamespace
  approach). Story 4.2 specifies the exact debug-pod recipe.
- The pod's spec, status, and recent events
  (`kubectl get pod ... -o yaml`, `kubectl describe pod ...`).

This captures contemporaneous state at containment time but not
process memory pages. For Olaitan's threat model — DFIR-grade
post-mortem of containment events — the kill-chain timeline,
exfiltration evidence in `/tmp` and `/var/log`, and the pod
manifest are the load-bearing forensic inputs. Memory-page
forensics (which the CRIU path would have provided) becomes a
Future Work item for Chapter 5.

**Alternatives considered and rejected.**

- *Bump containerd to 2.0+ as a Story 4.2 prerequisite.* This
  would unlock the kubelet checkpoint path. Rejected as the default
  because (a) containerd 2.0 was released 2024-11-05 and the project
  has no operational experience with it, (b) the bump touches
  `architecture.md:80`, `hack/bootstrap-kubeadm.md`, the Helm
  chart's `kubeVersion` constraint, and `eval/manifest.yaml`
  reproducibility (NFR37) — each is a multi-file change with
  cluster-bringup verification gates. Story 4.2 may revisit if the
  project owner explicitly approves the bump.
- *Bump Kubernetes to 1.30+ to graduate the API to beta.* The
  feature-gate alpha-vs-beta status is **not** the binding
  blocker — the spike confirmed empirically that the alpha gate
  enables cleanly on K8s 1.29. The runtime is the binding blocker.
- *Direct `runc checkpoint` bypassing the CRI.* Sidesteps the
  containerd 1.7 RPC gap by invoking runc directly on the node.
  Rejected because it requires shell access to the node's
  `runc` binary, container-ID discovery via `crictl`, and a
  custom controller-side binary that ships outside the K8s API
  surface. The project's controller is a Kubernetes operator;
  reaching past the kubelet to invoke runc breaks the abstraction
  and re-introduces the kernel/CRIU compatibility risk without
  the substrate-version lever.
- *`crictl checkpoint`.* Same containerd-1.7 RPC blocker; the
  CLI is a thin wrapper over `CheckpointContainer`.
- *Switch the CRI runtime from containerd to CRI-O.* CRI-O has
  shipped checkpoint support since 1.25. Rejected as too
  substrate-disruptive for this stage of the project; no
  brownfield CRI-O experience.

**Risks inherited.**

- *Memory-page forensics excluded from MVP.* Story 4.2's fallback
  captures filesystem and log evidence but not in-memory state.
  Chapter 5 must declare this as Future Work and note it limits
  detection of in-memory-only payloads (fileless malware, JIT'd
  loaders). The DFIR rubric (RQ5, Story 5.7) must be designed
  knowing the fallback's scope so its evaluation is not graded
  against a CRIU-grade memory-image baseline.
- *Substrate kernel drift risk if the project later adopts
  CRIU.* If Story 4.2 (or a successor) is reopened to ship CRIU,
  the kernel-vs-CRIU compatibility check must run on every
  evaluation cluster: `criu check --all` is the gate.
- *containerd version skew between kind dev clusters and the
  production kubeadm cluster.* The spike used containerd 2.0.2 in
  kind; production runs containerd 1.7. Any future spike or test
  that uses kind nodes for CRI-level behavioural verification
  must explicitly note this skew or pin a kind version that
  ships containerd 1.7 (kind v0.20.x).
- *No live CRIU performance data for the project's substrate.*
  Story 4.2 cannot inherit measured numbers from this spike —
  the 121-140 ms wall-clock is failure-time, not checkpoint-time.

**Hand-off to Story 4.2.**

Story 4.2 implements *one of* the following two paths. Default is
the fallback; the CRIU path activates only on explicit project-owner
approval of the substrate bumps.

*Path A — Documented fallback (default).*

- *File.* `internal/response/forensics/kubectl_fallback.go` plus
  `kubectl_fallback_test.go`. The map at `architecture.md:954`
  binds FR36 to `internal/response/forensics/`; that mapping
  remains correct.
- *Capture inputs.* For each container in the doomed pod:
  `kubectl logs <pod> -c <container> --previous` (terminated
  container's last-state log), `kubectl logs <pod> -c <container>`
  (current logs), plus pod spec, status, and recent events
  via the typed client-go API.
- *Filesystem snapshot.* A debug-pod runs against the doomed
  pod's node, mounts the kubelet's pod-volumes path read-only,
  and `tar`s the pod's writable layers. Exact recipe in Story 4.2.
- *S3 contract.* Same FR45 contract as the CRIU path would have
  used: content-addressed by SHA-256, KMS-encrypted (NFR17),
  written under `s3://<bucket>/<incident-id>/forensic-bundle.tar.gz`.
  Object Lock applies. Story 4.7 (forensic-write retry and
  deferred queue) inherits this object shape.
- *Settling window.* Story 4.3's settling window applies
  unchanged — capture begins after the FSM enters
  `PRESERVED+KILLED` and before `kubectl delete pod`.

*Path B — CRIU forensic checkpoint (conditional, requires
project-owner approval of substrate bumps).*

- *Prerequisite 1: containerd 2.0+ on the production kubeadm
  cluster.* `architecture.md:80` updates to `containerd 2.0+
  with runc 1.2+`; `hack/bootstrap-kubeadm.md` updates the apt
  source pin; `eval/manifest.yaml` updates the runtime version
  cell. Each is a multi-file change with its own verification
  gate; Story 4.2 cannot satisfy them on its own — they are
  prerequisite stories the project owner must schedule.
- *Prerequisite 2: CRIU package installed on every node.* Add
  to `hack/bootstrap-kubeadm.md` as a step alongside the
  containerd install. Pin to the jammy `criu 3.16.1-2` package
  unless the cluster also bumps to a newer Ubuntu (which
  introduces its own kernel-vs-CRIU compatibility check via
  `criu check --all`).
- *Prerequisite 3: `ContainerCheckpoint` feature gate enabled.*
  At K8s 1.29 alpha (`feature-gates: ContainerCheckpoint=true`
  on apiserver and kubelet) or, if the project also bumps to
  K8s 1.30+, no flag is required (beta default-on).
- *File.* `internal/response/forensics/criu.go` plus tests.
  The map at `architecture.md:954` binds FR36 to
  `internal/response/forensics/`; that mapping remains correct.
- *Capture path.* The controller calls the kubelet's
  `POST /checkpoint/{namespace}/{pod}/{container}` endpoint via
  the Kubernetes API server's `nodes/proxy` subresource. The
  kubelet writes the archive to `/var/lib/kubelet/checkpoints/`;
  the controller streams it out via a privileged sidecar or a
  debug-pod with the `/var/lib/kubelet` hostPath mount.
- *Privacy contract.* The archive is treated as a
  secret-tier binary artefact: KMS-encrypted on S3 (NFR17),
  redaction pipeline NOT applied (binary memory pages cannot
  pass through a text redactor), retention controlled by the
  same Object Lock window as Path A.
- *Performance contract.* Story 4.2 must measure on the
  production substrate; the spike provides no usable numbers.
  If median checkpoint time exceeds 5 s (`epics.md:546`) or p99
  exceeds the 10 s NFR7 budget (`epics.md:1809-1810`),
  Story 4.2 escalates to the project owner before merging.

*Test fixtures from `spikes/criu-checkpoint/` that should inform
Story 4.2.* The busybox `workload.yaml` deployment that loops a
`secret-marker=should-not-be-cleartext` line per second is reusable
as a Story 4.2 integration-test fixture for the privacy assertions.
The Go harness URL-construction logic (`kubeletCheckpointURL`) maps
directly to the production controller's URL builder if Path B is
taken.

**Thesis (Ch3 + Ch5) implications.**

Chapter 1 §1.6 currently describes the forensic preservation
feature without committing to a memory-image baseline. No edit
needed there.

Chapter 3 *does* commit to memory-image forensics in two places
that contradict this ADR's Path A default and must be revised once
Story 4.2 implements the fallback:

- *§3.7.1 (state table row, `chapter-3-methodology.md:160`)*
  currently reads "pod state preserved via container checkpoint
  (CRI-O CRIU), then pod deleted." Suggested replacement:
  "the doomed pod's logs, manifest, recent events, and writable-
  layer filesystem are captured to S3 by the `ForensicsController`
  before pod deletion; memory-image checkpoint via CRIU is
  conditional on a substrate uplift — see ADR-2026-05-02-01."
- *§3.7.4 ("Forensic State Preservation",
  `chapter-3-methodology.md:186`)* currently reads
  "the `ForensicsController` invokes the container runtime's
  checkpoint API (CRIU via CRI-O or containerd) to capture a
  memory and filesystem snapshot of the running container before
  deletion." Suggested replacement: replace the CRIU-centric
  description with the fallback's capture set (`kubectl logs
  --previous` for each container, a debug-pod filesystem-tar of
  the pod's writable layers, pod spec/status/events via the K8s
  API), retain the "stored in a configurable S3-compatible object
  store … KMS encryption (NFR17), content-addressed by SHA-256
  (FR45)" wording, and add a closing sentence noting that memory-
  image checkpoint is a Path B option conditional on the
  substrate prerequisites in ADR-2026-05-02-01.

Chapter 5 (Future Work) gains an entry along the lines of:
"Memory-image forensics (CRIU container checkpoint) deferred
pending substrate-version uplift to containerd 2.0+; the fallback
path captures kill-chain evidence sufficient for the DFIR rubric
(RQ5) but cannot reconstruct in-memory adversary state.
Engineering scope to enable: a kernel-vs-CRIU compatibility gate
(`criu check --all` on every node), the substrate bumps listed in
ADR-2026-05-02-01 Path B prerequisites, and a binary-aware
forensic redactor for archive content if regulatory contexts
require redaction before persistence."

Story 5.10 owns the actual edits in both Ch3 §3.7.1 / §3.7.4 and
the Ch5 Future Work entry; this ADR carries the reference points
and the wording seeds.

**Follow-ups.**

- Patch `_bmad-output/planning-artifacts/architecture.md` line 117
  (the "CRIU forensic checkpoint feasibility" Unknowns bullet) to
  reflect this spike's conclusion. Done in this story (Task 6.1).
- Patch `_bmad-output/planning-artifacts/architecture.md` line 205
  (the "CRIU client (deferred until spike result is known)" line)
  to name the chosen fallback. Done in this story (Task 6.2).
- Add a row to `spikes/README.md` under "Active spikes" matching
  the Story 1.2 and 1.3 row format. Done in this story (Task 6.3).
- Story 4.2 reads this ADR's "Hand-off to Story 4.2" section
  verbatim, defaults to Path A, and gates Path B on explicit
  project-owner approval of the substrate prerequisites.
- Story 1.5 (traceability matrix bootstrap) records Story 1.4 as
  *informing* FR36 — satisfaction lands in Story 4.2 (Path A or
  Path B depending on the project owner's choice).
- Story 5.10 (thesis revision pass) inherits both the Ch3 §3.7.1
  / §3.7.4 contradictions flagged above and the Ch5 Future Work
  entry described above.

---

## ADR-2026-05-12-01: Calico bootstrap migration to Tigera operator install

**Status:** Accepted.

**Date:** 2026-05-12.

**Context.** Story 1.10 ships the Calico CNI flow adapter, which
consumes the Calico Goldmane gRPC API. Goldmane is shipped only
under Calico's Tigera operator install path (the
`tigera-operator.yaml` plus `custom-resources.yaml` pair from the
v3.31.5 release manifests); the manifest install path that
`deploy/demo/setup.sh` and `hack/bootstrap-kubeadm.md` currently
codify against v3.29.0 does not produce a Goldmane Deployment.
ADR-2026-04-30-01 flagged the bootstrap migration as the
prerequisite cost Story 1.10 inherits.

ADR-2026-04-27-01 codified the v3.29.0 pin under the (incorrect)
belief that v3.29.0 was the April 2026 stable Calico release.
ADR-2026-04-30-01 records the corrected fact: v3.31.5 was
released 2026-04-15 as the actual April 2026 stable, and is the
release that ships Goldmane. This ADR captures the implementation
consequence of that correction.

**Decision.** Migrate the cluster bring-up procedure to the
**Tigera operator install path** on Calico **v3.31.5**:

1. `deploy/demo/setup.sh` bumps the `CALICO_VERSION` pin from
   `v3.29.0` to `v3.31.5` and replaces the manifest-install
   invocation with the operator-install pair.
2. `hack/bootstrap-kubeadm.md` rewrites the "Install Calico CNI"
   section to walk through the Tigera operator install (`kubectl
   create -f tigera-operator.yaml` followed by `kubectl create
   -f custom-resources.yaml` from the v3.31.5 release).
3. `deploy/helm/olaitan/CNI.md` documents the Goldmane Service
   surface (`goldmane.calico-system.svc:7443`) and the mTLS
   cert-provisioning paths.

The dev sandbox cannot run `kubeadm init` plus a Tigera operator
install end-to-end (same constraint as Story 1.1 AC5). Hardware
verification is deferred to operator-side follow-up logged in
`_bmad-output/implementation-artifacts/deferred-work.md`. The
documented procedure plus the spike's kind smoke test
(`spikes/calico-flow/README.md`, "Bring-up sequence", verified
end-to-end on a kind cluster) is the verification artefact.

**Why this direction.**

- Goldmane is the upstream-supported flow-export path for Calico
  OSS as of v3.31.5 (ADR-2026-04-30-01). The flow-log file tail
  alternative carries higher fragility (per-node hostPath mounts,
  Felix-version-dependent JSON shape, rotation-aware reader); the
  cluster-level gRPC path is the more durable contract.
- v3.31.5 is the corrected April 2026 stable; v3.29.0 was the
  result of ADR-2026-04-27-01's historical mistake. The version
  bump is a one-time-per-cluster operator cost, not an ongoing
  maintenance burden.
- Goldmane supports iptables, eBPF, and nftables dataplanes
  (verified in the spike's AC1 inventory). Clusters running the
  iptables dataplane are unaffected by the install-path change
  beyond the manifest swap.
- The Helm chart's `kubeVersion: ">=1.29.0"` constraint is
  unchanged: Tigera operator v3.31.5 supports Kubernetes 1.29
  through 1.31 inclusive.

**Alternatives considered and rejected.**

- *Stay on v3.29.0 manifest install and descope FR4 to four
  streaming sources.* Rejected: the Story 1.3 spike succeeded,
  so the descope is no longer the right tradeoff (FR4 is fully
  achievable with the operator install path). Shipping the
  agent without Calico flow records would forfeit S3 (lateral
  movement) and S4 (C2 beaconing) detection coverage in the
  evaluation plan.
- *Bump to v3.30.x instead of v3.31.5.* Rejected: v3.31.5 is
  the corrected April 2026 stable; jumping the line by one
  minor version with no justification trades reproducibility for
  no benefit. The spike captured fixtures against v3.31.5.
- *Self-host the v3.31.5 operator manifests in the Olaitan
  registry.* Rejected: adds a manifest-signing pipeline that
  does not belong in a feature-implementation story. The
  upstream operator manifests are content-addressed by tag and
  Calico has not yanked v3.31.5 in the weeks since release.
- *Run two install paths in parallel (v3.29.0 manifest for
  existing clusters, v3.31.5 operator for new clusters).*
  Rejected: doubles the substrate-verification surface and
  splits the eval-cluster pin. One canonical install path keeps
  the reproducibility envelope (NFR37) intact.

**Consequences.**

- *Operator uplift for existing v3.29.0 clusters.* Operators
  running the v3.29.0 manifest install must follow Calico's
  v3.30 upgrade-path documentation
  (https://docs.tigera.io/calico/latest/operations/upgrading)
  to migrate to v3.31.5. The migration is documented as
  in-place by upstream and does not require workload downtime
  on stable dataplanes. This is a one-time operator-side
  procedure outside the agent's automation surface.
- *Helm chart impact.* `deploy/helm/olaitan/templates/networkpolicy.yaml`
  gains a conditional egress rule allowing the agent DaemonSet
  to reach `calico-system/goldmane:7443` when
  `calicoSensor.enabled=true`. Existing NetworkPolicy egress
  rules (Kubernetes API, NATS) are unchanged.
- *Reproducibility envelope (NFR37).* `eval/manifest.yaml`
  inherits the v3.31.5 pin when Story 5.1 builds the
  reproducibility envelope; the version cell tracks Calico's
  point releases per the same cadence as containerd / runc / Go.
- *Hardware verification deferred.* The dev sandbox cannot run
  kubeadm bootstrap end-to-end (Story 1.1 AC5 lineage). Story
  1.10 logs the operator-side end-to-end verification under
  `_bmad-output/implementation-artifacts/deferred-work.md` as
  "Story 1.10 AC5 bootstrap migration verification on real
  hardware".

**Historical correction.** ADR-2026-04-27-01 codified the
v3.29.0 Calico pin under the belief that v3.29.0 was the
April 2026 stable release. v3.31.5 was the actual April 2026
stable, released 2026-04-15. ADR-2026-04-27-01 is preserved as
the historical record (ADRs are append-only by convention);
ADR-2026-04-30-01 documents the spike-driven discovery of the
mistake, and this ADR records the install-path implementation
consequence. The chart `kubeVersion` constraint (>=1.29.0) is
unchanged across all three ADRs.

**Follow-ups.**

- `deploy/demo/setup.sh`: bump `CALICO_VERSION` to `v3.31.5` and
  switch to the operator-install pair. Done in this story.
- `hack/bootstrap-kubeadm.md`: rewrite the "Install Calico CNI"
  section. Done in this story.
- `deploy/helm/olaitan/CNI.md`: documents the Goldmane Service
  surface plus the mTLS provisioning paths. Done in this story.
- `_bmad-output/implementation-artifacts/deferred-work.md`: add
  the AC5 hardware-verification follow-up. Done in this story.
- Story 5.1 (`eval/manifest.yaml`) inherits the v3.31.5 pin.
- Project memory (`project_olaitan.md`) is refreshed by Story
  1.10 to reflect v3.31.5 and the operator install path. Done
  out of band; this ADR is the durable technical record.
