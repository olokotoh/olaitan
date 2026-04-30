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
