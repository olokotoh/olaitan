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
