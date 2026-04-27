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
