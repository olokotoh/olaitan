# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Release-candidate tags are pre-releases: they do not move `latest`, and the
public API and Helm values may still change between them. `v1.0.0` is reserved
for the point at which the evaluation campaign has produced detection-latency
and false-positive numbers; see [Unreleased](#unreleased).

## [Unreleased]

### Added

- Repository hygiene for public use: `SECURITY.md` documenting the agent's
  blast radius and the LLM tier's prompt-injection threat model,
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue templates, and a README
  rewritten for operators rather than examiners.

> **Known gap.** Detection-latency (MTTD) and false-positive-rate numbers are
> not yet measured against a live cluster. The harness, scenarios,
> pre-registered analysis plan and reproducibility envelope are complete; the
> campaign that fills them in is outstanding. No performance figure in this
> repository should be cited until it is.

## [v1.0.0-rc3] - 2026-08-30

### Fixed

- The chart-publishing job in the release workflow now authenticates to cosign
  before signing, so chart signatures are produced rather than skipped (#95).

## [v1.0.0-rc2] - 2026-08-29

### Added

- **Release pipeline** (#94). Tagging `v*` now publishes a multi-arch
  (`linux/amd64`, `linux/arm64`) image to `ghcr.io/olokotoh/olaitan` and the
  Helm chart to `oci://ghcr.io/olokotoh/charts`, with a keyless cosign signature
  and an SPDX SBOM on the image. Chart signing was configured here but did not
  actually produce a signature until the cosign authentication fix in rc3, so
  the rc2 chart is unsigned. Installing no longer requires cloning or building.
- `:edge` image tag published on every green push to `main`.
- Version stamping: `olaitan version` reports the release tag rather than
  `dev`.

### Changed

- Pre-release tags (`-rc`, `-alpha`, `-beta`) are marked as pre-releases and
  do not move `latest`.

## [v1.0.0-rc1] - 2026-08-18

First tagged artefact, covering the work of Epics 1 through 7.

### Added

- **Five-source telemetry collection**: Falco eBPF syscalls, Kubernetes API
  audit webhook, CRI runtime events, Calico CNI flows via Goldmane, and
  application logs.
- **Three-tier detection**: an OLT-dialect Sigma rule engine with hot reload,
  Welford statistical baselines with restart-aware warm-up, and an optional
  multi-agent LLM analyst tier.
- **Trust-bounded LLM integration**: a trust ladder that caps the analyst
  tier's contribution to a workload's score, with the bound covered by a
  dedicated harness.
- **Graduated isolation state machine**: CLEAN, SUSPICIOUS, RESTRICTED,
  QUARANTINED, PRESERVED_KILLED, enforced through generated NetworkPolicies,
  with cooldown-gated de-escalation and operator override.
- **Helm chart** with pinned Falco, NATS and Redis subcharts, plus production,
  air-gapped and evaluation overlays.
- **Six Grafana dashboards** and an operator runbook covering ten scenarios.
- **Reproducible evaluation harness** (`cmd/olaitan-eval`), a pre-registered
  analysis plan, and an analysis pipeline.

[Unreleased]: https://github.com/olokotoh/olaitan/compare/v1.0.0-rc3...HEAD
[v1.0.0-rc3]: https://github.com/olokotoh/olaitan/compare/v1.0.0-rc2...v1.0.0-rc3
[v1.0.0-rc2]: https://github.com/olokotoh/olaitan/compare/v1.0.0-rc1...v1.0.0-rc2
[v1.0.0-rc1]: https://github.com/olokotoh/olaitan/tree/v1.0.0-rc1
