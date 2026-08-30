# Olaitan

**Runtime security for Kubernetes: multi-source detection, graduated isolation, and an optional LLM analyst that is never trusted more than the evidence supports.**

[![Release](https://img.shields.io/github/v/release/olokotoh/olaitan?include_prereleases&sort=semver)](https://github.com/olokotoh/olaitan/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Olaitan watches five telemetry sources at once, correlates them into evidence
packages, scores those packages through a three-tier engine, and moves each
workload along an isolation state machine that it enforces with generated
NetworkPolicies. It is designed so that the most powerful tier, a language
model, cannot escalate a workload on its own say-so.

> **Research preview.** The system works and is installable, but it is the
> output of a research project, not a supported product. Issues are answered
> on a best-effort basis. See [Limitations](#limitations) before running it
> anywhere that matters.

## What it does

```
  eBPF syscalls (Falco) ─┐
  K8s audit webhook ─────┤
  CRI runtime events ────┼──▶ correlator ──▶ evidence package
  CNI flows (Calico) ────┤                          │
  application logs ──────┘                          ▼
                                    ┌───────────────────────────┐
                                    │ tier 1  Sigma rules       │
                                    │ tier 2  Welford baselines │
                                    │ tier 3  LLM analyst (opt) │
                                    └─────────────┬─────────────┘
                                                  ▼
              CLEAN ▸ SUSPICIOUS ▸ RESTRICTED ▸ QUARANTINED ▸ PRESERVED_KILLED
                                                  │
                                                  ▼
                                    generated NetworkPolicies
```

Tier 1 and tier 2 are deterministic. Tier 3 is optional, off by default, and
capped: the analyst's contribution to a score is bounded by a trust ladder, so
a compromised or manipulated model cannot by itself drive a workload past the
states the deterministic tiers already justify.

## Install

```bash
helm install olaitan oci://ghcr.io/olokotoh/charts/olaitan --version v1.0.0-rc3
```

No clone and no local build. The chart bundles pinned Falco, NATS and Redis
subcharts; disable any of them with `--set <name>.enabled=false` if you already
run that infrastructure.

Enforcement is **observe-only by default**. `response.networkPolicy.enabled` is
`false`, so out of the box Olaitan detects and records but writes no
NetworkPolicies. Turning it on is a deliberate act, and you should set
`response.networkPolicy.clusterCidrs` to your cluster's real CIDRs first or
egress blocking under RESTRICTED will take DNS with it.

## How this differs from Falco alone

Falco is one of Olaitan's five inputs, and an excellent one. The difference is
what happens after a rule fires.

| | Falco alone | Olaitan |
| --- | --- | --- |
| Signal sources | eBPF syscalls | eBPF, K8s audit, CRI, CNI flows, app logs, correlated |
| Output | an alert stream | an evidence package with a score and a workload state |
| Repeated weak signals | each alert stands alone | accumulate through a rolling risk window |
| Statistical drift | not modelled | Welford baselines per workload |
| Response | left to you | graduated NetworkPolicy isolation with TTL de-escalation |
| Explanation | the rule text | optional LLM analyst, score-capped and schema-validated |

If you want syscall alerts, run Falco. If you want something that decides a
workload is compromised across several weak signals and then contains it, that
is the gap this fills.

## Limitations

Read this section before trusting it with anything.

- **The published detection latency and false-positive numbers do not exist
  yet.** The evaluation harness, scenarios and analysis pipeline are complete
  and reproducible, but the campaign that produces MTTD and FPR against a live
  cluster has not been run. Do not cite performance figures from this repo.
- **Kubeadm clusters only.** Managed control planes (EKS, GKE, AKS) are out of
  scope: the audit webhook needs `--audit-webhook-config-file` on the API
  server, which managed providers do not expose, and the CNI flow adapter needs
  Calico installed via the Tigera operator, which conflicts with cloud CNIs.
- **Falco's eBPF driver needs kernel 6.5 or newer.** On older kernels the
  subchart can fall back to the kernel module, but nothing here was measured
  that way.
- **Targets Kubernetes 1.29.** The chart's `kubeVersion` floor is `>=1.29.0`.
- **The LLM tier costs money and adds latency.** It is off by default for both
  reasons. Everything except tier-3 reasoning works with it disabled.
- **The agent writes NetworkPolicies into your cluster when enforcement is on.**
  Review [SECURITY.md](SECURITY.md) for the blast radius and the guards that
  bound it.

## Documentation

| | |
| --- | --- |
| [Operator runbook](docs/runbook.md) | ten operational scenarios, end to end |
| [Helm values reference](docs/helm-values.md) | every value, generated from the chart |
| [Architecture decisions](docs/patterns.md) | why the system is shaped this way |
| [NATS subjects](docs/nats-subjects.md) | the internal message contract |
| [Writing rules](docs/sigma-extensions.md) | the OLT Sigma dialect |
| [Contributing](CONTRIBUTING.md) | development setup and the review bar |

## Research

Olaitan began as academic work and the evidence trail is kept in the open on
purpose: a pre-registered analysis plan, a reproducibility envelope that pins
every input to a run, and a traceability matrix from requirements to tests.

If you use this in academic work, please cite:

```bibtex
@misc{olokoto2026olaitan,
  title  = {Trust-Bounded Multi-Agent LLM Integration for Autonomous
            Kubernetes Runtime Security},
  author = {Olokoto, Habeeb},
  year   = {2026},
  note   = {\url{https://github.com/olokotoh/olaitan}}
}
```

The evaluation harness lives in `cmd/olaitan-eval`, the pre-registered plan in
`analysis/preregistration.md`, and the reproducibility envelope in
`eval/manifest.yaml`.

## License

MIT. See [LICENSE](LICENSE).
