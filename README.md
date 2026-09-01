# Olaitan

**Runtime security for Kubernetes: multi-source detection, graduated isolation, and an optional LLM analyst whose influence on a decision is bounded by construction.**

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
capped. The analyst's contribution to a workload's score is bounded, and the
bound is chosen so that, on the shipped defaults, the model **on its own cannot
escalate anything**: with no deterministic signal the most it can contribute is
10.5, below the score of 20 that reaches the first non-CLEAN state. See
[SECURITY.md](SECURITY.md#the-llm-tier-and-prompt-injection) for what that does
and does not guarantee.

## Install

```bash
helm install olaitan oci://ghcr.io/olokotoh/charts/olaitan \
  --version 1.0.0-rc3 \
  --namespace olaitan --create-namespace
```

No clone and no local build. The chart version is unprefixed SemVer, not the
git tag: `v1.0.0-rc3` is the tag that triggers the release, `1.0.0-rc3` is what
the registry holds.

Install into the `olaitan` namespace as shown. The agent's default
`excluded_namespaces` list contains `kube-system` and `olaitan`, so installing
anywhere else leaves the agent able to act on its own workloads. The chart bundles pinned Falco, NATS and Redis
subcharts; disable any of them with `--set <name>.enabled=false` if you already
run that infrastructure.

Enforcement is **observe-only by default**. `response.networkPolicy.enabled` is
`false`, so out of the box Olaitan detects and records but writes no
NetworkPolicies. Turning it on is a deliberate act, and you should set
`response.networkPolicy.clusterCidrs` to your cluster's real CIDRs first or
egress blocking under RESTRICTED will take DNS with it.

Run this first, against whatever cluster you are pointed at:

```bash
hack/preflight.sh      # or: make preflight
```

It probes storage, privileged-workload admission, NetworkPolicy **enforcement**
and each optional source, and prints `yes` / `no` / `BLOCKER` with the exact
remedy flag for each. It changes nothing. After the install, the chart's
`NOTES.txt` tells you the same thing from inside: what it detected, which
sources are on, which are off, and why.

### Where it runs

| Platform | Install | NetworkPolicy enforced | Audit webhook | Overlay |
| --- | --- | --- | --- | --- |
| kind | ✅ verified | ❌ no (kindnet accepts and ignores) | ✅ possible | `values-kind.yaml` |
| kubeadm | ✅ verified | depends on your CNI | ✅ possible | (defaults) |
| k3s / k3d | template-verified | ✅ (kube-router) | ✅ possible | `values-k3s.yaml` |
| minikube | template-verified | ❌ unless `--cni=calico` | ✅ possible | `values-minikube.yaml` |
| EKS (EC2) | template-verified | ❌ until VPC CNI policy enabled | ❌ impossible | `values-eks.yaml` |
| AKS Standard | template-verified | ❌ unless an engine was chosen | ❌ impossible | `values-aks.yaml` |
| GKE Standard | template-verified | ✅ with Dataplane V2 | ❌ impossible | `values-gke.yaml` |
| OpenShift | template-verified | ✅ (OVN-Kubernetes) | ✅ possible | `values-openshift.yaml` |
| EKS Fargate | ❌ impossible | n/a | n/a | n/a |
| AKS Automatic | ❌ blocked | n/a | n/a | n/a |
| GKE Autopilot | ❌ blocked | n/a | n/a | n/a |

`verified` means installed and observed on a live cluster of that type.
`template-verified` means the chart renders and validates for it and nothing
was run there. Rendering is not running, and the two are never blurred; the
cited, per-platform detail is in
[docs/platform-support-matrix.md](docs/platform-support-matrix.md).

The three features that genuinely need a self-managed control plane -- the
audit webhook, the containerd CRI sensor, the Calico flow adapter -- are all
**off by default**, and a default render contains no hostPath mount from
Olaitan's own templates. "Impossible" above means the K8s audit webhook
specifically: no managed provider exposes `--audit-webhook-config-file`, so
that one source cannot be turned on there at all. Everything else works.

## How this differs from Falco alone

Falco is one of Olaitan's five inputs, and an excellent one. The difference is
what happens after a rule fires.

| | Falco alone | Olaitan |
| --- | --- | --- |
| Signal sources | eBPF syscalls | eBPF, K8s audit, CRI, CNI flows, app logs, correlated |
| Output | an alert stream | an evidence package with a score and a workload state |
| Repeated weak signals | each alert stands alone | correlated into one evidence package; an optional rolling risk window (off by default) also lets them accumulate over time |
| Statistical drift | not modelled | Welford baselines per workload |
| Response | left to you (Talon and falcosidekick are separate components) | graduated NetworkPolicy isolation, cooldown-gated de-escalation |
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
- **NetworkPolicy enforcement is your CNI's job, not Olaitan's.** Olaitan
  reports a workload `QUARANTINED` once it has written the policy. On a cluster
  whose CNI does not enforce NetworkPolicy the API server accepts every policy
  and the data plane ignores all of them, so the workload keeps full network
  access while the tool says it is contained. Stock kind, stock EKS (VPC CNI)
  and stock AKS all behave this way. Enforcement is **off by default** for this
  reason. Before turning it on, run `hack/check-netpol-enforcement.sh`, which
  pushes real traffic through a deny-all policy and tells you which world you
  are in.
- **Falco's modern eBPF driver needs BTF (`CONFIG_DEBUG_INFO_BTF`) and kernel
  5.8 or newer.** True of every current mainstream node image. On an older
  kernel set `falco.driver.kind=kmod`; `hack/preflight.sh` reports the node
  kernel so you can tell before installing.
- **Targets Kubernetes 1.29 and newer.** The chart's `kubeVersion` floor is
  `>=1.29.0`, and it is load-bearing rather than conservative: the collector's
  Falco-socket permission container is a native sidecar, which needs 1.29.
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

A preprint (IEEE format, targeting arXiv `cs.CR`) is written but **not yet
posted**; this section will carry the link when it is. Until then the
repository is the citable artefact.

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
