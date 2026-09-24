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
  --version 1.0.0-rc4 \
  --namespace olaitan --create-namespace
```

No clone and no local build. The chart version is unprefixed SemVer, not the
git tag: `v1.0.0-rc4` is the tag that triggers the release, `1.0.0-rc4` is what
the registry holds.

### Try it on kind

With Docker, [kind](https://kind.sigs.k8s.io/), helm and kubectl installed:

```bash
kind create cluster --name olaitan
helm install olaitan oci://ghcr.io/olokotoh/charts/olaitan \
  --version 1.0.0-rc4 \
  --namespace olaitan --create-namespace
kubectl -n olaitan wait pod --all --for=condition=Ready --timeout=10m
```

That is the whole default install, Falco included: on a single-node cluster,
six pods (Falco and the collector, one each per node; the aggregator; NATS;
nats-box; Redis). Before release, this sequence
was run word for word on a fresh single-node kind (kind v0.30.0, Ubuntu 24.04
host, kernel with BTF) with the chart packaged the way the release packages
it, and every pod was Ready in RESULT_TIME. Two things can stop it on your
machine:

- **Falco needs BTF** (`/sys/kernel/btf/vmlinux` exists on the host). Most
  current distribution kernels have it; see [Limitations](#limitations).
- **inotify limits.** kind nodes share the host's
  `fs.inotify.max_user_instances`, and the default of 128 runs out with a
  few clusters up; pods then fail with `too many open files`. The
  verification host ran with `max_user_instances=1024` and
  `max_user_watches=1048576`, which is kind's own
  [known-issues](https://kind.sigs.k8s.io/docs/user/known-issues/#pod-errors-due-to-too-many-open-files)
  advice.

On kind NetworkPolicies are accepted and ignored (kindnet does not enforce
them), which is one reason enforcement is off by default; see below.

Install into the `olaitan` namespace as shown. The agent's default
`excluded_namespaces` list contains `kube-system` and `olaitan`, so installing
anywhere else leaves the agent able to act on its own workloads. The chart bundles Falco and NATS
subcharts and its own Redis, with every image pinned by tag and digest; disable
any of them with `--set <name>.enabled=false` if you already run that
infrastructure.

Enforcement is **observe-only by default**. `response.networkPolicy.enabled` is
`false`, so out of the box Olaitan detects and records but writes no
NetworkPolicies. Turning it on is a deliberate act, and you should set
`response.networkPolicy.clusterCidrs` to your cluster's real CIDRs first or
egress blocking under RESTRICTED will take DNS with it.

To check a cluster before installing, clone this repository and run, against
whatever cluster you are pointed at:

```bash
git clone https://github.com/olokotoh/olaitan && cd olaitan
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
| **kind-full** (reference) | ⚠️ verified 2026-09-21, see note | ✅ yes (Calico) | ✅ enabled | `values-full.yaml` |
| kubeadm | ⚠️ verified 2026-08-31, see note | depends on your CNI | ✅ possible | (defaults) |
| k3s / k3d | template-verified | ✅ (kube-router) | ✅ possible | `values-k3s.yaml` |
| minikube | template-verified | ❌ unless `--cni=calico` | ✅ possible | `values-minikube.yaml` |
| EKS (EC2) | template-verified | ❌ until VPC CNI policy enabled | ❌ impossible | `values-eks.yaml` |
| AKS Standard | template-verified | ❌ unless an engine was chosen | ❌ impossible | `values-aks.yaml` |
| GKE Standard | template-verified | ✅ with Dataplane V2 | ❌ impossible | `values-gke.yaml` |
| OpenShift | template-verified | ✅ (OVN-Kubernetes) | ✅ possible | `values-openshift.yaml` |
| EKS Fargate | ❌ impossible | n/a | n/a | n/a |
| AKS Automatic | ❌ blocked | n/a | n/a | n/a |
| GKE Autopilot | ❌ blocked | n/a | n/a | n/a |

**kind-full is the reference profile: the one place all five sources run at
once.** Every other row above runs some subset. `values-kind.yaml` leaves the
audit webhook, the containerd sensor, the Calico flow adapter and the applog
sidecar at their chart defaults of off, so the full combination had never been
exercised together until this profile existed. It needs a clone of this
repository; from its root, bring it up with:

```
hack/install-full-kind.sh <scratch-dir-outside-this-repo>
```

That script exists because the ordering is not obvious: on kind the
kube-apiserver is a static pod that refuses to start when its audit policy or
webhook kubeconfig is missing, so both files have to be written before
`kind create cluster` runs, which in turn means the audit CA must be generated
before any node exists to have an IP. The profile therefore points the
apiserver at `127.0.0.1:8443` through `auditWebhook.hostPort`, which is
knowable in advance and stable across recreations. Set `WORKERS=1` on a host
under about 16GB; the profile still installs, but pod traffic stops crossing
a node boundary and the Calico flow adapter sees less.

**kind-full also runs the LLM analyst tier for real (Story 10.6).** The
profile pulls `qwen2.5:3b-instruct` into an in-cluster Ollama (image pinned by
digest, model on a chart-created volume) and routes the L1, L2 and Senior
roles to it, so no API key is needed and nothing leaves the cluster at
inference time. Only the short-lived pull Job may reach the internet (DNS and
HTTPS); the serving pod keeps an empty egress policy. The trust cap for this
model family is 25, enforced in code.

**The in-cluster model is slow on CPU, and that is measured, not guessed.**
On an 8 vCPU AWS m6i.2xlarge with no GPU, running beside the whole profile,
`qwen2.5:3b-instruct` reads a prompt at about 17 to 27 tokens/s and writes at
about 8.5 tokens/s. A chain role's prompt is 8k to 10k tokens, so each role
spends about 5 to 10 minutes just reading it, plus about 35 seconds writing:
15 to 30 minutes per incident, with incidents queued one after another. That proves
the tier runs with no key; it does not keep up with a live cluster. For
real-time use, give Ollama a GPU node, or use a hosted model: layer one
overlay after the profile and supply the key out of band, in a Secret you
create yourself, so it never passes through helm values:

```
kubectl -n default create secret generic olaitan-llm-key --from-file=llm-api-key=/dev/stdin < key.txt
-f deploy/helm/olaitan/values-llm-deepseek.yaml --set secrets.llmApiKeyExistingSecret=olaitan-llm-key
-f deploy/helm/olaitan/values-llm-claude.yaml   --set secrets.llmApiKeyExistingSecret=olaitan-llm-key
```

(`--set-file secrets.llmApiKey=./key.txt` also works, but then the key is in
the release's values.) The in-cluster model stays configured as the fallback
for every role, but on CPU that fallback cannot finish: the overlay sets the
hosted budget (60s to 120s per role) for every provider, the fallback
included. A working fallback needs a GPU node or per-provider budgets
(deferred). The `fake-llm` fixture is for unit and CI tests only and is not
part of any profile. `make e2e-full-real-llm` (in-cluster model) and
`make e2e-full-real-llm-deepseek` (DeepSeek, key from the Secret above) prove
the tier on a live cluster: a real in-pod attack, then schema-valid L1, L2
and Senior output from the model, the configured provider and model recorded
in `AUDIT.assessments`, and the model's own confidence capped at its family's
trust cap (ollama 25, openai 30, claude 35). The profile raises the per-role
LLM timeouts thirtyfold for the CPU model, and never scores its own namespace
(`correlator.neverScoreReleaseNamespace`) so Olaitan does not investigate its
own pods ahead of a real incident. The 3B Qwen2.5 weights are under the Qwen Research licence, so for commercial use
switch `analyst.local.model` and `ollama.pull.models` to an Apache-2.0 size
such as `qwen2.5:7b-instruct`.

**The kind-full caveat, stated here rather than only in the matrix.** The
2026-09-21 run was made with `WORKERS=1`, so what is verified is one
control-plane plus one worker. The committed default in `hack/kind-full.yaml`
is two workers; it renders and the node list is generated from the same file,
but that shape has not itself been booted. Treat the row as "verified with one
worker; the two-worker default is unexercised". Prerequisites the script needs
beyond the usual: `openssl`, and `python3` with PyYAML (`make e2e-full` always
passes `WORKERS`, so PyYAML is required on that path). The release installs
into the `default` namespace, matching the e2e suite.

One more thing the row does not convey on its own: on the verification host
the WORKER node's Falco did not start, because the host had
`fs.inotify.max_user_instances` at its default of 128 with most of it already
consumed. "Five sources healthy" was therefore satisfied with Falco running on
the control-plane node only. Raise the inotify limits before reading a
single-node Falco result as a two-node one.

`verified` means installed and observed on a live cluster of that type.
`template-verified` means the chart renders and validates for it and nothing
was run there. Rendering is not running, and the two are never blurred; the
cited, per-platform detail is in
[docs/platform-support-matrix.md](docs/platform-support-matrix.md).

**The kubeadm caveat, stated here rather than only in the matrix.** The
2026-08-31 kubeadm run established that the chart installs and every workload
schedules. It also found that the collector could not attach to Falco's
socket at all, so the primary detection source was dead on that cluster. That
defect is fixed, and the fix has **not been re-run on kubeadm** -- it was
verified in containers and on kind. Treat the kubeadm row as "installs, and
the known blocker is fixed but unconfirmed there".

"Impossible" above means the K8s audit webhook specifically, and it is the
only capability with a hard platform limit: it needs
`--audit-webhook-config-file` on kube-apiserver, and no managed provider
exposes kube-apiserver flags. There is no workaround, only a different route
in through the cloud's own log pipeline, which Olaitan does not implement yet.

The other two optional sources are often described as needing a self-managed
control plane. They do not. The containerd CRI sensor needs a **host socket**
at a path that matches your runtime (see `values-k3s.yaml` and
`values-eks.yaml`, which ship the right paths for those platforms), and the
Calico flow adapter needs **Calico**. Both are off by default, and both are
available on managed platforms.

A default install mounts nothing from the host in Olaitan's own templates.
Falco posts its alerts to the collector over HTTP (`http_output`, through the
node-local `<release>-falco-ingest` Service, with a generated token), so the
collector needs no access to Falco's filesystem. Every hostPath mount on a
default render comes from the bundled Falco subchart, which needs them to
load its kernel driver.

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
  reason. Before turning it on, run `hack/check-netpol-enforcement.sh` (from a
  clone of this repository), which
  pushes real traffic through a deny-all policy and tells you which world you
  are in.
- **Falco's modern eBPF driver needs BTF (`CONFIG_DEBUG_INFO_BTF`) and kernel
  5.8 or newer.** True of mainstream node images we have checked, and NOT
  confirmed for AKS's Azure Ubuntu 5.15 and Azure Linux 3.0 images, which are
  on the open-questions list in
  [the support matrix](docs/platform-support-matrix.md). Check a node with
  `bpftool feature probe kernel | grep ringbuf`. On a kernel without BTF, set
  `falco.driver.kind=kmod`; `hack/preflight.sh` reports the node kernel so you
  can tell before installing.
- **Targets Kubernetes 1.29 and newer.** The chart's `kubeVersion` floor is
  `>=1.29.0`: the optional applog sidecar defaults to the native sidecar form,
  which needs 1.29.
- **The LLM tier costs money and adds latency.** It is off by default for both
  reasons. Everything except tier-3 reasoning works with it disabled. The
  kind-full reference profile turns it on with an in-cluster CPU model: no
  money, but minutes of latency per investigation.
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

The evaluation harness lives in `cmd/olaitan-eval`, the pre-registered plan in
`analysis/preregistration.md`, and the reproducibility envelope in
`eval/manifest.yaml`.

## License

MIT. See [LICENSE](LICENSE).
