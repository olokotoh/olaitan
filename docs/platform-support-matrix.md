# Platform support matrix: what Olaitan can actually do, per platform

**Researched 2026-08-30** against first-party vendor documentation. Every row is
cited. Rows marked **UNCERTAIN** were not confirmable in a vendor doc and must
not be claimed until tested on a live cluster.

**Verification legend.** `verified` = installed and observed on a live cluster of
that type. `template-verified` = the chart renders and validates for that
platform, but nothing was run there. **Rendering is not running, and the
distinction is never blurred in this document.**

---

## The two facts that shape everything

**1. No managed control plane exposes `--audit-webhook-config-file`.** Kubernetes
offers exactly two audit backends, log and webhook; EKS, AKS and GKE all run
kube-apiserver as a managed component whose flags you cannot set. On every
managed platform Olaitan's audit source must be re-plumbed through the cloud's
own log pipeline -- a *pull/stream adapter*, not the HTTP receiver Olaitan
implements today. Falco already ships `k8saudit-eks`, `k8saudit-aks` and
`k8saudit-gke` plugins for exactly this, which is the cheapest documented path.

**2. NetworkPolicy is NOT enforced by default on most platforms.** This is the
finding that matters most for a security tool, because the API server accepts
the policy either way. Olaitan can report a workload QUARANTINED while it keeps
full network access. Proven locally on kind; per the research it is also true of
stock EKS (VPC CNI) and stock AKS (no policy engine selected).

---

## Support matrix

| Platform | Install | Falco driver | NetworkPolicy enforced | Default StorageClass | Audit webhook | Overlay |
| --- | --- | --- | --- | --- | --- | --- |
| **kind** | ✅ verified | modern_ebpf (Falco 0.45.0-rc1) | ❌ **no** (kindnet) | ✅ `standard` | ✅ possible | `values-kind.yaml` |
| **kind + Calico** | script, live run pending | modern_ebpf (Falco 0.45.0-rc1) | ✅ (Calico) | ✅ `standard` | ✅ possible | `values-kind.yaml` |
| **kubeadm** | ✅ verified | modern_ebpf | depends on CNI | depends | ✅ possible | (defaults) |
| **k3s / k3d** | template-verified | modern_ebpf | ✅ (kube-router) | ✅ `local-path` | ✅ possible | `values-k3s.yaml` |
| **minikube** | template-verified | modern_ebpf | ❌ unless `--cni=calico` | ✅ addon | ✅ possible | `values-minikube.yaml` |
| **EKS (EC2)** | template-verified | modern_ebpf **required** | ❌ off until enabled | ❌ **none ≥1.30** | ❌ CloudWatch instead | `values-eks.yaml` |
| **EKS Fargate** | ❌ **impossible** | n/a | n/a | n/a | n/a | n/a |
| **AKS Standard** | template-verified | modern_ebpf | ❌ off unless chosen | ✅ `default` | ❌ Event Hub instead | `values-aks.yaml` |
| **AKS Automatic** | ❌ **blocked** | n/a | ✅ (Cilium) | ✅ | ❌ | n/a |
| **GKE Standard** | template-verified | modern_ebpf | ✅ with Dataplane V2 | ✅ balanced PD | ❌ Cloud Logging | `values-gke.yaml` |
| **GKE Autopilot** | ❌ **blocked** | n/a | ✅ always on | ✅ strongest | ❌ | n/a |
| **OpenShift** | template-verified | modern_ebpf | ✅ (OVN-Kubernetes) | ✅ | ✅ possible | `values-openshift.yaml` |

Each overlay carries only that platform's deltas, every line commented with the
reason. CI lints and `kubeconform`-validates all seven on every run against the
chart's `kubeVersion` floor (1.29.0), which is the evidence behind the
`template-verified` rows and **the only thing they claim**.

The two `verified` rows are separate, and neither rests on CI:

- **kind** is installed and observed on every e2e run, and again by hand on
  2026-09-01 for Story 9.6.
- **kubeadm** was installed by hand on a real 3-node cluster on 2026-08-31.
  Note what that run actually established: the chart installs and every
  workload schedules, but the collector could not attach to Falco's socket
  (Blocker 8) until Story 9.6, and **the fix has not yet been re-run on
  kubeadm**. Story 9.6 was verified in containers and on kind; the kubeadm
  re-run is outstanding.

The `portability` matrix job (kind, minikube, k3s) is written but **has not run
yet** -- this branch has never been pushed, so no CI has executed against it.
Until it does, minikube and k3s stay `template-verified`, and this note is here
so nobody promotes them on the strength of a job existing.

### Where Olaitan genuinely cannot run

- **EKS Fargate** -- "Daemonsets aren't supported on Fargate" and "Privileged
  containers aren't supported on Fargate". Worse than an error: a Fargate profile
  matching the namespace **silently swallows the DaemonSet** with no scheduling
  and no message.
- **AKS Automatic** -- Deployment Safeguards + Baseline PSS in Enforce mode, and
  "the baseline Pod Security Standards in AKS Automatic can't be turned off".
  Rejects privileged containers, hostPath and host namespaces by name. Only
  escape hatch: excluding Olaitan's namespace from Deployment Safeguards.
- **GKE Autopilot** -- the Warden validating admission webhook blocks privileged
  containers outright.

These are platform policy, not Olaitan defects. Preflight must detect them and
say so plainly rather than letting the operator discover it from a CrashLoop.

---

## Calico and Goldmane: where the network flow source can run (Story 10.11)

The Calico flow sensor (`calicoSensor`, FR4) reads the **Goldmane** gRPC API,
which exists only on a Calico install done through the **Tigera operator** on
Calico v3.31.5+. The legacy manifest install (`kubectl apply -f calico.yaml`)
creates no Goldmane Deployment, so on such a cluster the source cannot be
enabled at all. A platform's own CNI being "Calico-compatible" is not enough
either; the question is whether `kubectl -n calico-system get deployment
goldmane` returns something.

| Platform | Goldmane available | How |
| --- | --- | --- |
| **kind + Calico** | ✅ | `hack/install-calico-kind.sh`, which installs the pinned operator and writes the Path B values |
| **kubeadm** | ✅ | operator install; `hack/bootstrap-kubeadm.md` walks through it |
| **minikube** | depends | `--cni=calico` uses the manifest install, so **no Goldmane**; the operator has to be installed on top |
| **EKS / AKS / GKE / OpenShift** | UNCERTAIN | none of these run the Tigera operator by default and none was tested here |
| **stock kind, k3s** | ❌ | kindnet and kube-router are not Calico |

The `kind + Calico` row is the only one this repository gives a scripted path
for. It is **not** marked verified: the script and the traffic fixture
(`tests/e2e/fixtures/calico-flow-traffic.yaml`) are committed, but the live run
that observes `olaitan.events.raw.network` events and
`source_healthy{source="network"} 1` is outstanding, and the row will not say
verified until that output exists.

Note the interaction with the NetworkPolicy finding above: `kind + Calico` is
also the only kind cluster where the release NetworkPolicy, including the
adapter's own Goldmane egress rule, is actually enforced rather than merely
accepted. `hack/check-netpol-enforcement.sh` is what settles that empirically.

---

## Falco version and node kernel (Story 10.1)

**Pinned: Falco `0.45.0-rc1` (image), chart `falcosecurity/falco` `9.1.0`,
`modern_ebpf` driver.** The single record is `hack/falco-support.env`; the helm
suite fails if the chart, this page or `eval/manifest.yaml` disagree with it,
and `hack/preflight.sh` judges every node kernel against it.

| Kernel | Falco 0.43.1 / 0.44.x | Falco 0.45.0-rc1 (pinned) | Evidence |
| --- | --- | --- | --- |
| < 5.8 | depends on distro backports of BTF + BPF ring buffer | same | Falco kernel docs: "usually all versions `>=5.8` are enough" |
| 5.8 to 6.x | **mostly runs**; exits at start under minikube on GitHub's `6.17.0-1022-azure` runners (exit 2 within 1s, CI 2026-09-11; cause not captured) | runs, including that minikube runner | CI portability matrix; kind and k3s on the same runners pass with both |
| **7.0** | ❌ **exits every few minutes** | ✅ **verified: 30 min soak, 0 restarts** (kind, 7.0.0-31-generic) | falcosecurity/falco#3955; reproduced here on 0.43.1: 12 restarts in 63 min |
| > 7.0 | ❌ same defect reported on 7.1.2 | untested here; reported fixed on 7.2 in falcosecurity/falco#3955 | preflight prints a caveat |

**Why 0.43.1 and 0.44.x crash on 7.x.** `could not parse param 2 (name) for
event ... of type 307 (openat)` / `param 1 (exe) ... type 223 (clone)`, then
Falco exits. The modern_bpf driver builds each event in a per-CPU "auxmap" and
assumed a BPF program could not be preempted mid-event; on preemptible
(`PREEMPT_DYNAMIC`) 7.x kernels it can, another program overwrites the buffer,
and the parser reads a corrupted event (falcosecurity/libs#2719). Fixed by
**falcosecurity/libs#3086** (two auxmaps per CPU with an in-use flag, merged
2026-09-08), first shipped in libs `0.26.0-rc1` and so in Falco `0.45.0-rc1`
(2026-09-09). Upstream tracks it in **falcosecurity/falco#3955** (milestone
0.45.0).

**Why an RC.** No stable release has the fix, and Falco `0.44.0` also removed
the gRPC output (falcosecurity/falco#3798), so there was never a stable Falco
that both runs on 7.x and matches the old transport. Olaitan moved to
`http_output` in Story 10.2 for that reason. **TODO:** move to `0.45.0` GA when
it ships (planned 2026-09-21) and update `hack/falco-support.env` in the same
change.

---

## Two research findings that changed the code

**Falco's legacy `ebpf` driver is deprecated in chart 8.0.0 and REMOVED in
9.0.0.** The tree had `driver.kind: ebpf`, which runs `falco-driver-loader` to
compile a probe against kernel headers. That already failed on kind (reproduced:
`/lib/modules/<kernel>/build: No such file or directory`), and it fails on
Bottlerocket (immutable dm-verity rootfs, no headers, kernel lockdown) and on
Container-Optimized OS. Changed to `modern_ebpf` in commit `2571acf` before this
research arrived; the research raises it from "fixes kind" to **"required on EKS
and time-limited everywhere"**.

**EKS ≥1.30 ships NO default StorageClass.** "Starting with 1.30, Amazon EKS no
longer includes the default annotation on the gp2 StorageClass." A PVC with no
`storageClassName` stays Pending forever -- so NATS JetStream never binds and the
aggregator never starts. `hack/preflight.sh` already distinguishes "no default
class" from "no classes at all" and prints the `--set` flags; this research is
why that distinction earns its place.

---

## Per-platform gotchas worth pinning

**EKS**
- containerd socket differs by node OS: `/run/containerd/containerd.sock` on
  Amazon Linux 2023, `/run/host-containerd/containerd.sock` on Bottlerocket.
  Olaitan's CRI sensor hardcodes the former → must become configurable.
- The EBS CSI driver is not installed by default and needs its own IAM role
  (IRSA or Pod Identity). Without it PVCs fail with `UnauthorizedOperation`.
- NetworkPolicy needs `enableNetworkPolicy="true"` on the VPC CNI add-on, VPC CNI
  ≥1.14.0-eksbuild.3, and node kernel ≥5.10. EC2 Linux nodes only.

**AKS**
- Never patch the built-in `default` StorageClass: "AKS reconciles the default
  storage classes and will overwrite any changes you make."
- Deployment Safeguards in Enforce mode also deny on unrelated best-practice
  rules (resource limits, probes, `:latest` tags), so chart defaults can trip
  checks that have nothing to do with privilege. Test with level Warn first.

**GKE**
- Dataplane V2 (Cilium) enforces NetworkPolicy with no add-on. This is the one
  platform where Olaitan's isolation response works out of the box.
- Autopilot resource defaults for DaemonSets are 50 mCPU / 100 MiB memory.

---

## UNCERTAIN: do not claim until tested

- Whether AKS's Azure-flavoured Ubuntu 5.15 and Azure Linux 3.0 kernels are
  built with `CONFIG_DEBUG_INFO_BTF` (modern eBPF's requirement). Check with
  `bpftool feature probe kernel | grep "map_type ringbuf is available"`.
- Whether AKS Automatic's Cilium dataplane enforces NetworkPolicy without an
  explicit `--network-policy cilium`.
- Whether a privileged eBPF DaemonSet is functional on EKS Auto Mode
  (Bottlerocket variants, SELinux enforcing, immutable root).
- Bottlerocket's shipped default for `settings.kernel.lockdown`.

Sources: AWS EKS user guide + best practices, Azure AKS docs, Google GKE docs,
Falco kernel/driver docs and chart 8.x changelog, Kubernetes audit documentation.

**On "every row is cited".** The per-platform claims above were researched
against those first-party docs on 2026-08-30, and the specific facts each row
rests on are restated inline in the platform overlays
(`deploy/helm/olaitan/values-<platform>.yaml`), which is where an operator
meets them. An earlier version of this line pointed at a per-platform research
record under `.hermes/cache/`; that path is a scratch cache, is not in the
repository, and is not reproducible by anyone reading this. Pointing at it was
worse than pointing at nothing, so it is removed rather than quietly left in.
Anything not confirmable in a vendor doc is in the UNCERTAIN list above and is
not claimed in the table.
