# Platform support matrix — what Olaitan can actually do, per platform

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
own log pipeline — a *pull/stream adapter*, not the HTTP receiver Olaitan
implements today. Falco already ships `k8saudit-eks`, `k8saudit-aks` and
`k8saudit-gke` plugins for exactly this, which is the cheapest documented path.

**2. NetworkPolicy is NOT enforced by default on most platforms.** This is the
finding that matters most for a security tool, because the API server accepts
the policy either way. Olaitan can report a workload QUARANTINED while it keeps
full network access. Proven locally on kind; per the research it is also true of
stock EKS (VPC CNI) and stock AKS (no policy engine selected).

---

## Support matrix

| Platform | Install | Falco driver | NetworkPolicy enforced | Default StorageClass | Audit webhook |
| --- | --- | --- | --- | --- | --- |
| **kind** | ✅ verified | modern_ebpf | ❌ **no** (kindnet) | ✅ `standard` | ✅ possible |
| **kubeadm** | template-verified | modern_ebpf | depends on CNI | depends | ✅ possible |
| **EKS (EC2)** | template-verified | modern_ebpf **required** | ❌ off until enabled | ❌ **none ≥1.30** | ❌ CloudWatch instead |
| **EKS Fargate** | ❌ **impossible** | n/a | n/a | n/a | n/a |
| **AKS Standard** | template-verified | modern_ebpf | ❌ off unless chosen | ✅ `default` | ❌ Event Hub instead |
| **AKS Automatic** | ❌ **blocked** | n/a | ✅ (Cilium) | ✅ | ❌ |
| **GKE Standard** | template-verified | modern_ebpf | ✅ with Dataplane V2 | ✅ balanced PD | ❌ Cloud Logging |
| **GKE Autopilot** | ❌ **blocked** | n/a | ✅ always on | ✅ strongest | ❌ |

### Where Olaitan genuinely cannot run

- **EKS Fargate** — "Daemonsets aren't supported on Fargate" and "Privileged
  containers aren't supported on Fargate". Worse than an error: a Fargate profile
  matching the namespace **silently swallows the DaemonSet** with no scheduling
  and no message.
- **AKS Automatic** — Deployment Safeguards + Baseline PSS in Enforce mode, and
  "the baseline Pod Security Standards in AKS Automatic can't be turned off".
  Rejects privileged containers, hostPath and host namespaces by name. Only
  escape hatch: excluding Olaitan's namespace from Deployment Safeguards.
- **GKE Autopilot** — the Warden validating admission webhook blocks privileged
  containers outright.

These are platform policy, not Olaitan defects. Preflight must detect them and
say so plainly rather than letting the operator discover it from a CrashLoop.

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
`storageClassName` stays Pending forever — so NATS JetStream never binds and the
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

## UNCERTAIN — do not claim until tested

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
Full citation list per platform in the research record at
`.hermes/cache/delegation/subagent-summary-0-20260831_121650_725708.txt`.
