# Locked-down platforms: EKS Fargate, AKS Automatic, GKE Autopilot

**Researched and tested 2026-09-01.** Supersedes the "Where Olaitan genuinely
cannot run" section of `platform-support-matrix.md`, which said these three were
impossible. Two of the three now have a working path, and the investigation
turned up an unrelated defect that is more urgent than any of them.

Verification legend as in the matrix: `verified` = observed running. Claims
without a test behind them say so.

---

## 0. URGENT, unrelated to the three platforms: Falco removed gRPC

**Olaitan's only syscall input is a Falco gRPC socket. Falco deleted gRPC in
0.44.0.**

| Falco | Chart | `grpc` keys in `falco.yaml` |
| --- | --- | --- |
| 0.42.0 | 7.x | present (25 lines) |
| 0.43.0/0.43.1 | 8.0.0–8.0.5 | present (27 lines), **deprecated** |
| **0.44.0** | **9.0.0** | **0 — removed** |
| 0.44.1 | 9.1.0 | 0 |

Upstream, verbatim:

- Release 0.44.0 (2026-05-26), under **Breaking Changes**:
  `chore!: drop gRPC output and server support` (PR #3798, merged 2026-02-05).
- PR #3798 body: *"Falco 0.43.0 deprecated the gRPC output and server supports.
  This PR drops their supports as well as any reference to them."*
- Proposal `20251215-legacy-bpf-grpc-output-gvisor-engine-deprecation.md`:
  *"this requires Falco being dependent on the protobuf, and additionally, on
  the entire C++ gRPC framework … the little amount of data that is sent through
  the gRPC stream, and the communication model (only involving a one-way
  communication from the server to the client) doesn't justify the need of using
  gRPC."*
- Same proposal, on a replacement: *"Upcoming evidences of non-negligible use of
  the gVisor engine and the gRPC output could be addressed by providing a
  separate source plugin in case of gVisor, and a **Falco Sidekick output as a
  replacement of the gRPC output**."* Explicitly listed under **Non-goals**:
  *"Implement the gRPC output as Falco Sidekick output"*. So there is no
  drop-in replacement and none is committed.

**Why this is not yet on fire:** the chart pins `falco 8.0.2` = appVersion
0.43.1, the last release that still has gRPC. Olaitan is *pinned to the final
version that works*. The ceiling is real: any operator who bumps the subchart to
9.x, or points `endpoints.falco` at their own Falco 0.44+, loses all syscall
input.

**Blast radius is small and bounded** — 2 non-generated files
(`internal/collector/falco/falco.go`, `translate.go`) plus the generated
`falcopb/`. Nothing else in the tree imports it.

**The replacement to build against is `http_output`**, which exists in both
0.43.1 and 0.44.1. It inverts the direction: Falco POSTs to a URL instead of the
collector dialling a socket. That is the *same shape as the audit webhook
receiver Olaitan already implements* (`internal/collector/audit`), so the
receiver pattern is already in the tree. It also deletes Story 9.6's entire
problem — no unix socket means no `0755 root:root` socket, no
`falco-socket-permissions` sidecar, no hostPath mount of the socket dir.

**Not verified:** whether setting the old `grpc:` keys on 0.44.1 fails loudly or
is silently ignored. If ignored, the failure mode is a collector waiting forever
on a socket that will never be created — the same silent class as the Fargate
DaemonSet swallow. **Test this before writing a migration note.**

---

## 1. The general escape hatch: plugin-only Falco — **verified running**

The blocker was always Falco's *driver*, never Falco. With
`driver.enabled=false` Falco loads no kernel module, no eBPF probe, and needs no
privilege at all.

Two non-obvious details, both found by testing rather than reading:

1. **`falco.plugins_hostinfo` defaults to `true`** and independently drags
   `/proc` back in as a hostPath, via the chart helper
   `falco.procfsMount.enabled` = `or .Values.driver.enabled
   .Values.falco.plugins_hostinfo`. Setting `driver.enabled=false` alone leaves
   a hostPath behind and **still fails restricted PSS.** Must set both.
2. **`collectors.enabled=true`** (the default) appends the `container` plugin to
   `load_plugins` whenever the driver is on, and if you override `load_plugins`
   yourself you get `Cannot load plugin 'container': plugin config not found for
   given name` and a CrashLoop. Set `collectors.enabled=false`.
3. `falcoctl.artifact.install` runs as an **init container**, which
   `podSecurityContext` does not cover — it needs its own
   `falcoctl.artifact.install.securityContext` or restricted PSS rejects it.
4. falcoctl installs rulesfiles to `/rulesfiles`, mounted at `/etc/falco` in the
   Falco container — so the rules path is `/etc/falco/k8s_audit_rules.yaml`,
   not `/etc/falco/rules.d`.

### Verified on a live cluster

kind `olaitan-port`, namespace labelled
`pod-security.kubernetes.io/enforce=restricted,enforce-version=latest`
(the closest local proxy to Autopilot Warden / AKS Automatic baseline PSS):

- Render contains **no** `privileged`, **no** `hostPath`, **no** host
  namespaces.
- `kubectl apply --dry-run=server` → admitted with **zero PodSecurity
  warnings**. (The default render, for contrast, produces the full violation
  list: privileged, 13 hostPath volumes, runAsNonRoot, seccomp.)
- Installed for real: `fp-falco … 1/1 Running`, Falco **0.44.1**, as
  UID 65532, `drop: [ALL]`, `allowPrivilegeEscalation: false`,
  `seccompProfile: RuntimeDefault`.
- Log: `Loaded plugin 'k8saudit@0.13.0'`, `Loaded plugin 'json@0.7.4'`,
  `Enabled event sources: k8s_audit`.
- **Detection proven, not assumed:** POSTed a crafted `audit.k8s.io/v1`
  EventList (pod create with `privileged: true`) to the plugin webhook → HTTP
  200 → Falco emitted
  `rule: "Create Privileged Pod"`, `priority: Warning`, `source: k8s_audit`.

Reproduction script: `hack/plugin-only-falco.sh` *(to be written — the working
invocation is in this session's transcript)*.

### What it costs

Everything syscall-derived. No process execution, no file integrity, no
outbound-connection detection, no container escape, no reverse shell. The five
demo scenarios in `deploy/demo/scenarios/` are all syscall-driven and **none of
them would fire** in this mode. What survives is the control-plane story: exec
into pod, privileged pod create, RBAC changes, secret access, service-account
abuse.

This is a genuine downgrade and must be labelled as one in NOTES.txt. It is the
difference between "Olaitan cannot run here" and "Olaitan runs here with
audit-plane detection only" — worth having, worth not overselling.

---

## 2. Olaitan's own workloads are already clean

Worth stating because it changes the framing: **the collector, aggregator and
applog sidecar are all restricted-PSS compliant today.** Verified by rendering
with `falco.enabled=false` and server-dry-running into the restricted namespace
— all 14 objects admitted, zero warnings.

- collector DaemonSet: UID 65532, `drop: [ALL]`, `readOnlyRootFilesystem`,
  `hostNetwork: false`, `hostPID: false`
- applog sidecar (`internal/admission/applog/inject.go:317`): non-root 65532,
  `drop: [ALL]`, RO rootfs, `allowPrivilegeEscalation: false`,
  `seccompProfile: RuntimeDefault`

So on all three locked-down platforms the thing that gets refused is *Falco's
driver*, and nothing else Olaitan ships. That is a much narrower problem than
the matrix currently implies.

---

## 3. GKE Autopilot

Researched against first-party Google docs; full evidence with verbatim quotes
in `~/falco-gke-autopilot-report.md`.

- **Falco is not allowlisted anywhere.** The verified open-source allowlist
  table has exactly two rows: Grafana Alloy (`Grafana/alloy/*`) and Grafana
  Beyla (`Grafana/beyla/*`). No Falco, no Tetragon, no OTel Collector. Not in
  the partner table either.
- **A customer-owned `WorkloadAllowlist` is the one working mechanism**
  (GKE ≥ 1.32.2-gke.1652000 for `AllowlistSynchronizer`; 1.35+ to change
  allowlist paths). Annotate the workload with
  `cloud.google.com/generate-allowlist: "true"`, let the rejection emit the CR,
  host it in a `gs://` bucket, permit the path in the
  `container.managed.autopilotPrivilegedAdmission` org policy, install via
  `AllowlistSynchronizer`.
- **But that path is per-customer and cannot be shipped by the project.** Each
  operator must own the bucket, the org policy, and an eligibility grant. Getting
  Falco itself allowlisted under `gke://` needs the Autopilot partner program,
  which routes through a Google partner manager.
- **Google's own coverage:** Container Threat Detection works on Autopilot
  (from 1.21.11-gke.900), Google-managed, ~45 detectors including
  `REVERSE_SHELL`, `ADDED_BINARY_EXECUTED`, `UNEXPECTED_CHILD_SHELL`. Requires
  SCC Premium/Enterprise. Google recommends against running a second runtime
  tool alongside it.
- **Audit plane is always available:** Autopilot emits kube-apiserver audit
  events to Cloud Logging under `resource.type="k8s_cluster"`,
  `logName=…cloudaudit.googleapis.com%2Factivity`, and Admin Activity logs
  **cannot be disabled**. No Warden exemption needed to read them.

**Verdict: not blocked.** Plugin-only Falco (§1) runs; the allowlist route is
documented for operators who want full syscalls and can meet the eligibility bar.

---

## 4. EKS Fargate

Full evidence (73 verbatim-verified quotes, 28 AWS pages) in
`~/eks-fargate-runtime-security-findings.md`.

- **GuardDuty Runtime Monitoring does not cover EKS Fargate.** Stated three
  times in AWS docs: *"GuardDuty doesn't support Amazon EKS clusters running on
  AWS Fargate."* The three-way split is sharp and easy to get wrong:
  EKS-on-EC2 ✅ (managed eBPF DaemonSet, needs `CONFIG_DEBUG_INFO_BTF=y`),
  **ECS**-on-Fargate ✅ (AWS injects a security sidecar per task),
  **EKS**-on-Fargate ❌. AWS built the sidecar-injection agent for ECS tasks
  only. Anyone citing "GuardDuty supports Fargate" is reading the ECS row.
- **No AWS-native per-pod syscall visibility on EKS Fargate exists at all.** No
  sidecar agent, no injected security container, no task-level security
  telemetry. The only auto-injected Fargate sidecar is a Fluent Bit *log
  router* whose input block *"can't be modified"*.
- **GuardDuty EKS Protection (audit-log based) does cover Fargate workloads**,
  at control-plane level only — agentless, no node prerequisites. AWS draws the
  line explicitly: *"EKS Protection monitors control plane activities through
  audit logs, while Runtime Monitoring observes behaviors within containers."*
  Caveat recorded honestly: AWS never says "works on Fargate" in those words;
  that is a well-founded inference from the agentless architecture, not a quote.
- **Hybrid clusters are documented and are the answer for full coverage.**
  Fargate profiles for app namespaces + a managed EC2 node group for the
  security namespace. Unmatched pods default to EC2 — *"Any other pods will be
  scheduled on the node in `ng-1`"* — so keeping Olaitan's namespace outside
  every Fargate selector is sufficient; no taint/toleration needed. Fargate
  profiles are immutable, so this is a create-time decision.

### The preflight Fargate check is currently broken for its own headline case

`hack/preflight.sh:110` detects Fargate by grepping **node labels**:

```sh
kubectl get nodes -o jsonpath='{.items[*].metadata.labels}' | grep -q "fargate"
```

Fargate nodes only appear once a Fargate pod is running. On a cluster with EC2
nodes plus a Fargate profile whose selector matches the install namespace — the
exact silent-swallow scenario the check's own message describes — no node
carries a fargate label at preflight time, the grep finds nothing, and preflight
stays silent right up until the DaemonSet is swallowed.

The fix is to ask the AWS API before installing, not the node list:
`aws eks list-fargate-profiles` → `describe-fargate-profile`, then match the
profile's selectors against the install namespace. **Gotcha most
implementations miss:** selectors support `*` and `?` wildcards on namespaces,
label keys *and* label values, so naive string equality gives false negatives.

Four in-cluster fallback signals when the AWS API is unavailable: the
`eks.amazonaws.com/compute-type=fargate` node label (documented only via AWS's
own kube-proxy anti-affinity rule, so: inferred-from-usage, not a label
reference), `fargate-ip-*` node names, the `CapacityProvisioned` annotation, and
the `fargate-scheduler` event source.

### Not a new finding: the audit webhook on EKS

The Fargate research flagged "the audit-webhook receiver can't attach to EKS at
all" as its widest-blast-radius result. **The tree already knows this** —
`platform-support-matrix.md` §"two facts that shape everything" opens with *"No
managed control plane exposes `--audit-webhook-config-file`"*, and the EKS row
reads "❌ CloudWatch instead". Recorded here only so a future reader does not
mistake it for a regression. The confirmation is still worth something: the
string `audit-webhook` appears zero times in the 127K-line EKS User Guide, and
`LogSetup` is a fixed five-value enum, CloudWatch-only. EKS audit ingest must be
CloudWatch Logs → subscription filter → Firehose/Lambda → NATS; delivery is
*"best effort"* and entries >1MB are truncated.

---

## 5. AKS Automatic

Full evidence in `~/olaitan-aks-automatic-research.md`.

- **Falco's privileged DaemonSet cannot run as shipped**, confirming the
  existing matrix row: *"The baseline Pod Security Standards in AKS Automatic
  can't be turned off."* Denies privileged, added capabilities, hostPath and
  host namespaces.
- **The `--excluded-ns` escape hatch in `values-aks.yaml` is contested and must
  not be relied on.** Microsoft's docs say you can exclude a namespace from both
  Safeguards and PSS on Automatic. But Azure/AKS issue #5442 reports the API
  returning `RequestNotAllowedBecauseAssociatedClusterIsAutomaticCluster`, with
  a Microsoft PM replying that hostPath agents are blocked and to use AKS
  Standard. **The chart currently presents this as "the only escape hatch"
  without qualification — that line needs a caveat or removal until someone
  tests it on a live Automatic cluster.**
- **No allowlist mechanism exists.** No AKS analogue to GKE's WorkloadAllowlist;
  custom policies are refused and Gatekeeper edits are *"reconciled"*. Automatic
  also blocks *"Modifying AKS-managed security policies and admission
  controls"*, which closes the deploy-into-`kube-system` workaround.
- **Microsoft's own agent is asymmetric.** The Defender sensor is an eBPF
  DaemonSet requesting `SYS_ADMIN, SYS_RESOURCE, SYS_PTRACE` — *broader* than
  Falco's ask — and docs say *"For AKS Automatic clusters, use the `kube-system`
  namespace"*, the namespace Azure Policy auto-excludes. No Learn page states it
  bypasses PSS, so the bypass itself is **NOT FOUND**, not asserted.
  Cost: $0.00941/vCore/hour (retail prices API, confirmed across 5 regions).
- **`k8saudit-aks` is the shippable path:** an ordinary Deployment reading Event
  Hub — no privilege, no hostPath, nothing in PSS touches it. Control-plane
  detections only.

---

## What should change in the tree

1. **`docs/platform-support-matrix.md`** — the three ❌ rows become
   "audit-plane only (plugin-only Falco)", with the syscall loss stated plainly.
2. **`hack/preflight.sh:99-115`** — currently says "Olaitan cannot run here / Use
   a GKE Standard cluster". Should offer the plugin-only path instead of a dead
   end. **And the Fargate check is broken for its own headline case** (§4) —
   node-label grep cannot see a Fargate profile that has not scheduled anything
   yet, which is exactly the silent-swallow scenario. Move to the AWS API.
3. **`values-{gke,aks,eks}.yaml`** — the "IS BLOCKED / CANNOT BE" banners are now
   wrong. `values-aks.yaml`'s "only escape hatch: exclude the namespace from
   Deployment Safeguards" additionally needs the issue-#5442 caveat (§5).
4. **New `values-plugin-only.yaml`** overlay carrying the four non-obvious
   settings from §1.
5. **The gRPC migration (§0) is the real deadline** and is independent of all
   platform work.

Priority order is 5 → 2 → 1 → 3 → 4: the gRPC ceiling is a countdown on
upstream's release cadence, the broken Fargate gate ships a false all-clear, and
the rest is documentation catching up to what is now true.
