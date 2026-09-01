# Portability audit — what actually stops a stranger installing Olaitan

**Date:** 2026-08-30 · **Branch:** `epic-9/portability-any-cluster` · **Chart under test:** published `oci://ghcr.io/olokotoh/charts/olaitan` v1.0.0-rc3 and the tree at `main` (778c08c)

This is the evidence base for Epic 9. Every line below was produced by running
the command shown, not by reading the code and inferring. Where something is
inferred or unverified it says so.

---

## The headline

The README claims **"Kubeadm clusters only. Managed control planes (EKS, GKE,
AKS) are out of scope."** That claim is **wrong in the operator's favour and
wrong in a way that costs adoption**: the three features that genuinely need a
kubeadm control plane are all **disabled by default**, so the default install
does not need one.

```
$ grep -n -A1 "^auditWebhook:|^containerdSensor:|^calicoSensor:" values.yaml
auditWebhook:      enabled: false
containerdSensor:  enabled: false
calicoSensor:      enabled: false
falco:             enabled: true      # the only source on by default
```

The default render contains **zero hostPath mounts from Olaitan's own
templates**; the 14 in the full render all come from the bundled Falco subchart,
which already probes six CRI sockets including `/run/k3s/containerd/containerd.sock`
and `/run/crio/crio.sock`:

```
$ helm template olaitan deploy/helm/olaitan --set secrets.redisPassword=x \
    | python3 -c '<group hostPath by source>'
olaitan/charts/falco/templates/daemonset.yaml  DaemonSet  ['/var/run/docker.sock',
  '/run/podman/podman.sock', '/run/host-containerd/containerd.sock',
  '/run/containerd/containerd.sock', '/run/crio/crio.sock',
  '/run/k3s/containerd/containerd.sock', '/boot', '/lib/modules', '/usr',
  '/etc', '/sys/kernel', '/proc', '/run/falco']
olaitan/templates/daemonset.yaml               DaemonSet  ['/run/falco']
```

So the *portability story is much better than the README says* — and nobody can
tell, because the README turns them away at the door.

---

## Blocker 1 — the very first command fails (CRITICAL)

A stranger's first action after finding the chart is `helm install`. It errors:

```
$ helm template olaitan deploy/helm/olaitan
Error: execution error at (olaitan/templates/secret.yaml:29:4):
  secrets.redisPassword is required when redis.enabled=true.
```

There is no default and no generated value. The bundled Redis is *our* choice of
subchart, not the operator's, so the chart demands a secret for a component the
operator did not ask for. **Impact: every install attempt fails until the user
reads the template source.**

## Blocker 2 — the published chart has no quickstart (CRITICAL)

`values-quickstart.yaml` exists only on the unmerged `epic-8/story-8-3` branch:

```
$ helm pull oci://ghcr.io/olokotoh/charts/olaitan --version 1.0.0-rc3
$ ls olaitan/values-quickstart.yaml
ABSENT from published rc3
```

`make quickstart` also cannot help a stranger: it is hard-wired to kind
(`kind create cluster --config hack/kind-config.yaml`) and to a local checkout.
There is currently **no supported path from "found the repo" to "saw it work"
on any cluster the user already has.**

## Blocker 3 — NetworkPolicy may be written but never enforced

**Status: the PROVEN claim is RETRACTED. The risk is real; the evidence was not.**

The response mechanism writes NetworkPolicies and nothing checks that the
cluster's CNI *enforces* them:

```
$ grep -rn "enforc" internal/response/netpol/*.go   # only internal state naming
```

This was originally recorded as PROVEN on kind, on the strength of
`hack/check-netpol-enforcement.sh` reporting NOT ENFORCED. **That script was
broken.** It grepped probe output for `timed out`, while agnhost prints a bare
uppercase `TIMEOUT`. The pattern never matched, so a *blocked* connection was
read as *traffic flowing* and the verdict was predetermined: NOT ENFORCED on
every cluster it was ever pointed at, regardless of the truth.

Found on a real 3-node kubeadm cluster running Calico v3.31.5, where the script
said NOT ENFORCED and a manual probe proved the opposite — nginx reachable
before a deny-all, `wget: download timed out` after. The script was accusing a
CNI that was working correctly the whole time.

Fixed in `d6d20b7`: match every phrasing a blocked connection can produce, and
self-test the matcher against a known-unreachable address (10.255.255.1) before
emitting any verdict. If a guaranteed-blocked connection does not read as
blocked, the script now exits INCONCLUSIVE instead of publishing a finding.

**Corrected result on kubeadm + Calico:**

```
$ ./check-netpol-enforcement.sh
   baseline: client CAN reach server (as expected)
RESULT: NetworkPolicy IS ENFORCED on this cluster.
```

**What remains true.** kind's default CNI (kindnet) does not implement
NetworkPolicy, and k3s's default flannel backend does not either — both
documented upstream. Olaitan writing a policy on those clusters still achieves
nothing, and would mark a workload QUARANTINED, write the audit record, move the
FSM and light the dashboard green while the pod keeps talking to the internet.
What changed is that **this repository has not demonstrated it**; the earlier
evidence was an artefact of the bug. Re-run the corrected script on kind before
making the claim again.

**This is the same class of defect as the security patrol's false closures
(2026-08-30): a control reporting success it did not achieve.** It is the most
serious finding in this audit, it is a correctness problem rather than a
packaging one, and it exists on clusters we already claim to support. Note the
mitigating fact: enforcement is `false` by default, so a default install is
honest — the trap is armed only when an operator turns response on, which is
precisely when they are trusting it most.

## Blocker 5 — the chart's default image tag does not exist (CRITICAL) — **PROVEN**

Installing the chart from the repository tree (what a contributor, or anyone
running `helm install ./deploy/helm/olaitan`, does) schedules pods that can
never start:

```
$ helm install olaitan deploy/helm/olaitan -n olaitan --create-namespace   # succeeds
$ kubectl -n olaitan get pods
olaitan-aggregator-...   0/1   ErrImagePull
$ kubectl -n olaitan describe pod ...
  Failed to pull image "ghcr.io/olokotoh/olaitan:0.1.0":
    ghcr.io/olokotoh/olaitan:0.1.0: not found
```

`Chart.yaml` carries `appVersion: "0.1.0"` and `values.yaml` leaves
`image.tag` empty so the helper falls back to it. The Story 8.1 release
workflow stamps the real version at package time, so **the published chart is
fine and only the in-tree default is broken** — which is exactly the path every
contributor and every `helm install ./chart` user takes.

Tags that actually exist on GHCR: `edge`, `1.0.0-rc2`, `1.0.0-rc3`.

The install *reports success* (`STATUS: deployed`) while nothing can run. Same
family as the other findings here: a green signal over a broken reality.

## Blocker 6 — the default install cannot start on ANY cluster under ~160 GiB (CRITICAL) — **PROVEN**

With the image tag fixed, the aggregator gets further and then dies:

```
$ kubectl -n olaitan logs -l app.kubernetes.io/component=aggregator
ERROR startup: aggregator ring wiring
  err="ensure stream EVENTS_RAW: nats: API error: code=500 err_code=10047
       description=insufficient storage resources available"
```

The PVC is **bound and healthy at 10Gi**, so this is not a cluster limitation.
`internal/nats/streams.go` declares each stream's `MaxBytes` independently of
the volume it has to fit in:

| stream | declared MaxBytes |
| --- | --- |
| EVENTS | 10 GiB |
| EVENTS_RAW | 50 GiB |
| THREATS | 100 GiB |
| **total** | **160 GiB** |

against a default `nats.persistence.size` of 10 Gi. JetStream reserves against
the file store up front, so `EVENTS_RAW` alone (50 GiB) exhausts a 10 Gi volume
and the very first `CreateOrUpdateStream` fails.

This is filed as issue #96 and scoped to Story 8.3 as a *quickstart* fix
(`values-quickstart.yaml` setting `nats.streamMaxBytesOverride`). **That framing
is too narrow.** The defect is not specific to kind or to a single-node laptop:
the chart's declared retention exceeds its own default volume by 16x, so a
plain `helm install` fails on every cluster whose default StorageClass gives it
less than ~160 GiB. An override in one demo values file leaves the default
install broken everywhere else.

The honest fix belongs in the default: either size the streams to the volume, or
size the volume to the streams, and add a render-time guard that fails loudly
when the declared sum exceeds `nats.persistence.size` rather than letting the
operator discover it from a JetStream error code at runtime.

## Blocker 7 — the repo's own kubeadm terraform cannot build a working multi-node cluster (CRITICAL) — **PROVEN**

`deploy/terraform` is the module the thesis evaluation runs on. It did not set
`source_dest_check = false` on the EC2 instances, and AWS defaults it to `true`.

EC2 drops any packet whose source or destination IP does not belong to the
instance. Every CNI overlay violates that by design: a VXLAN packet leaving a
node carries a **pod** IP (192.168.0.0/16), not the node's 10.77.0.0/24 address,
so AWS discards it. Silently — no error, no log, no counter.

What that produces is worse than a broken cluster: a cluster that **looks
healthy and is not.**

```
$ kubectl get nodes            # all 3 Ready
$ kubectl -n olaitan get pods -o wide
olaitan-falco-brj48    2/2  Running                 ip-10-77-0-28    <- CoreDNS node
olaitan-falco-jkgt2    0/2  Init:CrashLoopBackOff   ip-10-77-0-25
olaitan-falco-lgx49    0/2  Init:CrashLoopBackOff   ip-10-77-0-234
olaitan-aggregator     0/1  CrashLoopBackOff        ip-10-77-0-25
```

One root cause, four symptoms that each look like a different bug:

- **both CoreDNS replicas** happened to schedule on `ip-10-77-0-28`, so DNS
  worked on that node and timed out on every other one
- aggregator on `.25`: `aggregator: nats: connect: dial tcp: lookup
  olaitan-nats: i/o timeout` — NATS was Running on `.28`
- falcoctl init: `lookup falcosecurity.github.io: i/o timeout`
- Calico's own APIService: `FailedDiscoveryCheck ... context deadline exceeded`,
  which then wedged four namespaces in `Terminating`

Fixed in `main.tf` with the reasoning recorded inline. Verified live on the
running cluster with `modify-instance-attribute --no-source-dest-check`.

**Why this one matters most.** Single-node kind cannot expose it — there is no
cross-node traffic to drop. Every Olaitan test to date ran on kind, so the
multi-node path the thesis claims to evaluate had never actually worked. It also
generalises: the failure is invisible in `kubectl get nodes`, `helm status`
reports `deployed`, and the aggregator's own health endpoint answers fine while
the ring behind it is unreachable.


## Blocker 8 — the collector cannot attach to Falco's socket as non-root (CRITICAL) — **PROVEN, FIXED in Story 9.6**

With cross-node networking repaired, Falco reached 2/2 Running on all three
nodes and the collector still crash-looped on every one:

```
$ kubectl -n olaitan logs olaitan-collector-8p7p8 --previous
"msg":"ring exited with error","ring":"collector",
"err":"collector: falco run: falco: sub (terminal, no retry): rpc error:
 code = Unavailable desc = ... dial unix /run/falco/falco.sock:
 connect: permission denied"

$ sudo ls -la /run/falco/falco.sock
srwxr-xr-x 1 root root 0 Aug 31 22:37 /run/falco/falco.sock
```

Falco creates the socket `0755 root:root`. Connecting to a Unix socket requires
**write** permission, and the collector runs `runAsUser: 65532` /
`runAsNonRoot: true` per NFR11. Owner-only write means the collector can never
attach. **Olaitan's primary detection source is unreachable on a stock kubeadm
cluster** — Falco runs, the collector dies, and no syscall events are ingested.

**Fixed 2026-09-01 (Story 9.6).** The chart now ships a
`falco-socket-permissions` container in the collector's own pod: root, all
capabilities dropped except CHOWN, read-only root filesystem, holding
the socket at `0660` group 65532. It is a native sidecar
(`initContainers` + `restartPolicy: Always`), so it is ordered before the
collector's first dial AND keeps running: a Falco restart recreates the socket
at `0755` and the sidecar repairs it within one interval, which a one-shot init
container could not do (init containers do not re-run when an app container
restarts). It lives in the collector's pod rather than Falco's so that an
operator pointing `endpoints.falco` at their own Falco DaemonSet gets the same
fix; `falco.extra.initContainers` would only have reached the bundled subchart.

Verified by running it, not by reading it. The defect was reproduced in
containers (socket bound `0755 root:root` under umask 022; UID 65532 gets
`EACCES`), the rendered script then made the same dial succeed under exactly
the shipped securityContext, the source was restarted to prove the reconcile
loop repairs `0755` within one interval, and the fixer was run with no
privilege to confirm it exits non-zero rather than reporting success. On a live
kind cluster the sidecar starts before the collector and the pod reaches 2/2.

**The original wrong turn, kept as the record.** A first attempt set
`grpc.unix_socket_mode: "0775"`
in the Falco values. The rendered ConfigMap carried it and the socket stayed
`0755`, because **that key does not exist** — upstream `falco.yaml` (checked
through 0.42.0) exposes only `enabled`, `bind_address`, `threadiness` and the
mTLS cert paths. It was an invented setting that Falco silently ignored, and the
"fix" would have been published as working. `falcosecurity/falco#1351` is the
upstream request for exactly this, still open.

Real options, for Story 9.6:
1. a `chmod` initContainer on the collector DaemonSet (runs as root once, then
   the long-lived process stays non-root) — most likely correct;
2. a supplemental group shared with Falco, if the Falco chart can be made to
   create the socket group-writable;
3. running the collector as root — rejected: that trades a file permission for
   a privileged process parsing untrusted event data.

**Why kind never caught it.** On kind, Falco and the collector end up sharing an
effective identity, so the dial succeeds and the permission question never
arises. Every prior test ran there.


## Blocker 4 — no NOTES.txt, no capability detection

```
$ ls deploy/helm/olaitan/templates/NOTES.txt   # does not exist
$ grep -n "Capabilities|KubeVersion|APIVersions" templates/_helpers.tpl   # no hits
```

The chart never asks what cluster it is on and never tells the operator what it
concluded. After a successful install the user gets no next step, no "these
sources are off and here is why", no verification command.

---

## What is genuinely impossible, and where

Kept separate from the above on purpose: these are real platform limits, not
our bugs. A portable chart must **degrade honestly** around them rather than
pretend.

| Capability | Where it is impossible | Why |
| --- | --- | --- |
| K8s audit webhook | EKS, AKS, GKE (all managed) | needs `--audit-webhook-config-file` on kube-apiserver; managed control planes do not expose flags. Documented alternatives are CloudWatch / Azure Diagnostic Settings / Cloud Logging — a *different* ingestion path, not a flag flip |
| Calico CNI flow adapter | any cluster not running Calico via the Tigera operator | conflicts with cloud CNIs (VPC CNI, Azure CNI) |
| containerd CRI sensor | CRI-O clusters; any node without `/run/containerd` | socket path differs (k3s: `/run/k3s/containerd/containerd.sock`) |
| privileged DaemonSet | GKE Autopilot (unless allowlisted) | admission policy blocks privileged workloads |

All four are already `enabled: false` by default, which is why the default
install is far more portable than advertised.

---

## Verification status of this document

- Chart renders, hostPath inventory, missing NOTES.txt, missing quickstart,
  Redis password failure, absent CNI enforcement check: **verified by command
  on 2026-08-30**, outputs above.
- Per-platform limits table: from official vendor documentation gathered in
  parallel research; each row is cited in the Epic 9 story that consumes it.
  **Not yet verified against a live EKS/AKS/GKE cluster** — that is a story
  acceptance criterion, not an assumption to build on.

## New finding 2026-09-01 — Falco's gRPC output is DEPRECATED upstream

Not a portability blocker, and not fixed here, but it belongs on the record
before this is open-sourced: Falco 0.43.1 announces the interface Olaitan's
primary detection source depends on as deprecated, twice, on every start:

```
$ kubectl -n olaitan logs olaitan-falco-88xg6 -c falco
Using deprecated gRPC server (deprecated as consequence of gRPC output deprecation).
Using deprecated gRPC output. Please consider using other outputs.
```

Olaitan reads Falco through `grpc_output` over the Unix socket. That is the
path Blocker 8 was about, the path Story 9.6 just fixed, and the path upstream
is signalling it intends to remove. When it goes, Olaitan's largest signal
source goes with it, on a Falco version bump rather than on a change of ours.

Deliberately NOT actioned in Epic 9, which is a packaging epic: replacing the
transport is a Ring 1 adapter change with its own tests and its own evaluation
impact. Recorded here so the decision is made deliberately rather than
discovered by a CI failure after a subchart bump. The documented successors are
the `falcosidekick` HTTP output and the JSON output over a file or socket.
