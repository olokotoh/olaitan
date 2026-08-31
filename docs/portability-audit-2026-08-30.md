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

## Blocker 3 — NetworkPolicy is silently inert (CRITICAL, correctness) — **PROVEN**

The entire response mechanism writes NetworkPolicies. Nothing anywhere checks
that the cluster's CNI *enforces* them:

```
$ grep -rn "enforc" internal/response/netpol/*.go   # only internal state naming
```

This was not left as an inference. `hack/check-netpol-enforcement.sh` runs a
client and a server pod, proves the client can reach the server, applies a
deny-all ingress policy, and re-tests. On a stock kind cluster — **the exact
cluster `make quickstart` builds and the e2e suite runs on**:

```
$ ./hack/check-netpol-enforcement.sh
== NetworkPolicy enforcement probe ==
   context: kind-olaitan-port
   server pod IP: 10.244.0.5
   baseline: client CAN reach server (as expected)

RESULT: NetworkPolicy is NOT ENFORCED on this cluster.
        The API server accepted a deny-all policy and traffic still flowed.
EXIT=1
```

Olaitan would mark a workload QUARANTINED, write the audit record, move the FSM
and light the dashboard green — while the pod keeps talking to the internet.

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
