# Ten values that matter

`values.yaml` has over 1300 lines. Almost all of it you will never touch. These
ten are the ones that decide whether Olaitan is useful, safe, or expensive in
your cluster.

The complete reference stays at [helm-values.md](helm-values.md), generated
from the chart. This page is the shortlist, not a replacement.

---

## 1. `response.networkPolicy.enabled`

**Default: `false`.** The global enforcement kill switch.

While it is `false`, Olaitan detects, scores and moves workloads through its
state machine, but writes nothing to your cluster. Turning it on lets the agent
create and delete NetworkPolicies in workload namespaces.

**If you get it wrong:** enabling this before you trust the agent's decisions
turns a false positive into an outage. Leave it off until you have watched the
transitions on your own traffic.

## 2. `response.networkPolicy.clusterCidrs`

**Default: empty.** Your cluster's real pod and service CIDRs.

RESTRICTED blocks external egress while allowing RFC 1918 ranges, the CIDRs
listed here, and `extraAllowedCidrs`.

**If you get it wrong:** empty, on a cluster whose internal ranges are not
covered by the defaults, means a RESTRICTED workload loses in-cluster DNS. The
workload then looks far more broken than the thing you were containing. Set
this *before* you set value 1.

## 3. `response.excluded_namespaces`

**Default: `kube-system`, `olaitan`.** Namespaces the response ring never acts in.

**If you get it wrong:** removing `kube-system` lets the agent quarantine
CoreDNS, which takes the cluster down while the agent reports success.
Removing `olaitan` lets it quarantine itself in the middle of an incident.
Add to this list; think very hard before subtracting.

## 4. `evaluation.config`

**Default: full pipeline.** Which detection tiers run.

- `RS` runs the deterministic tiers only: Sigma rules plus Welford baselines.
- `RSL` and `RSLT-*` add the LLM analyst tier.

**If you get it wrong:** nothing breaks, but `RS` is the honest starting point.
It costs nothing, sends no telemetry anywhere, and is the configuration most
operators should run first.

## 5. `analyst.provider` and the `analyst.*_model` family

**Default: `none`.** Which language model backs tier 3, if any.

Provider-agnostic: Claude, OpenAI, Ollama, or any OpenAI-compatible endpoint.
Roles are configured separately (`l1`, `l2`, `senior`), so you can run a cheap
model at L1 and a stronger one for escalation.

**If you get it wrong:** pointing every role at an expensive model and leaving
the agent running against a noisy cluster is how you get a surprising bill.
Set a spend limit on the credential.

## 6. `secrets.llmApiKey`

**Default: unset.** The credential for value 5.

**If you get it wrong:** scope it to the smallest thing your provider offers.
The tier-3 analyst reads attacker-influenceable fields (log lines, process
arguments, image names), so treat the credential as reachable by anything that
can write to those.

## 7. `falco.enabled`

**Default: `true`.** The bundled Falco subchart, which supplies eBPF syscall
telemetry: one of the five signal sources and the richest one.

**If you get it wrong:** it needs kernel 6.5 or newer for the eBPF driver, and
it cannot work inside kind at all (kind nodes are containers; eBPF is
host-scoped). Turning it off is correct for a laptop demo and a significant
loss of signal anywhere else. If you disable it, also set
`endpoints.falco` to a closed port or the collector will keep dialling a
service that is not there.

## 8. `nats.streamMaxBytesOverride`

**Default: empty**, which leaves JetStream retention sized for production.

**If you get it wrong:** on a small node the default sizing exceeds available
storage and the aggregator and collector sit in `CrashLoopBackOff` with
`ensure stream EVENTS_RAW: ... insufficient storage resources available`. This
is the single most likely thing to break your first install
([issue #96](https://github.com/olokotoh/olaitan/issues/96)). `values-quickstart.yaml`
sets 1 GiB per stream for exactly this reason.

## 9. `baselines.warmupDuration`

**Default: `30m`.** How long the Welford statistical tier observes a workload
before its deviations are trusted.

**If you get it wrong:** shortening this to seconds, as the quickstart overlay
does, means the statistical tier has effectively no history and any detection
you see is carried by the rule tier alone. That is fine for a demo and
misleading in production, where a too-short warm-up produces deviation alerts
against a baseline that never settled.

## 10. `fsm.dwellSeconds` and `fsm.deescalationCooldownSeconds`

**Defaults: `0 / 120 / 120` seconds, and `600`.** How long a workload must stay
in a state before it can leave, and how long the agent waits before relaxing a
workload to a lower state.

These damp oscillation. Without them a workload flaps between states on
noisy signal, and every flap under enforcement is a NetworkPolicy write.

**If you get it wrong:** too short and you flap. Too long and a cleaned-up
workload stays contained well past the point it should have been released.
Note that non-CLEAN states do **not** expire on a timer: de-escalation happens
when signals subside, gated by this cooldown. A workload whose signals never
clear stays where the agent put it until you intervene.

---

## What is not on this list

**Retention and sizing**, beyond value 8. The defaults are reasonable and the
failure mode is a bill, not an outage.

**Resource requests and limits.** Tune them after you have watched real usage,
not before.

**The audit subjects** (`response.audit.enabled`, default `false`). Turn them on
if you are forwarding to a SIEM. They are append-only and retention-capped, and
they are how the quickstart renders its timeline.
