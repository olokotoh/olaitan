# Security policy

## Support status

Olaitan is a **research preview**. There is no support contract and no
guaranteed response time. Security reports are taken seriously and answered on
a best-effort basis.

## Supported versions

Only the most recent release line receives fixes. There are currently no
maintained older branches: `v1.0.0-rc1` and `v1.0.0-rc2` are superseded, and
fixes land on `main` and in the next tag rather than being backported. The
`:edge` image tracks `main` and is not a supported artefact.

## Reporting a vulnerability

Report privately through GitHub's
[security advisory form](https://github.com/olokotoh/olaitan/security/advisories/new).
Please do not open a public issue for anything exploitable.

Include the version or commit, the cluster shape, and the smallest reproduction
you can manage. If you would like credit in the advisory, say so and give the
name you want used.

There is no embargo period you are obliged to honour and no bounty. A note on
timing before you publish is appreciated, not required.

## What this agent can do to your cluster

Olaitan is a detector that can also act. Before installing it, understand the
blast radius.

**Read surface, always.** The aggregator's ClusterRole grants get/list on
`pods`, `events` and `serviceaccounts`; the `apps` workload kinds
(deployments, replicasets, statefulsets, daemonsets); the `batch` kinds; and
the RBAC kinds (roles, rolebindings, clusterroles, clusterrolebindings). It
does **not** grant `nodes` or `namespaces`.

Beyond the API, it receives Kubernetes audit events, which carry request
metadata for the whole cluster, plus container runtime and CNI flow telemetry
from its nodes and application logs from the workloads it is pointed at. Audit
events in particular can be sensitive, so treat Olaitan's storage and its NATS
streams as security-relevant data.

**Write surface: the permission is granted whether or not enforcement is on.**

This is the part worth reading twice. `response.networkPolicy.enabled` gates
the *code path*, not the *RBAC*. Even on a default observe-only install, the
aggregator's ClusterRole holds:

- `networkpolicies`: create, update, delete, in every namespace
- `pods`: patch, cluster-wide (the agent annotates pods with FSM state)

Neither rule is conditional on any value. The chart does gate RBAC on values
where it intends to, so this is a deliberate shape rather than an oversight,
but it means **"enforcement is off" is a statement about the agent's behaviour,
not about what its ServiceAccount could do.** Anyone who can exec into the
aggregator, or who finds an escalation path through its ServiceAccount, has
cluster-wide NetworkPolicy write regardless of your settings. Size your review
against the ClusterRole, not against the flag.

**Setting `response.forensics.enabled` widens this considerably.** That flag is
gated in the chart, and it adds cluster-wide:

- `pods`: delete
- `pods/log`: get

Cluster-wide pod-log read is a larger data-exposure surface than the audit
stream warned about above: it reaches application logs in every namespace,
including ones Olaitan is not monitoring. Pod delete is what makes the
PRESERVED_KILLED state possible. Enable forensics deliberately.

The collector's Role is separate and namespace-scoped: get, list and watch on
`pods` and `events` in the release namespace only.

**What enabling enforcement changes** is that the agent starts using those
permissions: RESTRICTED cuts a workload's egress to a configured allow-list,
and QUARANTINED cuts effectively all of its traffic. A false positive at
QUARANTINED is an outage for that workload. That is why the default is off.

## Guards on the blast radius

| Guard | Where | What it bounds |
| --- | --- | --- |
| `response.networkPolicy.enabled` | chart values | Global enforcement kill switch. `false` by default, so nothing is written until you opt in. |
| `response.excluded_namespaces` | `config/olaitan.yaml` | Namespaces the response ring skips entirely. Defaults to `kube-system` and `olaitan`. **Not settable through Helm values** (see below). |
| Trust ladder score cap | code | Bounds how far the LLM tier alone can move a workload's score. |
| Dwell guards and `deescalation_cooldown_seconds` | `config/olaitan.yaml` | Damp oscillation. A single low sample cannot de-escalate a workload; the cooldown defaults to 600s. |
| `response.override` | `config/olaitan.yaml` | **Off by default.** When enabled, an operator annotation pins a workload's state, overriding the agent. The pin carries its own TTL (default 1h) and releases on expiry or on removing the annotation. |

Keep `kube-system` and `olaitan` in `excluded_namespaces`. An agent that can
quarantine CoreDNS can take the cluster down while reporting that it did its
job, and one that can quarantine itself will do so mid-incident.

**Changing that list currently requires building the chart from source.** The
chart renders `config/olaitan.yaml` into a ConfigMap almost verbatim; only a
few settings have Helm bridges, and `excluded_namespaces` is not one of them.
On the published-chart install path you get the defaults, which is why the
install command in the README puts the release in the `olaitan` namespace: that
name is already on the default list. Surfacing this guard as a Helm value is on the roadmap; there is no public
tracking issue for it yet.

**Two things this list does not include, deliberately:**

- **There is no cap on how many workloads can be quarantined at once.** A
  correlated false positive across many pods is not bounded by anything today.
  If you enable enforcement, watch the transition rate.
- **Non-CLEAN states do not expire on a timer.** De-escalation is driven by
  signals subsiding, gated by the cooldown above. The only TTL on a *state*
  belongs to operator override pins, not to anything the agent chose. A
  workload whose score never drops below its entry threshold for a full
  cooldown stays where the agent put it until you intervene.

  There is a second TTL in the response path, but it is **off by default**:
  the rolling risk-decay window (`internal/response/risk/window.go`), where a
  signal stops contributing once it is older than the window. It is enabled by
  setting `OLT_RISK_WINDOW_SECONDS` to a non-zero value, and
  `cmd/olaitan/main.go` defaults it to `0`, which selects per-package scoring
  instead. If you turn it on, it becomes the main thing governing how fast a
  workload becomes eligible to step down. If you leave it alone, it governs
  nothing.

## The LLM tier and prompt injection

The tier-3 analyst reads fields that an attacker inside the cluster can
influence: log lines, process arguments, container image names, Kubernetes
object names. Treat this as an untrusted input path into a language model.

Three mitigations are in place, and they are defence in depth rather than a
proof:

1. **Redaction** before any evidence reaches the model.
2. **A schema-validated response contract.** The model returns a constrained
   structure; free-form text is not executed and does not reach the response
   path.
3. **The trust ladder score cap.** This is the load-bearing mitigation: the
   others reduce the chance of manipulation, this one bounds its consequence.

   Be precise about what it guarantees. The score is
   `0.4*rule + 0.3*baseline + 0.3*llm_capped`, with the analyst's contribution
   clamped to a cap of 35 (`internal/decision/score/score.go`). So the most the
   model can contribute alone is `0.3 * 35 = 10.5`, below the 20 needed to
   reach SUSPICIOUS. **A fully controlled model cannot escalate a workload that
   the deterministic tiers scored at zero.** `TestProperty_NoLLMOnlyEscalation`
   checks that bound in CI.

   What it does **not** guarantee: the contribution is additive, so the cap
   bounds the model's *contribution*, not the *state* a borderline workload can
   reach. This does not bite at the SUSPICIOUS boundary, because the analyst
   chain only runs at all above a severity floor of 50 or a sigma floor of 3.0
   (`internal/decision/analyst/trigger.go`), and either already scores at least
   20 deterministically. It bites at the higher bands: a workload the
   deterministic tiers put at 35 plus a full 10.5 reaches 45.5 and crosses
   RESTRICTED at 40. If you need the stronger property, run with the analyst
   tier off; everything except tier-3 reasoning works without it.

   **The bound is checked against a constant, not against your configuration.**
   `config.SuspiciousThreshold` is hardcoded to `20.0` and is what both the
   config validator and `TestProperty_NoLLMOnlyEscalation` compare against, but
   the FSM takes its live threshold from `detection.confidence_bands.watch`. A
   legal `watch: 10` would let the analyst alone clear the bar while the
   validator and the property test both still pass. If you lower `watch` below
   20, the no-LLM-only-escalation guarantee no longer holds and nothing will
   tell you.

**On suppression.** An attacker who controls log lines and process arguments
may prefer to argue a real detection is benign rather than to manufacture a
false one. The structure of the score bounds this too, and it is worth being
exact rather than alarming: the analyst term is clamped to `[0, cap]` and
**added** to the deterministic score (`total := rules + baseline + llm`). The
model can never subtract. The whole of its downward influence is contributing
`0` instead of up to `10.5`, which is the same bound in the same place. A
suppressed verdict cannot erase a rule match or a baseline deviation.

That is a real structural protection, not a hedge. It is also the reason to
alert on tier-1 and tier-2 signals directly: they are the part an analyst
cannot argue away.

If you find a way past the cap in either direction, that is the report we most
want to receive.

## Hardening notes

- Leave enforcement off until you have watched the agent's decisions on your
  own traffic for long enough to trust them.
- Set `response.networkPolicy.clusterCidrs` to your real cluster CIDRs before
  enabling enforcement, or RESTRICTED will sever in-cluster DNS.
- Scope the LLM provider credential to the smallest thing your provider offers,
  and set a spend limit on it.
- The agent's own namespace should be in `response.excluded_namespaces` so it
  cannot quarantine itself mid-incident.
