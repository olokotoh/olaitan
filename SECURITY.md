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
against the ClusterRole, not against the flag. Narrowing this is tracked as
part of Story 8.5.

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
name is already on the default list. Surfacing this guard as a Helm value is
tracked as part of Story 8.5.

**Two things this list does not include, deliberately:**

- **There is no cap on how many workloads can be quarantined at once.** A
  correlated false positive across many pods is not bounded by anything today.
  If you enable enforcement, watch the transition rate.
- **Non-CLEAN states do not expire on a timer.** De-escalation is driven by
  signals subsiding, gated by the cooldown above. The only TTL on a *state*
  belongs to operator override pins, not to anything the agent chose. A
  workload whose score never drops below its entry threshold for a full
  cooldown stays where the agent put it until you intervene.

  There is a second TTL in the response path, and it is the one that actually
  governs how fast a workload becomes eligible to step down: the rolling
  risk-decay window (`internal/response/risk/window.go`), where each signal
  stops contributing once it is older than the window. It is configured by the
  `OLT_RISK_WINDOW_SECONDS` environment variable rather than by a config key,
  which makes it easy to miss when tuning de-escalation.

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

   What it does **not** guarantee: the contribution is additive, so a workload
   the deterministic tiers already scored at 19 can be pushed over the
   SUSPICIOUS threshold by the analyst alone. The cap bounds the model's
   *contribution*, not the *state* a borderline workload can reach. If you need
   the stronger property, run with the analyst tier off; everything except
   tier-3 reasoning works without it.

**What the cap does not address: suppression.** Every mitigation above bounds
the model in the upward direction. An attacker who already controls log lines
and process arguments may prefer the opposite: arguing a real detection is
benign, or helping satisfy the "signals subsiding" condition that drives
de-escalation. The deterministic tiers still fire independently of the analyst,
so a suppressed verdict cannot erase a rule match or a baseline deviation, but
the analyst's downward influence on a score is not separately bounded. Treat
tier-3 output as advisory, and alert on tier-1 and tier-2 signals directly if
you care about this.

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
