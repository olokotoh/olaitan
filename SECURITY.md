# Security policy

## Support status

Olaitan is a **research preview**. There is no support contract and no
guaranteed response time. Security reports are taken seriously and answered on
a best-effort basis.

## Reporting a vulnerability

Report privately through GitHub's
[security advisory form](https://github.com/olokotoh/olaitan/security/advisories/new).
Please do not open a public issue for anything exploitable.

Include the version or commit, the cluster shape, and the smallest reproduction
you can manage. If you would like credit in the advisory, say so and give the
name you want used.

## What this agent can do to your cluster

Olaitan is a detector that can also act. Before installing it, understand the
blast radius.

**When enforcement is off (the default), it can:**

- read pods, nodes, namespaces and events across the cluster
- receive Kubernetes API audit events, which contain request metadata for the
  whole cluster
- read container runtime and CNI flow telemetry from the nodes it runs on
- read application logs from the workloads it is pointed at

That is a broad read surface. Audit events in particular can carry sensitive
request metadata, so treat Olaitan's storage and its NATS stream as
security-relevant data.

**When `response.networkPolicy.enabled` is set to `true`, it can additionally:**

- create, update and delete NetworkPolicies in workload namespaces
- move a workload to RESTRICTED, cutting its egress to a configured allow-list
- move a workload to QUARANTINED, cutting effectively all of its traffic

A false positive at QUARANTINED is an outage for that workload. This is why the
default is off.

## Guards on the blast radius

| Guard | Where | What it bounds |
| --- | --- | --- |
| `response.networkPolicy.enabled` | chart values | Global enforcement kill switch. `false` by default, so nothing is written until you opt in. |
| `response.excluded_namespaces` | `config/olaitan.yaml` | Namespaces the response ring skips entirely. Defaults to `kube-system` and `olaitan`. |
| Trust ladder score cap | code | Bounds how far the LLM tier alone can move a workload's score. |
| Dwell guards and `deescalation_cooldown_seconds` | `config/olaitan.yaml` | Damp oscillation. A single low sample cannot de-escalate a workload; the cooldown defaults to 600s. |
| `response.override` | `config/olaitan.yaml` | An operator annotation pins a workload's state, overriding the agent. The pin carries its own TTL (default 1h) and releases on expiry or on removing the annotation. |

Keep `kube-system` and `olaitan` in `excluded_namespaces`. An agent that can
quarantine CoreDNS can take the cluster down while reporting that it did its
job, and one that can quarantine itself will do so mid-incident.

**Two things this list does not include, deliberately:**

- **There is no cap on how many workloads can be quarantined at once.** A
  correlated false positive across many pods is not bounded by anything today.
  If you enable enforcement, watch the transition rate.
- **Non-CLEAN states do not expire on a timer.** De-escalation is driven by
  signals subsiding, gated by the cooldown above. The only TTL in the response
  path belongs to operator override pins, not to agent-chosen states. A
  workload whose signals never clear stays where the agent put it until you
  intervene.

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
3. **The trust ladder score cap.** Even a fully controlled model cannot escalate
   a workload past what the deterministic tiers independently justify. This is
   the load-bearing mitigation: the others reduce the chance of manipulation,
   this one bounds its consequence.

If you find a way past the cap, that is the report we most want to receive.

## Hardening notes

- Leave enforcement off until you have watched the agent's decisions on your
  own traffic for long enough to trust them.
- Set `response.networkPolicy.clusterCidrs` to your real cluster CIDRs before
  enabling enforcement, or RESTRICTED will sever in-cluster DNS.
- Scope the LLM provider credential to the smallest thing your provider offers,
  and set a spend limit on it.
- The agent's own namespace should be in `response.excluded_namespaces` so it
  cannot quarantine itself mid-incident.
