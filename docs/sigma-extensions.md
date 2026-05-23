# OLT Dialect: Sigma Extensions

This document defines the **OLT** dialect of Sigma rules used by the
Olaitan deterministic detection tier. OLT is a strict superset of the
SIGMA-HQ specification: every standard SIGMA-HQ rule must remain
parseable by an OLT-compliant engine. The extensions are additive and
confined to two well-known namespaces (`k8s.*`, `attack`) plus a
project-local rule-ID grammar.

The dialect is the load-bearing input to Story 1.15 (OLT Sigma rule
engine) and Story 1.16 (initial OLT rule corpus). It is consumed by
the rule-engine implementation, the CI lint tool (`cmd/olaitan-lint`,
Story 6.5), and the rule-corpus authors.

The chosen parser path that backs this dialect is recorded in
`docs/deferred-decisions.md` ADR-2026-04-28-01.

## 1. Scope and superset claim

OLT-rules use the same YAML document shape as SIGMA-HQ rules. All
standard SIGMA-HQ top-level fields (`title`, `id`, `description`,
`status`, `references`, `author`, `date`, `modified`, `tags`, `level`,
`logsource`, `detection`, `fields`, `falsepositives`) carry their
SIGMA-HQ semantics unchanged. OLT adds three things:

1. A namespaced field-reference family for Kubernetes-native data
   (`k8s.*`).
2. A top-level `attack:` annotation listing MITRE ATT&CK technique IDs.
3. A project-local rule-ID grammar that the CI lint tool enforces.

OLT does not remove, redefine, or constrain any SIGMA-HQ-defined field.
The reserved namespaces are explicitly carved out below; everything
outside them remains standard SIGMA-HQ.

## 2. Reserved namespaces

| Namespace | Owner | Examples | Notes |
|---|---|---|---|
| `k8s.*` | OLT | `k8s.pod.namespace`, `k8s.pod.serviceaccount`, `k8s.workload.owner_kind`, `k8s.container.image` | Resolved by the OLT field resolver against `EvidencePackage.workload_posture` (Story 1.14). |
| `attack` (top-level only) | OLT | `attack: [T1496]` | List of MITRE ATT&CK technique IDs, canonical `T<digits>` form. |
| Everything else | SIGMA-HQ | `process.exe`, `network.dst_port`, `EventID`, etc. | Resolved by the OLT field resolver against the streaming-event field map. |

A rule that puts an OLT extension field anywhere outside the OLT
namespaces, or that uses a namespace listed here for non-OLT semantics,
is rejected by the lint tool.

## 3. Kubernetes-native field references (`k8s.*`)

The `k8s.*` namespace exposes workload posture as a flat set of dotted
field names. The names are stable; the engine binds them onto OLT's
internal posture data (`EvidencePackage.workload_posture`). Story 1.14
assembles that data; Story 1.15 wires the binding.

Defined fields (this list grows as new posture sources land; the lint
tool warns on unknown `k8s.*` references):

| Field | Type | Source | Description |
|---|---|---|---|
| `k8s.pod.namespace` | string | KUBE_AUDIT, posture probe | Namespace of the workload's Pod. |
| `k8s.pod.serviceaccount` | string | KUBE_AUDIT, posture probe | ServiceAccount the Pod runs as. |
| `k8s.pod.name` | string | KUBE_AUDIT, posture probe | Pod name. |
| `k8s.workload.owner_kind` | string | KUBE_AUDIT, posture probe | Kind of the Pod's controller (`Deployment`, `StatefulSet`, `Job`, `CronJob`, `DaemonSet`). |
| `k8s.workload.owner_name` | string | KUBE_AUDIT, posture probe | Name of the Pod's controller. |
| `k8s.container.image` | string | CONTAINER_LIFECYCLE, KUBE_AUDIT | Image reference of the container that produced the event. |
| `k8s.container.name` | string | CONTAINER_LIFECYCLE | Container name within the Pod. |

All `k8s.*` references support the standard SIGMA-HQ modifier set
(see §5).

## 4. ATT&CK annotation (`attack:`)

Every OLT rule MUST declare an `attack:` field at the top level whose
value is a non-empty YAML list of MITRE ATT&CK for Containers v18
technique IDs. Two ID forms are valid:

- **Base technique** — uppercase `T` followed by exactly four digits
  (`T1496`, `T1611`). No separator, no trailing dot.
- **Sub-technique** — base technique ID, a single dot, and exactly
  three digits (`T1059.004`).

Both forms are accepted in the same list. The four-digit base and
three-digit sub-technique counts match MITRE ATT&CK Enterprise v18.

```yaml
attack:
  - T1496       # Resource Hijacking (S5 Cryptomining)
  - T1611       # Escape to Host (S1 Container Escape)
  - T1552       # Unsecured Credentials (S2 Credential Exfiltration)
  - T1613       # Container and Resource Discovery (S3 Lateral Movement)
  - T1071       # Application Layer Protocol (S4 C2 Beaconing)
```

The five evaluation scenarios pin to these technique IDs. The CI lint
tool rejects rules without an `attack:` field, rules whose `attack:`
list is empty, and IDs that fail the regex `^T[0-9]{4}(\.[0-9]{3})?$`.

Rationale: `attack:` is the join key between rule output, the
`EvidencePackage.attack_techniques` slice (Story 1.14), the `L1Hypothesis`
and `L2Verification` schemas (Stories 3.5, 3.6), and the forensic
report's ATT&CK section (Story 4.4). A missing or malformed annotation
breaks downstream traceability.

## 5. Modifiers

OLT supports the standard SIGMA-HQ modifier set unchanged. The chosen
wrap-path parser (sigmalite, per ADR-2026-04-28-01) implements:
`contains`, `all`, `startswith`, `endswith`, `windash`, `base64`,
`base64offset`, `re`, `cidr`, `expand`. Story 1.15 lands the chained
modifier semantics; the lint tool refuses unknown modifier names.

Modifiers attach to the field key with a pipe, exactly as in SIGMA-HQ:

```yaml
detection:
  selection:
    process.exe|endswith:
      - 'xmrig'
      - 'minerd'
    k8s.pod.namespace|startswith: 'tenant-'
    network.src_ip|cidr: '10.0.0.0/8'
```

## 6. Rule-ID grammar

OLT rule IDs follow the regex (architecture.md, line 470):

```
^OLT-(EXEC|NET|FILE|PRIV|IMPACT|RECON|PERSIST|EXFIL|CRED|LATERAL)-[0-9]{3}$
```

The category bin selects the high-level kill-chain phase the rule
covers; the three-digit sequence is allocated within the category.
Categories map to broad ATT&CK tactics rather than specific techniques
so that one rule may carry several `attack:` entries while still
sitting in a single category.

| Category | Tactic alignment | Examples |
|---|---|---|
| `EXEC` | Execution | Anomalous binary launch, shell-spawn-from-web |
| `NET` | Command and Control / Lateral movement (network plane) | Beacon-shaped traffic, internal port-scan |
| `FILE` | Discovery, Collection, Defense Evasion (filesystem plane) | Sensitive-path read, file-system enumeration |
| `PRIV` | Privilege Escalation | Capability changes, sudo abuse |
| `IMPACT` | Impact | Cryptominers, ransomware encryptors |
| `RECON` | Reconnaissance, Discovery | API discovery, namespace listing |
| `PERSIST` | Persistence | CronJob abuse, Pod respawn loops |
| `EXFIL` | Exfiltration | Outbound large-payload uploads |
| `CRED` | Credential Access | ServiceAccount-token theft, secret reads |
| `LATERAL` | Lateral Movement | Container-to-container reconnaissance, RBAC abuse |

The CI lint tool refuses any rule whose `id:` field does not match the
regex.

## 7. Worked example

```yaml
title: Cryptominer process pattern in unprivileged Pod
id: OLT-IMPACT-005
description: |
  Detects xmrig / minerd-style executable launches in workload Pods
  not labelled as crypto workloads, with elevated CPU and outbound
  traffic to a known mining pool port range.
status: experimental
attack:
  - T1496
severity: 75
detection:
  process_match:
    process.exe|endswith:
      - 'xmrig'
      - 'minerd'
      - 'cpuminer'
  k8s_context:
    k8s.workload.owner_kind: Deployment
    k8s.pod.namespace|startswith: 'tenant-'
  network_match:
    network.dst_port:
      - 3333
      - 4444
      - 5555
  condition: process_match and k8s_context and network_match
falsepositives:
  - Legitimate crypto-bridge workloads (label `app.kubernetes.io/component=crypto`)
fields:
  - process.exe
  - k8s.pod.namespace
  - k8s.workload.owner_kind
  - network.dst_port
```

This rule is also the parser-validation fixture for the spike POC at
`spikes/sigma-parser/testdata/OLT-IMPACT-005.yaml`. It exercises the
three load-bearing OLT extension surfaces (`attack:`, `k8s.*` field
references, the `OLT-IMPACT-005` ID grammar) plus three standard SIGMA-HQ
modifiers (`endswith`, `startswith`, integer pattern lists).

## 8. Severity convention

OLT rules MAY declare a top-level `severity:` integer in the range
`[0, 100]`. The standard SIGMA-HQ `level:` field (`informational`,
`low`, `medium`, `high`, `critical`) remains valid; when both are
present, `severity:` wins because it carries finer resolution that
the deterministic ThreatScore depends on. A rule with neither field
is treated as `level: medium` for backward compatibility.
An explicit `severity: null` (or `severity:` with no value) is
rejected at parse time: rules either supply an integer in `[0, 100]`
or omit the `severity:` key entirely so the level-table fallback
applies. Silent fallback from explicit-null is forbidden because the
deterministic ThreatScore consumer cannot distinguish "operator
opted out of severity" from "operator forgot to fill it in", and a
loud parser error is the safer disposition for security tooling.

| `level:` | Implied `severity:` if numeric absent |
|---|---|
| `informational` | 10 |
| `low` | 30 |
| `medium` | 50 |
| `high` | 75 |
| `critical` | 90 |

The numeric severity is consumed by the ThreatScore weighting
documented in `_bmad-output/planning-artifacts/architecture.md`.

## 9. Hand-off into the rule engine

The OLT field resolver, lint regex, severity convention, and ATT&CK
annotation enforcement land in `internal/decision/rules/` under
Story 1.15. The chosen wrap-path parser (sigmalite) handles standard
SIGMA-HQ parsing and the modifier set; OLT extensions ride on
sigmalite's existing extension surfaces (`Extra` map for `attack:`
and `severity:`, `FieldResolver` for `k8s.*`).

Story 1.16 landed the initial corpus of ten rules covering S1-S5 at
`rules/<category>/OLT-<CATEGORY>-NNN.yaml` from repo root; each rule
conforms to this dialect and passes `corpus_lint_test.go` (the
default-tag walk over `rules/` that re-uses `parser.ParseRule` and
asserts the AC1 distribution invariants plus the AC2 falsepositives
gate).
