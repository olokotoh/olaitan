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

The annotation is a single top-level `attack:` key whose value is the
YAML list of technique IDs. It is NOT a per-technique dotted key of the
form `attack.<technique>`: there is one `attack:` field per rule, and a
rule that covers several techniques lists them all under that one key.
The parser reads the list from the rule's extension map
(`extractAttack` over sigmalite's `Rule.Extra["attack"]`,
`internal/decision/rules/parser/parser.go`), so a malformed shape is
rejected at parse time.

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

## 9. False-positive characterisation field (`falsepositives:`)

Every OLT rule MUST declare a `falsepositives:` field whose value is a
non-empty YAML list of human-readable strings. The field carries its
standard SIGMA-HQ semantics (a list of known benign conditions that can
trip the rule) and OLT raises it to a required convention because a
deterministic detection that ships without its benign-context notes is
not operable: the operator needs the false-positive characterisation to
tune allowlists and to triage an alert.

The corpus enforces this. The default-tag corpus walk
(`TestCorpusLint_AllRulesParse`,
`internal/decision/rules/corpus_lint_test.go`) asserts the AC2
falsepositives gate over every rule under `rules/`, so a rule that omits
the field, or that ships an empty list, fails the build.

OLT pins one additional convention on the content of each entry: an
entry names BOTH the benign source AND the allowlist mechanism that
suppresses it, so the note is actionable rather than decorative. The
real corpus follows this shape, for example (from
`rules/priv/OLT-PRIV-001.yaml`):

```yaml
falsepositives:
  - Privileged DaemonSets such as CNI or CSI plugins; excluded by the workload_kind filter
  - Security testing workloads inside dedicated namespaces; allowlist via a dedicated namespace shape
```

The first clause identifies the benign workload; the second names how an
operator excludes it (a detection-side filter the rule already carries,
or an allowlist mechanism an operator adds in an overlay). A rule whose
false positives cannot be characterised this way is usually too broad
and should be narrowed before it ships.

## 10. Additional worked examples

Section 7 gives the first worked example (`OLT-IMPACT-005`). The two
rules below complete the minimum set of three, each drawn verbatim from
the real corpus and each exercising a different combination of OLT and
SIGMA-HQ surfaces.

### 10.1 `OLT-PRIV-001`: privileged capability acquisition

This rule exercises the `process.cap_effective|contains` list match, a
`k8s.workload.owner_kind` list value, a negated `k8s.pod.namespace`
system-namespace filter in the `condition`, the highest severity band
(`severity: 90`), and the container-escape technique `T1611`.

```yaml
title: Privileged capability acquisition in workload Pod
id: OLT-PRIV-001
description: |
  Detects a container process that acquires CAP_SYS_ADMIN or
  CAP_SYS_PTRACE inside a Deployment or StatefulSet workload Pod
  outside the system namespaces. These capabilities are sufficient
  for a container escape via privileged syscalls and are not held by
  typical application workloads, so their presence in a tenant
  controller is a strong indicator of an in-progress escape attempt.
status: experimental
attack:
  - T1611
severity: 90
detection:
  cap_acquired:
    process.cap_effective|contains:
      - 'CAP_SYS_ADMIN'
      - 'CAP_SYS_PTRACE'
  workload_kind:
    k8s.workload.owner_kind:
      - Deployment
      - StatefulSet
  system_namespace:
    k8s.pod.namespace:
      - 'kube-system'
      - 'kube-public'
      - 'kube-node-lease'
      - 'olaitan'
  condition: cap_acquired and workload_kind and not system_namespace
falsepositives:
  - Privileged DaemonSets such as CNI or CSI plugins; excluded by the workload_kind filter
  - Security testing workloads inside dedicated namespaces; allowlist via a dedicated namespace shape
fields:
  - process.cap_effective
  - k8s.pod.namespace
  - k8s.workload.owner_kind
```

### 10.2 `OLT-CRED-001`: ServiceAccount token read by a non-system process

This rule exercises the `file.path|startswith` modifier on two parallel
selections, the `process.exe|re` regular-expression modifier, a
multi-branch `condition` combining `or` and `not`, and the
credential-access technique `T1552`.

```yaml
title: ServiceAccount token read by non-system process
id: OLT-CRED-001
description: |
  Detects a read against the projected ServiceAccount token file by a
  process whose executable does not belong to the system process
  allowlist (kubelet, kube-proxy, coredns). Workload Pods rarely read
  the token directly because the standard client libraries handle the
  mount internally; an explicit open call is a strong indicator of
  credential theft.
status: experimental
attack:
  - T1552
severity: 75
detection:
  sa_token_read_runtime:
    file.path|startswith: '/run/secrets/kubernetes.io/serviceaccount/'
  sa_token_read_legacy:
    file.path|startswith: '/var/run/secrets/kubernetes.io/serviceaccount/'
  system_process:
    process.exe|re: '^/(usr/)?(local/)?s?bin/(kubelet|kube-proxy|coredns)$'
  condition: (sa_token_read_runtime or sa_token_read_legacy) and not system_process
falsepositives:
  - In cluster sidecars that read the token to seed a custom HTTP client; pin via a process.exe allowlist in operator overlay
  - Service mesh proxies (Linkerd, Envoy) that proxy the apiserver; allowlist via a dedicated namespace shape
fields:
  - file.path
  - process.exe
  - k8s.pod.namespace
```

These three (`OLT-IMPACT-005`, `OLT-PRIV-001`, `OLT-CRED-001`) span the
`endswith`, `contains`, `startswith`, and `re` modifiers; integer and
string pattern lists; negated and multi-branch `condition` expressions;
the `k8s.*` posture references; the `attack:` list; and the `severity:`
and `falsepositives:` conventions. A fourth corpus rule,
`rules/net/OLT-NET-001.yaml`, additionally demonstrates the `cidr`
modifier (`network.dst_ip|cidr`) over a negated RFC1918 condition for
beacon-shaped outbound traffic.

## 11. Validating an OLT rule against the SIGMA-HQ reference parser

The strict-superset property (NFR30) is not aspirational: it is backed by
the parser implementation and a corpus test that runs in CI.

**The parser is a thin wrap of the SIGMA-HQ reference parser.** The OLT
parser depends on `github.com/runreveal/sigmalite` (pinned in `go.mod`,
no source fork; the upstream commit is recorded in
`internal/decision/rules/parser/NOTICE` under Apache-2.0).
`parser.ParseRule(yamlBytes)` calls `sigma.ParseRule(yamlBytes)` first
(`internal/decision/rules/parser/parser.go`), and only after the
SIGMA-HQ parse succeeds does it extract the OLT-only `attack:` and
`severity:` fields from sigmalite's `Rule.Extra` extension map. If
sigmalite rejects the YAML (a malformed `detection:`, a missing `title:`,
a bad modifier), the parse fails before any OLT check runs. Because the
OLT additions ride sigmalite's documented extension surface and never
remove or redefine a SIGMA-HQ field, an OLT rule is a SIGMA-HQ rule plus
additive annotations.

**A test parses the whole corpus through that path.**
`TestCorpusLint_AllRulesParse` (`internal/decision/rules/corpus_lint_test.go`)
walks every rule under `rules/` and runs `parser.ParseRule` (hence
`sigma.ParseRule`) over each one, asserting it parses without error.

To validate a rule you are authoring, drop it under the appropriate
`rules/<category>/` directory and run the corpus walk:

```sh
go test ./internal/decision/rules/ -run TestCorpusLint -count=1
```

This target also runs by default under `make test`, so a rule that does
not parse through the SIGMA-HQ reference parser fails the build. The
wrap-path proof-of-concept lives under `spikes/sigma-parser/` (with
`testdata/OLT-IMPACT-005.yaml` as the parser-validation fixture), and the
parser-strategy decision is recorded in
[`deferred-decisions.md`](deferred-decisions.md) ADR-2026-04-28-01.

**Scope of the claim.** The strict-superset evidence is (i) the additive
wrap-path architecture (OLT adds only `attack:` and `severity:` on the
sigmalite extension surface and never removes or redefines a SIGMA-HQ
field) and (ii) the corpus walk that parses every OLT rule through the
SIGMA-HQ reference parser. It is not a full SIGMA-HQ conformance-suite
round-trip over the entire upstream SIGMA-HQ ruleset; the claim is that
OLT rules validate as SIGMA-HQ rules, demonstrated over the OLT corpus.

## 12. Hand-off into the rule engine

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
