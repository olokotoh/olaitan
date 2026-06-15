# S5: Cryptomining (MITRE ATT&CK T1496)

**Technique.** T1496 (Resource Hijacking). A compromised workload runs a
cryptominer (xmrig/minerd/cpuminer) and connects out to a mining-pool
stratum endpoint, consuming tenant compute for the attacker's gain.

**Success criterion (AC6).** RESTRICTED <= 120 s.

**Triggering rules.**
- OLT-IMPACT-005 (severity 75, T1496): an xmrig/minerd/cpuminer-style
  process launch in a Deployment-owned tenant pod with outbound traffic to a
  mining-pool port (3333/4444/5555).
- OLT-IMPACT-006 (severity 75, T1496): an outbound TCP flow to a stratum pool
  port (3333/4444/5555/7777/14444) with WARNING severity from a tenant pod.

**Target workload.** `manifests/workload.yaml` provisions a `tenant-acme/web`
Deployment NOT labelled as a crypto workload (so the false-positive allowlist
does not suppress it).

**Deterministic stimulus (BI-3).** The harness injects two synthetic events
directly (see `attack/inject.md`): (a) a falco process event whose
`process.exe` ends `xmrig`, with `network.dst_port=3333`, matching
OLT-IMPACT-005's process_match + network_match for the tenant Deployment;
and (b) a network flow event to a stratum pool port (`network.dst_port=4444`)
with `event.severity=WARNING`, matching OLT-IMPACT-006. No randomness, no
real miner binary, no external network.

**AC8 detection signal (chosen: rule match).** The OLT-IMPACT-005 (and/or
OLT-IMPACT-006) rule match reaches `EVIDENCE.packages` within the 120 s
window. AC8 asserts this EVIDENCE-package signal, NOT the full FSM RESTRICTED
attainment (Story 5.4 + the A1 gate, BI-8).
