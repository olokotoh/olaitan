# S4: C2 beaconing (MITRE ATT&CK T1071)

**Technique.** T1071 (Application Layer Protocol), incl. T1071.001 (Web
Protocols). A compromised workload beacons to a command-and-control endpoint
with small, periodic outbound flows that intentionally avoid attention.

**Success criterion (AC5).** >= SUSPICIOUS <= 300 s.

**Triggering rules / baseline metric.**
- OLT-NET-001 (severity 50, T1071): a small (<1000-byte) outbound flow to a
  non-RFC1918 destination from a tenant pod.
- OLT-NET-002 (severity 50, T1071.001): outbound TCP to a C2-favoured port
  (8443/6697/8333) from a tenant pod.
- Baseline deviation (BI-4): the beaconing signature (many small flows to
  distinct public destinations) crosses the baseline engine's
  `outbound_unique_dst_ips` 3-sigma metric.

**Target workload.** `manifests/workload.yaml` provisions a `tenant-acme/web`
Deployment.

**Deterministic stimulus (BI-3, BI-4).** The harness (a) pre-seeds the
per-workload baseline with the rs_smoke 10-priming-plus-1-spike
EvidencePackage pattern so the `outbound_unique_dst_ips` deviation fires, and
(b) injects a synthetic small outbound flow event to
`olaitan.events.raw.network` (`event.category=flow`, `network.dst_ip` a
non-RFC1918 address, `network.bytes_out` < 1000, `network.dst_port=8443`,
`network.protocol=TCP`) so OLT-NET-001/OLT-NET-002 also match. No randomness,
no external network.

**AC8 detection signal (chosen: rule match OR baseline deviation).** Either
the OLT-NET rule match OR the `outbound_unique_dst_ips` baseline deviation
reaches `EVIDENCE.packages` within the 300 s window satisfies AC8's
disjunction (BI-4). AC8 asserts this EVIDENCE-package signal, NOT the full
FSM SUSPICIOUS-floor attainment (Story 5.4 + the A1 gate, BI-8).
