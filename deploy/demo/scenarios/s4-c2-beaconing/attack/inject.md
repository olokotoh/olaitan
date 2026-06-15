# S4 attack stimulus (T1071 C2 beaconing)

## What a real attacker would do

The compromised tenant pod beacons to a C2 endpoint with small, periodic
outbound flows to many distinct public destinations (the unique-destination
fan-out a baseline learns to flag), often on a port that resembles
legitimate web traffic (8443) to evade gateway controls.

## Deterministic kind stimulus (BI-3, BI-4, the harness path)

The harness drives BOTH halves of AC8's rule-OR-deviation disjunction (fixed
content, no randomness, no external network):

1. Baseline pre-seed: publish the rs_smoke 10-priming-plus-1-spike
   EvidencePackage pattern to `olaitan.evidence.packages` so the baseline
   engine's `outbound_unique_dst_ips` metric crosses 3 sigma (the deviation
   half).

2. A small outbound flow event to `olaitan.events.raw.network` matching
   OLT-NET-001 (non-RFC1918 dst, payload < 1000 bytes) and OLT-NET-002
   (C2-favoured TCP port 8443):

```json
{
  "id": "scenario-s4-net-1",
  "source": "network",
  "category": "flow",
  "pod": { "name": "<resolved tenant-acme/web pod>", "namespace": "tenant-acme" },
  "raw": {
    "dst_ip": "203.0.113.10",
    "network.dst_ip": "203.0.113.10",
    "network.bytes_out": "512",
    "network.dst_port": 8443,
    "network.protocol": "TCP"
  }
}
```

`203.0.113.0/24` is the RFC5737 TEST-NET-3 documentation range (NOT RFC1918),
so OLT-NET-001's `not (rfc1918_a or rfc1918_b or rfc1918_c)` clause holds.

The canonical injector is `injectScenario(t, js, "s4", podName)` in
`tests/e2e/scenarios_smoke_test.go`.
