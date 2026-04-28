# `wrap/` — sigmalite-based Sigma parser POC

Story 1.2 spike. Demonstrates that the OLT dialect can ride on top of
`github.com/runreveal/sigmalite` without forking the upstream parser.

## What this POC proves

- A standard SIGMA-HQ rule loaded via `sigma.ParseRule(yaml)` retains its
  full structure under sigmalite's evaluation engine.
- OLT-only top-level fields (`attack:`, `severity:`) survive the parse in
  `Rule.Extra` and decode through `Decoder.Decode(&v)` so OLT does not
  need to fork the upstream YAML schema.
- Kubernetes-native field references (`k8s.pod.namespace`,
  `k8s.workload.owner_kind`, etc.) resolve through a custom
  `sigma.FieldResolver` that splits the lookup space into a streaming-event
  half (`process.*`, `network.*`) and a workload-posture half (`k8s.*`).
- The matching path produces an `internal/schema.RuleMatch`-shaped struct
  so Story 1.15 inherits the exact return type.

## Running it

From this directory:

```
go run .
```

Expected output (success path):

```
[wrap] parsed rule id=OLT-IMPACT-005 title="Cryptominer process pattern in unprivileged Pod" attack=[T1496] severity=75
[wrap] positive               want=true got=true PASS
[wrap]   RuleMatch={"rule_id":"OLT-IMPACT-005","rule_name":"...","severity":"75","mitre_tags":["T1496"],"event_id":"positive"}
[wrap] negative_namespace     want=false got=false PASS
[wrap] negative_process       want=false got=false PASS
[wrap] fixtures: 3/3 passed
```

If any fixture prints `FAIL`, the POC exits non-zero.

## Performance rough cut (AC5)

```
go run . --bench
```

Adds a 100-iteration warm-up plus 1000 timed iterations of one fixture
against a 10-rule corpus (OLT-IMPACT-005 plus nine `id`-mutated
duplicates) and prints `total`, `min`, `median`, `p99`, `max`. The
recorded numbers feed ADR-2026-04-28-01's "Performance rough cut"
section. This is a sanity check, not the NFR3 100 ms p99 contract;
that gate is Story 1.15's.

## Failure mode if the wrap path were rejected

If the chosen library forbade arbitrary top-level fields (it would
error on `attack:` instead of stashing it in `Extra`) or refused the
custom `FieldResolver` contract, this POC's `parseOLTExtras` or
`oltResolver` would fail and the wrap path would be unviable.
sigmalite passes both contracts cleanly, which is the load-bearing
finding that pushes the ADR towards "wrap, don't fork".

## Boundary the POC respects

- Module is independent of `github.com/olokotoh/olaitan`. Spike deps do
  not enter the main `go.sum`.
- No `EvidencePackage` Go type is defined here. Story 1.14 lands that
  shape; Story 1.15 wires the matcher to it.
- No production `internal/decision/rules/*` code is touched.
