# S1 attack stimulus (T1611 container escape)

## What a real attacker would do

Inside the privileged tenant pod, exec a shell and abuse CAP_SYS_ADMIN to
mount the host filesystem (or use CAP_SYS_PTRACE to attach to a host
process), breaking out of the container boundary onto the node.

## Deterministic kind stimulus (BI-3, the harness path)

On kind, Falco's eBPF probe cannot load, so the harness injects the
synthetic falco event the production Falco adapter would emit, directly to
NATS subject `olaitan.events.raw.falco`. This is deterministic by
construction (fixed content, no randomness, no real exploit, no external
network) and is the proven rs_smoke S1 path.

The injected event (the EXACT shape OLT-PRIV-001's `cap_acquired` clause
matches):

```json
{
  "id": "scenario-s1-falco-1",
  "source": "falco",
  "category": "syscall",
  "severity": "CRITICAL",
  "pod": { "name": "<resolved tenant-acme/web pod>", "namespace": "tenant-acme" },
  "raw": {
    "process.exe": "/host/bin/sh",
    "process.cap_effective": "CAP_NET_BIND_SERVICE CAP_SYS_ADMIN CAP_SETUID"
  }
}
```

A network priming event precedes it so the correlator's multi-source
rising-edge fires and assembles the EvidencePackage onto
`olaitan.evidence.packages`.

The canonical injector is the Go helper `injectScenario(t, js, "s1", podName)`
in `tests/e2e/scenarios_smoke_test.go`; the JSON above is the field-shape
contract it emits.
