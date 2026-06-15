# S5 attack stimulus (T1496 cryptomining)

## What a real attacker would do

The compromised tenant pod launches a cryptominer (xmrig) and opens a long
-lived TCP connection to a mining-pool stratum endpoint (port 3333/4444),
burning tenant CPU for the attacker.

## Deterministic kind stimulus (BI-3, the harness path)

The harness injects two synthetic events directly (fixed content, no
randomness, no real miner, no external network).

(a) A falco process event matching OLT-IMPACT-005 (process_match +
network_match in one event, `olaitan.events.raw.falco`):

```json
{
  "id": "scenario-s5-falco-1",
  "source": "falco",
  "category": "process",
  "severity": "WARNING",
  "pod": { "name": "<resolved tenant-acme/web pod>", "namespace": "tenant-acme" },
  "raw": { "process.exe": "/tmp/xmrig", "network.dst_port": 3333 }
}
```

(b) A network flow event matching OLT-IMPACT-006 (stratum pool port +
WARNING severity, `olaitan.events.raw.network`):

```json
{
  "id": "scenario-s5-net-1",
  "source": "network",
  "category": "flow",
  "severity": "WARNING",
  "pod": { "name": "<resolved tenant-acme/web pod>", "namespace": "tenant-acme" },
  "raw": { "network.dst_port": 4444 }
}
```

The workload's owner_kind=Deployment and namespace=tenant-acme satisfy the
rules' `k8s_context` / `tenant_namespace` clauses.

The canonical injector is `injectScenario(t, js, "s5", podName)` in
`tests/e2e/scenarios_smoke_test.go`.
