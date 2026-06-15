# S3 attack stimulus (T1613 lateral movement)

## What a real attacker would do

From the compromised tenant pod, run a smuggled `kubectl` binary to
enumerate cluster resources (`kubectl get pods --all-namespaces`) and pivot
toward higher-value workloads.

## Deterministic kind stimulus (BI-3, the harness path)

The harness injects one synthetic falco process-exec event directly to
`olaitan.events.raw.network` (priming) + `olaitan.events.raw.falco` (the
match), fixed content, no randomness, no real kubectl, no external network.

The falco event matching OLT-LATERAL-001's `kubectl_exec` clause:

```json
{
  "id": "scenario-s3-falco-1",
  "source": "falco",
  "category": "process",
  "severity": "WARNING",
  "pod": { "name": "<resolved tenant-acme/web pod>", "namespace": "tenant-acme" },
  "raw": { "process.exe": "/usr/local/bin/kubectl" }
}
```

The workload's owner_kind=Deployment and namespace=tenant-acme (resolved
from the apiserver) satisfy the rule's `workload_kind` + `tenant_namespace`
clauses.

The canonical injector is `injectScenario(t, js, "s3", podName)` in
`tests/e2e/scenarios_smoke_test.go`.
