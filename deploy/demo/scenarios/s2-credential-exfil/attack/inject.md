# S2 attack stimulus (T1552 credential exfiltration)

## What a real attacker would do

From the tenant pod, read the projected ServiceAccount token directly with
a non-system tool (e.g. `cat /run/secrets/kubernetes.io/serviceaccount/token`
via curl), and/or reach the cloud instance-metadata service at
`169.254.169.254` to harvest node credentials for lateral movement beyond
the cluster.

## Deterministic kind stimulus (BI-3, the harness path)

The harness injects two synthetic events directly to NATS (fixed content, no
randomness, no real credential, no external network).

(a) A falco file-read event matching OLT-CRED-001 (`olaitan.events.raw.falco`):

```json
{
  "id": "scenario-s2-falco-1",
  "source": "falco",
  "category": "file",
  "severity": "WARNING",
  "pod": { "name": "<resolved tenant-acme/web pod>", "namespace": "tenant-acme" },
  "raw": {
    "file.path": "/run/secrets/kubernetes.io/serviceaccount/token",
    "process.exe": "/usr/bin/curl"
  }
}
```

(b) A network event to the metadata IP matching OLT-CRED-002
(`olaitan.events.raw.network`):

```json
{
  "id": "scenario-s2-net-1",
  "source": "network",
  "category": "flow",
  "pod": { "name": "<resolved tenant-acme/web pod>", "namespace": "tenant-acme" },
  "raw": { "dst_ip": "169.254.169.254", "network.dst_ip": "169.254.169.254" }
}
```

The canonical injector is `injectScenario(t, js, "s2", podName)` in
`tests/e2e/scenarios_smoke_test.go`; the JSON above is the field-shape
contract it emits.
