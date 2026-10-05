# S2 attack stimulus (T1552 credential exfiltration)

## What a real attacker would do

From the tenant pod, read the projected ServiceAccount token, use it against
the kube-API, and reach the cloud instance-metadata service at
`169.254.169.254` to harvest node credentials for lateral movement beyond the
cluster.

## Real in-cluster attack (Story 11.2a)

S2 is a REAL attack, not a synthetic NATS event. The shared executor
(`internal/eval/attack/attack.go`, `runS2`) applies the least-privilege
`s2-attacker` RBAC and the target, then `kubectl exec`s into the live pod and:

1. Reads the SA token, emitting ONLY its byte length and sha256 (the token
   value never enters argv, stdout, or a log line; the read is validated to be
   a real projected token). MITRE T1552 (OLT-CRED-001).
2. Uses the token against the kube-API (`/api/v1/.../secrets`), printing only
   the HTTP status. The Authorization header is piped to curl on STDIN
   (`printf ... | curl -H @-`, printf is a shell builtin), so the token is in
   NO process argv and never reaches Falco's `%proc.cmdline`. MITRE T1552.007.
3. Requests the instance-metadata IP. MITRE T1552.005 (OLT-CRED-002).

A `kubectl exec` that itself fails (pod swept, curl missing in the image) fails
the trial, so a run is never recorded as executed with steps that did not run.
An HTTP-level refusal (401/403) is a real attempt and is recorded as such.

Falco observes the real syscalls / connection and its alerts flow through the
real bus to the correlator, which assembles the EvidencePackage. The attack is
driven by `runRealAttack(t, tgt)` in `tests/e2e/scenarios_smoke_test.go` and by
`olaitan-eval` through the same executor. The synthetic injector
`injectScenario` refuses S1-S3.
