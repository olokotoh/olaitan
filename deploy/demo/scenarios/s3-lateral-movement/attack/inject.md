# S3 attack stimulus (T1613 lateral movement)

## What a real attacker would do

From the compromised tenant pod, bring a `kubectl` binary into the pod and run
it to enumerate cluster resources and pivot toward higher-value workloads.

## Real in-cluster attack (Story 11.2a)

S3 is a REAL attack, not a synthetic NATS event. The shared executor
(`internal/eval/attack/attack.go`, `runS3`) applies the target, then resolves
the live pod and brings a real, standalone kubectl into it: the target ships no
kubectl, so the runner uploads its OWN kubectl with `kubectl cp` (the transfer
streams over the API server exec channel, so nothing leaves the cluster) and
execs it in the SAME pod. The uploaded binary runs as `/tmp/kubectl`, so a
process whose exe ends `/kubectl` runs in a tenant Deployment pod and
OLT-LATERAL-001 fires (MITRE T1613; the `kubectl exec` itself is T1609).

The uploaded kubectl is checked to be a real, statically linked ELF named
kubectl (a busybox applet or a snap/mise/aqua shim is refused), and its sha256
and version are recorded so each run names exactly which client it used. A
kubectl that fails to run in-pod fails the trial (no trailing command masks its
exit code).

The workload's owner_kind=Deployment and namespace=tenant-acme (resolved from
the apiserver) satisfy the rule's `workload_kind` + `tenant_namespace` clauses.
Falco observes the real execve and its alert flows through the real bus to the
correlator, which assembles the EvidencePackage. The attack is driven by
`runRealAttack(t, tgt)` in `tests/e2e/scenarios_smoke_test.go` and by
`olaitan-eval` through the same executor. The synthetic injector
`injectScenario` refuses S1-S3.
