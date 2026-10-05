# S1 attack stimulus (T1611 container escape)

## What a real attacker would do

Inside the privileged tenant pod, exec a shell and abuse CAP_SYS_ADMIN /
CAP_SYS_PTRACE to reach the node's namespaces and filesystem, breaking out of
the container boundary onto the host.

## Real in-cluster attack (Story 11.2a)

S1 is a REAL attack, not a synthetic NATS event. The shared executor
(`internal/eval/attack/attack.go`, `runS1`) applies the Story 11.1 privileged
target, then `kubectl exec`s into the live pod and runs the escape primitive:
it enters the host namespaces with `nsenter --target 1` and reads host-view
paths (`/proc/1/root`, `/proc/1/cgroup`). Nothing on the host is modified
(read-only recon), so deleting the pod reverses it. A missing `nsenter` in the
image is a hard failure (so a toolless image is not mistaken for a detection
miss); the escape attempt's exit code is recorded.

The privileged process alone trips OLT-PRIV-001 (its `cap_effective` carries
CAP_SYS_ADMIN / CAP_SYS_PTRACE for a Deployment pod outside the system
namespaces); the host-reach attempt is the T1611 flavour. Falco observes the
real syscalls and its alert flows through the real bus (Falco -> gRPC -> NATS
-> correlator), which assembles the EvidencePackage on
`olaitan.evidence.packages`.

The attack is driven by `runRealAttack(t, tgt)` in
`tests/e2e/scenarios_smoke_test.go` and by `olaitan-eval` through the same
executor, so CI exercises exactly the primitive the evaluation runs. The
synthetic injector `injectScenario` refuses S1-S3.
