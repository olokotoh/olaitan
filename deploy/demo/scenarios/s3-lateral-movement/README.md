# S3: Lateral movement (MITRE ATT&CK T1613)

**Technique.** T1613 (Container and Resource Discovery). An attacker who has
landed in a tenant pod launches a Kubernetes API client (kubectl) to
discover and pivot to other cluster resources.

**Success criterion (AC4).** QUARANTINED <= 90 s.

**Triggering rule.** OLT-LATERAL-001 (severity 75, T1613): fires when
`process.exe` ends with `/kubectl` inside a Deployment-owned pod whose
namespace begins with `tenant-`.

**Target workload.** `manifests/workload.yaml` provisions a `tenant-acme/web`
Deployment.

**Deterministic stimulus (BI-3).** The harness injects a synthetic falco
process-exec event directly to `olaitan.events.raw.falco` (see
`attack/inject.md`) whose `process.exe` is `/usr/local/bin/kubectl` for the
Deployment-owned tenant pod, the EXACT shape OLT-LATERAL-001's `kubectl_exec`
clause matches. No randomness, no real kubectl binary, no external network.

**AC8 detection signal (chosen: rule match).** The OLT-LATERAL-001 rule match
reaches `EVIDENCE.packages` within the 90 s window. AC8 asserts this
EVIDENCE-package signal, NOT the full FSM QUARANTINED attainment (Story 5.4 +
the A1 gate, BI-8).
