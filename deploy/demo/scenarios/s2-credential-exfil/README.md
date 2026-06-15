# S2: Credential exfiltration (MITRE ATT&CK T1552)

**Technique.** T1552 (Unsecured Credentials), incl. T1552.005 (Cloud
Instance Metadata API). A workload reads its projected ServiceAccount token
directly and/or reaches the cloud instance-metadata endpoint to steal
credentials that grant lateral movement beyond the cluster boundary.

**Success criterion (AC3).** >= RESTRICTED <= 60 s.

**Triggering rules.**
- OLT-CRED-001 (severity 75, T1552): a read against
  `/run/secrets/kubernetes.io/serviceaccount/` (or the legacy
  `/var/run/secrets/...` path) by a process NOT in the
  kubelet/kube-proxy/coredns allowlist.
- OLT-CRED-002 (severity 50, T1552.005): an outbound connection to the
  instance-metadata IP `169.254.169.254` from a non-system-namespace pod.

**Target workload.** `manifests/workload.yaml` provisions a `tenant-acme/web`
Deployment with a projected ServiceAccount token mount.

**Deterministic stimulus (BI-3).** The harness injects two synthetic events
directly to `olaitan.events.raw.falco` and `olaitan.events.raw.network` (see
`attack/inject.md`): (a) a falco file-read event whose `file.path` starts
with `/run/secrets/kubernetes.io/serviceaccount/` by a non-allowlisted
process (`/usr/bin/curl`), matching OLT-CRED-001; and (b) a network event
whose `network.dst_ip` is `169.254.169.254` from the tenant pod, matching
OLT-CRED-002. No randomness, no real credential, no external network.

**AC8 detection signal (chosen: rule match).** The OLT-CRED-001 (and/or
OLT-CRED-002) rule match reaches `EVIDENCE.packages` within the 60 s window.
AC8 asserts this EVIDENCE-package signal, NOT the full FSM RESTRICTED-floor
attainment (Story 5.4 + the A1 gate, BI-8).
