# S1: Container escape (MITRE ATT&CK T1611)

**Technique.** T1611 (Escape to Host). A workload container acquires a
privileged capability (CAP_SYS_ADMIN or CAP_SYS_PTRACE) sufficient to break
out of the container boundary onto the host via privileged syscalls.

**Success criterion (AC2).** QUARANTINED <= 30 s after attack initiation.

**Triggering rule.** OLT-PRIV-001 (severity 90, T1611): fires when
`process.cap_effective` contains `CAP_SYS_ADMIN` or `CAP_SYS_PTRACE` for a
Deployment/StatefulSet-owned pod outside the system namespaces.

**Target workload.** `manifests/workload.yaml` provisions a privileged
`tenant-acme/web` Deployment (the privileged securityContext is the real
escape surface a future Falco-on-real-kernel run would exercise).

**Deterministic stimulus (BI-3, BI-5).** On kind, Falco's eBPF probe cannot
load, so the harness injects the synthetic falco event directly to
`olaitan.events.raw.falco` (see `attack/inject.md`). The injected event
carries `process.cap_effective` containing `CAP_SYS_ADMIN` for the
Deployment-owned pod, the EXACT field shape OLT-PRIV-001's `cap_acquired`
clause matches. This is the proven rs_smoke S1 path (a known-passing
baseline). No randomness, no real exploit binary, no external network.

**AC8 detection signal.** The OLT-PRIV-001 rule match reaches
`EVIDENCE.packages` (`olaitan_decision_rules_matches_by_attribute_total{rule_id="OLT-PRIV-001"}`
>= 1 AND `olaitan_correlator_evidence_packages_total` >= 1) within the 30 s
window. AC8 asserts this EVIDENCE-package signal, NOT the full FSM-state
attainment of QUARANTINED (Story 5.4 + the carry-forward A1 RSLT-full-kind
gate own the full chain, BI-8).
