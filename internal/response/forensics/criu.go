package forensics

// criu.go is the DORMANT, REJECTED Path-B alternative (BI-1/BI-2,
// ADR-2026-05-02-01). It is NOT wired into the controller, NOT registered as an
// fsm.MultiSink member, and NOT reachable from any live code path. It exists
// only as a documented placeholder recording why CRIU forensic checkpoint is
// out of scope at HEAD, so a future reader does not mistake the fallback for a
// design omission.
//
// CRIU is infeasible on the pinned substrate for two independent reasons, each
// sufficient on its own (docs/deferred-decisions.md, spikes/criu-checkpoint):
//
//  1. Runtime blocker: containerd 1.7 (the pinned runtime, architecture.md:80)
//     does not implement the CheckpointContainer CRI RPC; it landed only on the
//     containerd 2.0 milestone and was not back-ported.
//  2. Kernel/CRIU blocker: CRIU fails to initialise with
//     "vdso: Unexpected rt vDSO area bounds" on the kernel substrate.
//
// Enabling Path B requires explicit project-owner approval of substrate bumps
// (containerd 2.0+, runc 1.2+, a CRIU package on every node, and the
// ContainerCheckpoint feature gate). No such approval exists at HEAD, so this
// file deliberately contains no live implementation. When the substrate is
// approved, Story 4.2's hand-off in docs/deferred-decisions.md describes the
// kubelet POST /checkpoint capture path to implement here behind the same
// Uploader interface the fallback uses.
//
// Lint note: this file has no exported symbols on purpose; it documents the
// rejected alternative without adding dead callable code.
