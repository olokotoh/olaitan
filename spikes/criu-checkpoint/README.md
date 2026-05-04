# Spike: CRIU forensic checkpoint feasibility

Story 1.4 deliverable. Throwaway POC code; **do not import any of this
into the main module**. The durable record of the spike's outcome is
the ADR appended to `docs/deferred-decisions.md` (search for
`ADR-2026-05-02-01`). This directory's `go.mod` is independent of
`github.com/olokotoh/olaitan` so its dependency closure cannot bleed
into the production module.

## What this spike answers

Whether the kubelet's `ContainerCheckpoint` API can be used to
implement Story 4.2's `PRESERVED+KILLED` forensic-capture path on
the project's pinned Kubernetes 1.29 / containerd 1.7 / runc 1.1
substrate, and if not, whether a documented fallback (`kubectl logs
--previous` plus a debug-pod filesystem snapshot) is sufficient for
FR36.

## Outcome (TL;DR)

**CRIU forensic checkpoint is INFEASIBLE on the project's pinned
runtime stack.** Two independent blockers were identified, either of
which is sufficient to require the documented fallback or a
substrate-version bump:

1. **Runtime blocker (project pin):** containerd 1.7 does not
   implement the `CheckpointContainer` CRI RPC. The implementation
   was wired in
   [containerd/containerd#6965](https://github.com/containerd/containerd/pull/6965),
   merged 2024-03-07 to the **2.0 milestone** and not back-ported.
   The project pins containerd 1.7 (`architecture.md:80`).
2. **Kernel/CRIU blocker (host substrate):** even on the upstream
   stack used inside this spike's kind cluster (containerd 2.0.2,
   runc 1.2.3, CRIU 3.17.1), CRIU fails to initialise on Linux
   6.17.0 with `vdso: Unexpected rt vDSO area bounds` — the kernel's
   vDSO layout is newer than CRIU 3.17.1 supports. A production
   substrate on Ubuntu 22.04 LTS (kernel 5.15 or 6.5) would not hit
   this blocker, but the project's hardware substrate decisions
   inherit a kernel-vs-CRIU compatibility risk.

Story 4.2 therefore ships
`internal/response/forensics/kubectl_fallback.go` (the documented
fallback path) **unless** the project owner approves both a
containerd bump to 2.0+ and a documented kernel pin compatible with
the deployed CRIU version. See the ADR for the full hand-off.

## Reproduction

Prereqs on the host:

- Docker (verified with v29.4.1)
- kind v0.27.0 or newer (which bundles containerd 2.x in the node
  image)
- kubectl (any 1.29-skew-compatible client)
- jq (used by `make cluster` to print the kubelet feature-gate map
  from the configz response, matching the verification recipe in
  the Story 1.4 spec Task 2.2)
- Go 1.22+

```bash
make spike     # cluster up + CRIU install + workload + harness
make verify    # go vet + go test on the harness (no cluster needed)
make clean     # tear down the kind cluster
```

`make spike` performs:

1. `kind create cluster --config kind-config.yaml` (pinned to
   `kindest/node:v1.29.14`, control-plane only, ~24 s on this host).
2. `apt-get install -y criu` inside the kind node (Debian bookworm
   ships CRIU 3.17.1; the project's production target Ubuntu 22.04
   ships CRIU 3.16.1 in jammy/universe).
3. `criu check --all` to surface kernel-feature gaps.
4. `kubectl apply -f workload.yaml` to deploy a busybox sleep loop
   that writes a `secret-marker=should-not-be-cleartext` line every
   second (this is a privacy-scan input fixture; the marker is *not*
   a real secret, just a string that should appear in any honest
   memory-page dump).
5. `go run .` to exercise the kubelet checkpoint API three times,
   timing each call.

## Expected output (host: kernel 6.17.0, kind v0.27.0)

```
Target: http://localhost:18001/api/v1/nodes/olaitan-criu-spike-control-plane/proxy/checkpoint/criu-spike/busybox-target/busybox

Run 1: FAIL http=500 wall=140.45254ms body="checkpointing of criu-spike/busybox-target/busybox failed (rpc error: code = Unknown desc = checkpointing container \"...\" failed: runc did not terminate successfully: exit status …"
Run 2: FAIL http=500 wall=121.914382ms body="…"
Run 3: FAIL http=500 wall=136.888881ms body="…"

Summary: 0/3 successful checkpoints over 3 runs.
Outcome: FAIL — no successful checkpoint. See ADR-2026-05-02-01 for the documented fallback path.
```

The full CRIU dump log (visible via `docker exec
olaitan-criu-spike-control-plane cat
/run/containerd/io.containerd.runtime.v2.task/k8s.io/<container-id>/criu-dump.log`)
ends with:

```
(00.041209) Error (criu/vdso.c:381): vdso: Unexpected rt vDSO area bounds
(00.041214) Error (criu/vdso.c:613): vdso: Failed to fill self vdso symtable
(00.041217) Error (criu/kerndat.c:1615): kerndat_vdso_fill_symtable failed when initializing kerndat.
```

## Versions exercised

| Component | Version | Source |
|---|---|---|
| Host kernel | 6.17.0-22-generic | `uname -r` on dev host |
| Host OS | Ubuntu (host) — kind nodes are Debian bookworm | `cat /etc/os-release` inside kind node |
| kind | v0.27.0 | `kind --version` |
| Kubernetes | v1.29.14 (matches `architecture.md:79` pin) | `kubectl version` |
| containerd | v2.0.2 (kind v0.27.0 bundles 2.x — **NOT** the project's pinned 1.7) | `containerd --version` inside kind node |
| runc | v1.2.3 (newer than the project's pinned 1.1) | `runc --version` inside kind node |
| CRIU | 3.17.1-2+deb12u2 (Debian bookworm; production Ubuntu 22.04 jammy ships 3.16.1-2) | `criu --version` inside kind node |
| Go | 1.26.2 | `go version` on dev host |

## Wall-clock timing data (AC5)

Three timed checkpoint calls against `criu-spike/busybox-target/busybox`
on this host:

| Run | HTTP | Wall-clock | Outcome |
|---|---|---|---|
| 1 | 500 | 140.5 ms | FAIL at CRIU vDSO init |
| 2 | 500 | 121.9 ms | FAIL at CRIU vDSO init |
| 3 | 500 | 136.9 ms | FAIL at CRIU vDSO init |

`time.Now()`-bracketed in the Go harness. The 121-140 ms range is
the round-trip including kubelet → CRI → containerd → runc → CRIU
init failure → propagation back. **No checkpoint archive is written
on this host**, so the AC5 < 5 s budget cannot be measured here;
Story 4.2 must measure on a substrate where CRIU initialises
successfully.

## Privacy / AC4 status

AC4's checkpoint-content inspection is conditional on AC3 succeeding.
Since no archive was produced on this host, the spike could not
empirically extract memory pages and grep them. The privacy concern
is nevertheless **carried forward** to the ADR's hand-off:

- A successful CRIU checkpoint embeds full process memory pages,
  open-FD state, and network-socket state, which would include
  cleartext environment variables (e.g. the `APP_TOKEN` env var
  this spike's busybox pod carries by design), in-memory secrets,
  and unredacted log buffers.
- NFR15 (sensitive-data redaction before persistence) and NFR17
  (KMS encryption on S3) therefore both apply to checkpoint
  archives. Story 4.2's S3 writer must KMS-encrypt and tag every
  forensic checkpoint as a secret-tier artefact; the redaction
  pipeline that Story 3.1 builds operates on text and **must not**
  be applied to binary memory pages.

## What this spike deliberately does NOT do

- Does **not** modify any file under `internal/response/forensics/`.
  That directory remains an empty scaffold (architecture.md:800-802)
  until Story 4.2.
- Does **not** bump the Kubernetes version pin in `architecture.md`,
  the Helm chart, the bootstrap script, or the eval manifest.
- Does **not** add an S3 upload glue. Story 4.2 owns the persistence
  side.
- Does **not** install CRIU on production nodes. Story 4.2 (or a
  dedicated platform-substrate story) owns the kubeadm bootstrap
  changes.
- Does **not** carry a `Co-Authored-By:` trailer on any commit.

## References

- Story spec:
  `_bmad-output/implementation-artifacts/1-4-spike-criu-forensic-checkpoint-feasibility.md`
  (in the FYP planning repo).
- Architecture: `architecture.md:79-80`, `:117`, `:205`, `:217`,
  `:800-802`, `:954`.
- KEP-2008 (Forensic Container Checkpointing).
- containerd CRI checkpoint RPC: `containerd/containerd#6965`.
- Kubelet Checkpoint API:
  https://kubernetes.io/docs/reference/node/kubelet-checkpoint-api/
