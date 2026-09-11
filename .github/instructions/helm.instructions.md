---
applyTo: "deploy/helm/**"
---

# Helm chart review rules for Olaitan

These extend `.github/copilot-instructions.md` with Helm-specific rules. Flag any violation.

## Pod security baseline (NFR11)

- Read-only root filesystem (`readOnlyRootFilesystem: true`).
- Non-root execution as distroless UID/GID 65532 (`runAsNonRoot: true`, `runAsUser: 65532`, `runAsGroup: 65532`, `fsGroup: 65532`).
- Drop all Linux capabilities (`capabilities: { drop: [ALL] }`).
- No privilege escalation (`allowPrivilegeEscalation: false`).
- Default seccomp profile (`seccompProfile: { type: RuntimeDefault }`).
- `hostNetwork: false`, `hostPID: false`.

Flag any DaemonSet, Deployment, or workload manifest that loosens these baselines without an explicit code-comment justification.

## Volume mounts

- Mounts default to `readOnly: true`. A read-write mount needs explicit justification in a code comment.
- The only writable mount is the `/tmp` `emptyDir` required by the Go runtime for crash-trace artefacts.
- `hostPath` mounts are a strong red flag. The containerd socket directory (read-only, gated on `containerdSensor.enabled`) is the only legitimate hostPath mount in Olaitan's own templates. The default render mounts nothing from the host; the bundled Falco subchart's mounts are Falco's own.
- ConfigMap mounts use whole-directory mounts (`mountPath: /etc/olaitan/...`); do NOT introduce `subPath` because it breaks the chart's atomic-swap contract for hot-reload of rules.

## Falco ingest

- Falco reaches the collector over `http_output` (Falco 0.44 removed gRPC). Its URL is `${OLAITAN_FALCO_URL}${OLAITAN_FALCO_TOKEN}`, both from `falco.extra.env`, which the Falco chart renders through `tpl` in the release context. `olaitan.falcoIngest.validate` fails the render on anything the subchart cannot see (nameOverride/fullnameOverride, a port change, json_output or http_output off). Flag any change that bypasses that guard.
- The `falco-ingest` Service MUST keep `internalTrafficPolicy: Local`, so a node's alerts reach that node's collector and carry the right node name.
- The token must never be rendered into a ConfigMap: Falco expands `${OLAITAN_FALCO_TOKEN}` itself. Covered by tests in `deploy/helm/helm_test.go`.

## Secrets

- API-key material lives in a Secret mounted at `/etc/olaitan/secrets` with `defaultMode: 0400` (owner read-only). Flag any change that loosens the mode or moves credentials into a ConfigMap.
- `secrets.redisPassword` is required for chart rendering. The CI helm test sets it explicitly; a chart change that introduces a new required secret without updating the test is a regression.

## Downward API

- The collector subcommand's `K8S_NODE_NAME` env var must be sourced from `spec.nodeName` via the downward API, NOT from `os.Hostname()` (which returns the pod name on Kubernetes). The render is asserted by `TestCollectorDaemonsetHasK8sNodeNameDownwardAPI`.

## Helm tests

- Helm rendering tests live in `deploy/helm/helm_test.go` under build tag `helm`. Run via `go test -tags=helm ./deploy/helm/...`.
- Tests use `helm template` against the chart on disk plus `--set` overrides. Assertions are tight string-matches against the rendered manifest at exact indentation; this is intentional so a chart refactor that re-indents trips the test rather than passing on a near-miss.
- Every new chart-level invariant the code depends on (env var, mount, security setting) needs a corresponding helm test. A chart change that breaks an invariant should fail a helm test, not surface as a runtime crash on a real cluster.

## Versioning

- `Chart.yaml` `kubeVersion` is pinned to the minimum the chart depends on (e.g. `>=1.19` for `spec.nodeName` downward API). Flag chart changes that introduce a feature requiring a newer Kubernetes version without bumping `kubeVersion`.
