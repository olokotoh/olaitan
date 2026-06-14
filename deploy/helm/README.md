# Olaitan Helm Chart

Installs the Olaitan collector DaemonSet + aggregator Deployment, plus
its infrastructure dependencies (Falco, NATS JetStream, Redis) as
conditional subcharts, into a Kubernetes 1.29+ cluster.

## Prerequisites

- Kubernetes **1.29+** (`kubectl version` must report both client and server).
- **Helm 3.16+** — [install guide](https://helm.sh/docs/intro/install/).
- **CNI installed** — the demo path uses Calico v3.29.0 on a pod network
  CIDR of `192.168.0.0/16`. Any CNI that supports `NetworkPolicy`
  (networking.k8s.io/v1) is acceptable.
- **(Optional)** [`kubeconform`](https://github.com/yannh/kubeconform) —
  required only if you want to re-run the schema validation locally:
  `go install github.com/yannh/kubeconform/cmd/kubeconform@v0.6.7`.

A one-shot bootstrap helper lives at `deploy/demo/setup.sh` — it checks
your tooling, prints the kubeadm + Calico commands, and (with `--apply`)
runs the Helm repo + subchart fetch steps.

```bash
# Dry-run: print preflight only.
./deploy/demo/setup.sh

# Apply helm repo + dependency-update steps.
./deploy/demo/setup.sh --apply
```

## Quick Install

From the repo root:

```bash
# 1. Copy config/olaitan.yaml into the chart's files/ directory.
#    Required because Helm's .Files.Get is chart-relative.
make helm-prepare

# 2. Fetch Falco, NATS, and Redis subchart tarballs.
helm dependency update ./deploy/helm/olaitan

# 3. Install.
helm install olaitan ./deploy/helm/olaitan
```

The Olaitan pods will reach `Running` after the health server binds
(`/healthz` on port 8080). The rings themselves log
`"<ring>: not yet implemented, awaiting ring wiring"` until Epic 2
collectors and Epic 3+ rings land — that is expected for a 1.7 install.

## Configuration

The operator-facing knobs live in `deploy/helm/olaitan/values.yaml` —
every key has an inline comment describing its purpose and default
rationale. The most common overrides:

| Use case | Example override |
| --- | --- |
| Pin image tag | `--set image.tag=sha-abc1234` |
| Use existing Redis | `--set redis.enabled=false --set endpoints.redis=my-redis.svc:6379` |
| Use existing NATS | `--set nats.enabled=false --set endpoints.nats=nats://my-nats.svc:4222` |
| Use existing Falco | `--set falco.enabled=false --set endpoints.falco=unix:///run/falco/falco.sock` |
| Larger report volume | `--set reports.size=10Gi` |
| External reports PVC | `--set reports.externalPvc=true` (claim name: `<fullname>-reports` — for the canonical `helm install olaitan ...` this collapses to `olaitan-reports`; for any other release name, the prefix is `<release>-olaitan-`) |
| Operator-managed secrets | `--set-file secrets.llmApiKey=./path/to/key.txt` |
| Allow control-plane scheduling | `--set collector.runOnControlPlane=true` |

`helm show values ./deploy/helm/olaitan` dumps the full tree for reference.

## RBAC

The chart never requires `cluster-admin`. It grants:

- **Collector** (Role/RoleBinding, release namespace): `get,list,watch`
  on `pods,events`.
- **Aggregator** (ClusterRole/ClusterRoleBinding, cluster-wide):
  `create,update,delete` on `networkpolicies.networking.k8s.io`;
  `patch` on `pods`; `get,list` on `pods,events`.

No wildcard verbs, no wildcard resources. The cluster-wide scope on the
aggregator is load-bearing: NetworkPolicy responses must be written into
every workload namespace, which a Role would prevent.

## Local validation

```bash
# Render + kubeconform schema check (kubeconform must be on PATH).
make helm-prepare
helm template ./deploy/helm/olaitan --generate-name \
  | kubeconform -strict -summary -kubernetes-version 1.29.0 -schema-location default

# Full helm-tagged Go test suite (covers three value permutations).
go test ./deploy/helm/... -tags=helm -v
```

CI runs the same gates in `.github/workflows/ci.yml` under the `helm` job.

### Golden-file diff (Story 1.19)

The `helm` test suite includes three byte-stable golden snapshots at
`deploy/helm/testdata/golden/` (`default`, `rs`, `f`) covering the
canonical Epic 5 evaluation arms. A chart edit that materially changes
rendered output trips the golden diff in CI; regenerate intentionally
with:

```bash
HELM_GOLDEN_UPDATE=1 go test -tags=helm -run TestGoldenFile \
  ./deploy/helm/... -count=1
git diff deploy/helm/testdata/golden/   # review the diff before commit
```

The `Source:` helm metadata comments and `helm.sh/chart` /
`app.kubernetes.io/version` labels are normalised out of the diff so
chart-version bumps do not force a churn. See
`deploy/helm/helm_test.go:normaliseGolden` for the redaction list.

## Forensic mode (Epic 4)

Epic 4 adds DFIR forensic reporting: forensic capture on a kill, a
settling window before a post-mortem, a DFIR report agent, a durable
content-addressed + KMS-encrypted report write to an S3-compatible
store, an optional incident webhook, and the supporting RBAC + Secret
slots. Every controller is ADDITIVE and OFF by default, so a default
`helm upgrade` from an Epic 3 deployment changes nothing until an
operator opts in (see "Upgrade safety" below).

### The `forensics.*` / `notifications.*` values facade

The seven knobs an operator touches most live in a consolidated facade
that overlays the underlying `response.*` config (the facade WINS when
both a facade key and its `response.*` counterpart are set). The
`response.*` blocks remain the advanced escape hatch (distinct
bundle/report buckets, the deferred-queue knobs, `object_lock_mode`).

| Facade knob | Bridges to | Notes |
| --- | --- | --- |
| `forensics.path` | (none) | `fallback` only; `criu` is rejected at template time (Story 1.4 / ADR-2026-05-02-01). |
| `forensics.s3.bucket` | `response.forensics.s3_bucket` AND `response.report_archive.s3_bucket` | fans out to BOTH buckets (the common single-bucket case). |
| `forensics.s3.kms_key_alias` | `response.forensics.kms_key_alias` AND `response.report_archive.kms_key_alias` | fans out to BOTH. |
| `forensics.s3.retention_days` | `response.report_archive.retention_days` | report (object-lock) bucket ONLY; the bundle bucket has no retention. |
| `forensics.settling_window_seconds` | `response.settling.window_seconds` | the FR42/NFR7 settling window. |
| `notifications.enabled` | `response.notifications.enabled` | the one facade-level gate (a no-op without a `webhook_url`). |
| `notifications.webhook_url` | `secrets.notificationsWebhookUrl` -> `NOTIFICATIONS_WEBHOOK_URL` | a SECRET projected as an env var (a Slack/PagerDuty URL embeds a token), NEVER the ConfigMap. |

`forensics.path` is forward-compat only. Story 1.4 rejected CRIU
(containerd 1.7 lacks the `CheckpointContainer` CRI RPC, plus the kernel
vDSO blocker, per ADR-2026-05-02-01) and Story 4.2 shipped only the
documented kubectl-logs fallback. The chart `{{ fail }}`s a
`forensics.path=criu` selection at template time with a "not implemented;
use fallback" message rather than silently running the fallback under a
`criu` label.

### Enable recipe

The facade sets PARAMETERS only; it does NOT enable any capture
controller (collapsing the four gates into one would risk enabling a
write with no settling). Flip the four `response.*` gates AND set the
facade params:

```bash
helm upgrade olaitan deploy/helm/olaitan \
  --set response.forensics.enabled=true \
  --set response.settling.enabled=true \
  --set response.dfir.enabled=true \
  --set response.reportArchive.enabled=true \
  --set forensics.s3.bucket=olaitan-reports \
  --set forensics.s3.kms_key_alias=alias/olaitan \
  --set forensics.s3.retention_days=90 \
  --set forensics.settling_window_seconds=60 \
  --set notifications.enabled=true \
  --set-file secrets.notificationsWebhookUrl=./webhook-url.txt \
  --set-file secrets.s3AccessKey=./s3-access.txt \
  --set-file secrets.s3SecretKey=./s3-secret.txt
```

The report bucket MUST be object-lock-enabled + versioned (an operator
precondition the writer never creates). `notifications.enabled` is a
no-op without a `webhook_url` (an enabled webhook with no URL stages the
gate ahead of the secret rather than failing fast).

### Upgrade safety (Epic 3 -> Epic 4)

A `helm upgrade olaitan deploy/helm/olaitan/` from an Epic 3 RSLT-full
deployment installs the Epic 4 surface without disrupting in-flight
investigations:

- Every Epic-4 controller gate
  (`response.{forensics,settling,dfir,reportArchive,notifications}.enabled`)
  defaults `false`, so the default upgrade renders an exact superset of
  the Epic-3 manifests (no behaviour change unless an operator opts in).
- There is NO FSM-persistence-key rename (`fsm:{workload_id}`, Redis, no
  TTL, restart-recovered) and NO JetStream stream rename; the new
  INCIDENTS / REPORTS streams are new append-only streams.
- The settling-window timers re-arm from the rehydrated FSM on a pod
  restart (FR37/NFR24), so a rolling pod replacement during the upgrade
  does NOT silently de-escalate a QUARANTINED workload or drop an
  in-flight settling window.

The aggregator stays `replicas: 1` + `strategy: Recreate` (Ring-2
checkpoint correctness), the same singleton invariant Epic 3 carried.

## Uninstall

```bash
helm uninstall olaitan
```

The PersistentVolumeClaim is retained by default (contains DFIR
evidence reports). Delete manually when you are sure the reports are
archived:

```bash
# For the canonical `helm install olaitan ...` install, claim name
# is `olaitan-reports` (the chart fullname helper collapses
# `olaitan-olaitan` to just `olaitan`). For any other release name,
# substitute `<release>-olaitan-reports`.
kubectl delete pvc olaitan-reports
```

## Scope — what this chart does NOT do

- **CRDs** — `OlaitanStatus` (Target tier, Story 10.5) is not scaffolded here.
- **Audit webhook** — Story 2.3's concern.
- **TLS material** — this chart creates the Secret *key slots* for
  `redis-password`, `nats-creds`, and `llm-api-key`, but does not
  generate TLS certificates. Provision via external-secrets-operator or
  a SOPS-encrypted values overlay.
- **Live-cluster integration tests** — Story 7.1 owns the full-stack
  cluster smoke test; this chart gates on template + schema validation.
