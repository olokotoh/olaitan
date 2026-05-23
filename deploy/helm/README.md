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
