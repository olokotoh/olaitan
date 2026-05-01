# spikes/calico-flow

Story 1.3 spike. Subscribes to one Calico flow record from the
Goldmane gRPC API on a `kind` cluster running Calico OSS v3.31.5,
translates it into the canonical `internal/schema.Event` shape, and
records the per-record translation overhead. Throwaway code; the
production adapter lands in `internal/collector/cni/` under Story
1.10. The durable record lives in `docs/deferred-decisions.md` as
ADR-2026-04-30-01.

## Prerequisites

- `docker` 28+ (or compatible container runtime kind recognises)
- `kind` v0.27+
- `kubectl` matching the kind node image (v1.30.0 default)
- `go` 1.25+
- `buf` 1.55+ (only if regenerating the proto stubs)

## Layout

| File | Purpose |
|---|---|
| `proto/api.proto` | Vendored copy of Goldmane's flow API proto. |
| `proto/api.pb.go` | Generated protobuf types. |
| `proto/api_grpc.pb.go` | Generated gRPC service stubs. |
| `main.go` | Subscriber + translator + bench harness. |
| `translate.go` | `FlowResult` to `schema.Event` translation. |
| `main_test.go` | Fixture-driven contract test (`TestTranslateContract`). |
| `kind-config.yaml` | kind cluster definition with `disableDefaultCNI` so Calico can install. |
| `traffic.yaml` | Two pods plus a Service to drive flow generation. |
| `Makefile` | `make spike` orchestrates the full bring-up. |
| `cleanup.sh` | Idempotent kind teardown. |
| `testdata/sample-flow.binpb` | Real `FlowResult` captured during the live POC. |
| `testdata/expected.json` | Translator output for the fixture (timestamp normalised). |

## Pinned versions

| Component | Version |
|---|---|
| Calico release | `v3.31.5` (released 2026-04-15) |
| Goldmane proto SHA | `2e4da40144aac869e1ed2cc220b6c4b62f32efdd` (the `v3.31.5` tag commit) |
| kind | `v0.27.0` |
| kind node image | `kindest/node:v1.30.0` |
| Go | `1.26.2` |
| `google.golang.org/grpc` | `v1.80.0` |
| `google.golang.org/protobuf` | `v1.36.11` |

## Bring-up sequence

The full path the spike was driven through, end-to-end:

```bash
# 1. Cluster
kind create cluster --name olaitan-flow-spike --image kindest/node:v1.30.0 \
  --config kind-config.yaml

# 2. Calico operator
kubectl --context kind-olaitan-flow-spike create -f \
  https://raw.githubusercontent.com/projectcalico/calico/v3.31.5/manifests/tigera-operator.yaml
kubectl --context kind-olaitan-flow-spike rollout status -n tigera-operator \
  deployment/tigera-operator --timeout=180s

# 3. Installation + APIServer + Goldmane + Whisker CRs (default custom-resources.yaml)
kubectl --context kind-olaitan-flow-spike create -f \
  https://raw.githubusercontent.com/projectcalico/calico/v3.31.5/manifests/custom-resources.yaml

# 4. Wait for goldmane Deployment to be Ready (≈ 3 minutes total)
kubectl --context kind-olaitan-flow-spike -n calico-system rollout status \
  deployment/goldmane --timeout=300s

# 5. Generate traffic (two pods plus a Service)
kubectl --context kind-olaitan-flow-spike apply -f traffic.yaml

# 6. Extract Tigera CA bundle and a client cert (Goldmane requires mTLS)
mkdir -p /tmp/goldmane-tls
kubectl --context kind-olaitan-flow-spike -n calico-system get configmap tigera-ca-bundle \
  -o jsonpath='{.data.tigera-ca-bundle\.crt}' > /tmp/goldmane-tls/ca.crt
kubectl --context kind-olaitan-flow-spike -n calico-system get secret whisker-backend-key-pair \
  -o jsonpath='{.data.tls\.crt}' | base64 -d > /tmp/goldmane-tls/client.crt
kubectl --context kind-olaitan-flow-spike -n calico-system get secret whisker-backend-key-pair \
  -o jsonpath='{.data.tls\.key}' | base64 -d > /tmp/goldmane-tls/client.key

# 7. Port-forward
kubectl --context kind-olaitan-flow-spike -n calico-system port-forward \
  svc/goldmane 7443:7443 &

# 8. Capture one flow + write fixture + check round-trip
go run . --mode capture \
  --addr localhost:7443 \
  --ca /tmp/goldmane-tls/ca.crt \
  --cert /tmp/goldmane-tls/client.crt \
  --key /tmp/goldmane-tls/client.key \
  --src-ns spike-traffic --dst-ns spike-traffic \
  --timeout 60

# 9. Bench (≥100 records, median + p99)
go run . --mode bench \
  --addr localhost:7443 \
  --ca /tmp/goldmane-tls/ca.crt \
  --cert /tmp/goldmane-tls/client.crt \
  --key /tmp/goldmane-tls/client.key \
  --timeout 600

# 10. Tear down
./cleanup.sh
```

`make spike` runs steps 1 through 9 in sequence; `make cleanup`
removes the kind cluster and the TLS material.

## Expected console output

`go run . --mode capture` prints the FlowResult metadata, then:

```
PASS
fixture:  testdata/sample-flow.binpb (≈ 200 bytes)
expected: testdata/expected.json
```

`go run . --mode bench` prints:

```
PASS
samples:  100
median:   ≈ 250 µs (workload-dependent)
p99:      ≈ 1.5 ms (workload-dependent)
min:      ≈ 200 µs
max:      ≈ 2 ms
```

`go test -race ./...` runs three offline tests:

- `TestTranslateContract` — decodes the binary fixture, runs the
  translator, compares JSON byte-for-byte against `expected.json`.
- `TestRoundTripJSON` — `marshal -> unmarshal -> re-marshal`
  produces a semantically identical value.
- `TestTimestampStability` — `Flow.start_time` is interpreted as
  Unix seconds in UTC.

## AC5 reproducibility anchor

| Field | Value |
|---|---|
| CPU | `Intel(R) Core(TM) i7-10510U @ 1.80 GHz` |
| Kernel | `6.17.0-22-generic` (Ubuntu 24.04.4) |
| Go toolchain | `go1.26.2 linux/amd64` |
| Kubernetes | client `v1.35.4`, server `v1.30.0` (kind node image) |
| Spike commit (at capture time) | recorded in the ADR |

The spike's bench harness hoists the gRPC client, the JSON encoder,
and the translation function pointer outside the timed loop, so the
recorded timings reflect translation overhead rather than per-call
allocation. Percentile indices use the off-by-one-safe form
`samples[(n-1)*99/100]` as established by the Story 1.2 review.

## Deletion

This directory is deletable once Story 1.10 lands the production
`internal/collector/cni/` adapter and migrates any test fixtures it
inherits to `internal/collector/cni/testdata/`. The ADR carries the
durable record.
