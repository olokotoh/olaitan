# Calico CNI flow adapter

Operator-facing workflow for enabling the Olaitan Calico CNI flow
adapter (Story 1.10 / FR4). The adapter subscribes to the Calico
Goldmane gRPC API over mTLS, translates each `FlowResult` into a
canonical `schema.Event` (source=network / category=flow), and
publishes to JetStream subject `olaitan.events.raw.network`.

For the design rationale (why Goldmane, why operator-install) see
`docs/deferred-decisions.md` ADRs **ADR-2026-04-30-01** (Calico flow
record export mechanism) and **ADR-2026-05-12-01** (Calico bootstrap
migration to Tigera operator install).

## Pre-requisite: Tigera operator install on Calico v3.31.5+

Goldmane is shipped only under Calico's Tigera operator install path
on Calico **v3.31.5+**. The legacy manifest install
(`kubectl apply -f calico.yaml`) does NOT produce a Goldmane
Deployment.

Verify the install path:

```bash
kubectl -n calico-system get deployment goldmane
```

If the Deployment is absent, follow the operator install at
https://github.com/projectcalico/calico/releases/tag/v3.31.5:

```bash
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.31.5/manifests/tigera-operator.yaml
kubectl rollout status -n tigera-operator deployment/tigera-operator --timeout=180s

kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.31.5/manifests/custom-resources.yaml
kubectl -n calico-system rollout status deployment/goldmane --timeout=300s
```

The full bring-up sequence (kind cluster, traffic generator, fixture
capture) is in `spikes/calico-flow/README.md` and was verified
end-to-end during Story 1.3.

## mTLS provisioning

Goldmane enforces mTLS on its gRPC listener; a server-only TLS
handshake is rejected. The agent must present a client cert signed
by the Tigera operator's CA.

### Path A: cert-manager (preferred, production)

1. Install cert-manager if not already present.
2. Create a `ClusterIssuer` backed by the Tigera CA (Tigera's CA
   bundle is in the `tigera-ca-bundle` ConfigMap in `calico-system`).
3. Issue a `Certificate` resource targeting the ClusterIssuer with
   common name `olaitan-agent` and the `clientAuth` extended key
   usage.
4. Configure the chart:

```yaml
calicoSensor:
  enabled: true
  tls:
    certManagerSecretName: olaitan-cni-tls
```

The chart mounts the cert-manager-issued Secret directly. Cert
rotation is automatic; the adapter loads TLS material from disk on
every connect-loop iteration so a fresh Secret remount is picked up
without an agent restart.

### Path B: operator-supplied PEMs (dev sandbox)

For evaluation runs the operator can extract the Tigera CA bundle
plus a Tigera-issued client cert (the spike borrowed
`whisker-backend-key-pair`):

```bash
kubectl -n calico-system get configmap tigera-ca-bundle \
  -o jsonpath='{.data.tigera-ca-bundle\.crt}' | base64 -w0
kubectl -n calico-system get secret whisker-backend-key-pair \
  -o jsonpath='{.data.tls\.crt}'
kubectl -n calico-system get secret whisker-backend-key-pair \
  -o jsonpath='{.data.tls\.key}'
```

Paste the three base64-encoded values into `values.yaml`:

```yaml
calicoSensor:
  enabled: true
  tls:
    caBundle:   "LS0tLS1CRUdJTi..."
    clientCert: "LS0tLS1CRUdJTi..."
    clientKey:  "LS0tLS1CRUdJTi..."
```

The chart renders an `Opaque` Secret named `<release>-cni-tls` from
these values and mounts it at `/etc/olaitan/cni/`.

**Caveat: Path B is not rotation-aware.** When the Tigera-issued
Secret rotates, the operator must re-extract the new material and
`helm upgrade` the chart. Path A is the production target.

## Enabling the adapter

The dual-flag pattern requires BOTH chart-side and config-side
flags:

- `calicoSensor.enabled=true` in `values.yaml` (chart gating)
- `detection.sources.calico.enabled=true` in `config/olaitan.yaml`
  (adapter gating)

The chart's `templates/configmap.yaml` bridges the chart flag into
the rendered `olaitan.yaml`, so flipping `calicoSensor.enabled=true`
flips both flags automatically.

## NetworkPolicy egress

The chart's `templates/networkpolicy.yaml` adds an egress allow rule
from the Olaitan namespace to `calico-system/goldmane:7443` only
when `calicoSensor.enabled=true`. Operators who run a custom
NetworkPolicy outside the chart must replicate this rule manually.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `cni: dial ... (terminal, no retry)` with `Unauthenticated` | mTLS cert rejected by Goldmane | Verify the client cert is signed by the Tigera CA; check `kubectl -n calico-system logs deployment/goldmane` for the rejection reason |
| `cni: dial ... connection refused` looping | Goldmane Deployment not Ready, or wrong address | `kubectl -n calico-system get deployment goldmane`; verify the chart `calicoSensor.goldmaneAddr` matches the Service DNS |
| `cni: stream eof` followed by immediate reconnect | Goldmane restart (Tigera operator roll) | Self-healing; the connect retry recovers within ~1-60s |
| `cni: no flow for ... and connection not Ready` | Goldmane reachable but cluster is genuinely quiet | Watchdog is doing its job; consider whether a 10-minute staleness threshold is too tight for your cluster |
| Chart render fails with `calicoSensor.tls.caBundle is required` | Path B selected but no PEM supplied | Either set `tls.certManagerSecretName` (Path A) or fill in all three Path B PEMs |
| Agent pod CrashLoopBackOff with `cni: tls load (terminal, no retry): no such file` | Secret not mounted | Verify `kubectl describe pod` shows the `cni-tls` volume; check the chart's `calicoSensor.enabled` actually rendered the mount |

## Known limitations

- **`FlowKey.source_name` is GenerateName-derived.** Goldmane
  identifies workloads by "a set of pods that share a GenerateName"
  rather than by individual pod name. The adapter tags every event
  with `pod_name_kind:generatename` so the correlator (Story 1.14)
  can drive K8s API enrichment via the on-demand workload posture
  client (Story 1.11). Until Story 1.11 lands, downstream consumers
  see the GenerateName-derived set identity rather than the full
  `namespace/owner-kind/owner-name` workload identity.
- **Goldmane is tech preview as of Calico v3.31.5.** The proto wire
  format and `FlowResult` field set are not yet API-stable; each
  Calico point-release bump should re-verify the SHA pin in
  `internal/collector/cni/goldmanepb/README.md` and re-run the
  integration test suite.
- **Aggregation window.** `Flow.StartTime` records the start of
  Goldmane's 15-second aggregation interval, not a per-packet
  timestamp. Sigma rules using `timestamp` semantics must account
  for the aggregation window.
- **`startTimeGte` semantics.** The chart default
  (`calicoSensor.startTimeGte: -60`) replays the last 60 seconds of
  flow records on every reconnect, matching the spike's capture
  mode. An explicit `0` reaches Goldmane's documented "now"
  semantic per the v3.31.5 proto contract
  (`goldmane/proto/api.proto` line 91: "A value of zero means
  'now'") and starts the stream from current wall-clock without
  replay. Positive values are rejected at config-load time. To use
  the chart default explicitly, set `calicoSensor.startTimeGte:
  null` (or omit the key).
- **`aggregationInterval` is fixed at 15s.** Goldmane's proto
  contract pins the value (`goldmane/proto/api.proto` line 100: "It
  must always be 15s."). The chart default and the config-loader
  reject any non-15 value to fail fast rather than surface a
  Goldmane-side rejection at stream-open time.

## Future hardening

- Switch Path A from operator-manual ClusterIssuer to a
  chart-rendered `Certificate` resource (depends on a cert-manager
  dependency in the umbrella chart).
- Move proto vendoring to `buf push` against
  `buf.build/projectcalico/goldmane` when Calico publishes the proto
  to the Buf Schema Registry.
- Add a `calicoSensor.filter` knob that maps to
  `FlowStreamRequest.Filter` so operators can scope the stream to a
  subset of namespaces / labels at the Goldmane layer.
- Switch from iptables to BPF Calico dataplane and re-verify the
  fixture set against the BPF-mode `FlowResult` payload.
