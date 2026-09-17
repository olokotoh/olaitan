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
# Since Calico v3.30 the operator's CRDs ship separately and the
# operator does not install them itself. Without this first step the
# custom resources below fail with "no matches for kind Installation in
# version operator.tigera.io/v1".
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.31.5/manifests/operator-crds.yaml

kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.31.5/manifests/tigera-operator.yaml
kubectl rollout status -n tigera-operator deployment/tigera-operator --timeout=180s

kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.31.5/manifests/custom-resources.yaml
kubectl -n calico-system rollout status deployment/goldmane --timeout=300s
```

There is no supported path without the operator. Goldmane is an
operator-managed component: the Installation CR in
`custom-resources.yaml` is what causes the operator to create the
`goldmane` Deployment in `calico-system`, and with only
`tigera-operator.yaml` applied there is nothing for the adapter to
dial.

### On kind: `hack/install-calico-kind.sh`

The supported way to get a kind cluster the adapter can actually work
against. It creates (or reuses) a kind cluster from
`hack/kind-calico-config.yaml`, which disables kindnetd and sets the pod
CIDR Calico's default IPPool claims, installs the pinned Tigera operator
and custom resources, waits for Goldmane with a bounded timeout, and
writes the Path B values file:

```bash
hack/install-calico-kind.sh ./calico-tls
helm install olaitan deploy/helm/olaitan -f ./calico-tls/calico-values.yaml
kubectl apply -f tests/e2e/fixtures/calico-flow-traffic.yaml
```

The e2e cluster config (`hack/kind-config.yaml`) is NOT usable here: it
runs kindnetd, which ships no Goldmane and enforces no NetworkPolicy, so
the release's Goldmane egress rule would be accepted and ignored.

Overrides: `CLUSTER_NAME`, `KIND_NODE_IMAGE`, `CALICO_VERSION`,
`KUBECONFIG`, `GOLDMANE_TIMEOUT`. The script reuses an existing cluster,
so re-running it into a fresh output directory is the way to refresh the
certificates after Tigera rotates them; it refuses to write into a
directory that already holds certificate material, because replacing it
in place would leave an installed release pointing at material nobody
can account for.

The traffic fixture matters. Goldmane reports what Felix observed, so a
cluster with no east-west traffic produces no `FlowResult` and the
adapter sits connected and silent. The fixture runs a real pod-to-Service
request loop; the first flows land roughly 30 to 60 seconds later.

The original spike bring-up (port-forward, fixture capture, benchmark)
is in `spikes/calico-flow/README.md` and was verified end-to-end during
Story 1.3.

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

#### Key names: the chart remaps them for you

A cert-manager `Certificate` writes a `kubernetes.io/tls` Secret, whose
keys are `tls.crt` and `tls.key`. The adapter opens
`/etc/olaitan/cni/client.crt` and `/etc/olaitan/cni/client.key`
(`config/olaitan.yaml`, `detection.sources.calico`), and a missing file
is a terminal adapter error, so before Story 10.11 a Path A install
CrashLooped the collector with `cni: tls load (terminal, no retry)`.
The chart now projects the Secret through `items:` so the mount
produces the names the adapter reads:

| Secret key | File under `/etc/olaitan/cni` |
|---|---|
| `tls.crt` | `client.crt` |
| `tls.key` | `client.key` |
| `calicoSensor.tls.certManagerCAKey` (default `ca.crt`) | `ca.crt` |

Nothing changes on Path B: the chart renders that Secret itself with
the adapter's own key names, so it is mounted verbatim.

**If the issuer does not publish `ca.crt`.** cert-manager always writes
`tls.crt` and `tls.key`, but it writes `ca.crt` only when the issuer
supplies a CA, and some issuers publish the bundle under another key.
Name that key rather than renaming the Secret:

```yaml
calicoSensor:
  tls:
    certManagerSecretName: olaitan-cni-tls
    certManagerCAKey: tigera-ca-bundle.crt
```

The adapter cannot verify Goldmane's serving certificate without a CA
bundle, so an empty `certManagerCAKey` fails the render with a message
naming the value, rather than mounting a volume the adapter rejects at
run time. If the Secret carries no CA under any key, issue the
Certificate from an issuer that sets one, or use Path B, where the CA
bundle is supplied directly.

### Path B: operator-supplied PEMs (dev sandbox)

On kind, `hack/install-calico-kind.sh` does all of this and writes the
values file; the manual recipe below is for clusters it does not build.

For evaluation runs the operator can extract the Tigera CA bundle
plus a Tigera-issued client cert (the spike borrowed
`whisker-backend-key-pair`). Mind the asymmetry: the CA bundle lives in
a ConfigMap, so that jsonpath yields PEM and must be base64-encoded,
while the client pair lives in a Secret, so the same jsonpath already
yields base64 and must not be encoded twice:

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
| Path A pod stuck `ContainerCreating` with a Secret key error on the `cni-tls` volume | The cert-manager Secret has no key named by `calicoSensor.tls.certManagerCAKey` | `kubectl get secret <name> -o jsonpath='{.data}'` and set `certManagerCAKey` to the key that holds the CA bundle; see *Key names* above |
| No `olaitan.events.raw.network` events although the adapter is connected and `source_healthy{source="network"}` is 1 | The cluster is quiet, so Goldmane has nothing to report | Apply `tests/e2e/fixtures/calico-flow-traffic.yaml` and wait 30 to 60 seconds for the first Felix flush plus Goldmane window |

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
