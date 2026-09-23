# Audit-webhook receiver -- operator workflow

Story 1.7 introduces the Kubernetes audit-webhook receiver as the
second Olaitan signal source (Falco gRPC was the first, Story 1.6).
This document is the operator-facing wiring guide.

## What this gives you

The Olaitan audit adapter listens for `audit.k8s.io/v1` `EventList`
batches over mTLS, translates each event to a canonical `OltEvent` of
source `audit`, and publishes to `subjects.RawAudit` on JetStream with
at-least-once semantics. The signal complements Falco syscalls with
control-plane intent: RBAC bindings, NetworkPolicy mutations, Secret
reads, and `pods/exec`/`portforward` calls.

## Terminology note

The Olaitan architecture document refers to this as a
"`ValidatingWebhookConfiguration` audit-webhook variant". That phrasing
is incorrect Kubernetes terminology -- admission webhooks (synchronous
gates on incoming API requests via `AdmissionReview`) and audit-webhook
backends (asynchronous post-request push of audit `EventList` JSON via
`--audit-webhook-config-file`) are distinct features. Story 1.7 builds
the latter; the existing
`templates/validatingwebhookconfiguration.yaml` (a stub from Story 1.1
for a future admission-control feature) is left alone.

## Wiring overview

The chart renders three resources when `auditWebhook.enabled=true`:

1. `ConfigMap <release>-audit-policy` -- the audit policy YAML.
2. `Secret <release>-audit-webhook-kubeconfig` -- the kubeconfig the
   apiserver presents during mTLS.
3. `Secret <release>-audit-tls` -- the receiver's serving cert + key
   plus the cluster-CA bundle for verifying the apiserver client cert.

The apiserver-side wiring is operator-side (kubeadm
`apiServer.extraVolumes` + `extraArgs`) because the apiserver runs in
`kube-system`, outside this chart's namespace.

## Step-by-step: kubeadm 1.29

### 1. Generate the certificates and pick an address the apiserver can reach

Two things used to break here, both fixed in Story 10.8 (#137).

**The address.** The receiver listens in the collector DaemonSet, and the
chart's audit Service now selects it. But kube-apiserver runs on the host
network with the node's resolver, so on a self-managed cluster it cannot
resolve `<fullname>-audit-webhook.<namespace>.svc.cluster.local`, which is
the default in the kubeconfig. The supported way to reach the receiver is
the node itself:

- `auditWebhook.hostPort=<port>` publishes the receiver on every node the
  collector runs on, bound to `auditWebhook.hostIP` (default `127.0.0.1`,
  so the port stays off the node's other interfaces; empty binds all of
  them).
- `auditWebhook.serverAddress=127.0.0.1:<port>`, with the same port, makes
  each apiserver dial its own node's collector, with no cluster DNS and no
  Service in the path.
- `collector.runOnControlPlane=true` schedules a collector onto the
  control-plane nodes, which is where the apiserver runs. Without it no
  collector listens where the apiserver dials.

The default (empty `serverAddress`) only works where the apiserver uses
cluster DNS.

These values are validated at render, alone and against each other: a
loopback `serverAddress` without `hostPort`, ports that differ, a
`hostPort` with no `serverAddress`, or a `hostPort` without
`collector.runOnControlPlane=true` fails the install rather than silently
dropping every audit event. An IPv6 `serverAddress` is bracketed, as in a
URL (`[fd00::1]:31443`).

Reaching a `hostPort` on the node's loopback address depends on how the
cluster's CNI implements `hostPort` (the CNI `portmap` plugin, or the
CNI's own equivalent). It was verified on kind. If the apiserver's audit
log shows connection refused on `127.0.0.1:<port>`, check that your CNI
supports `hostPort` with a loopback `hostIP`.

**The CA.** The receiver verifies the apiserver's client certificate
against `auditWebhook.clusterCAData` and pins its CN. This document used
to sign the client certificate with a private audit CA while setting
`clusterCAData` to the cluster's own root CA, so the receiver rejected
every apiserver connection at the handshake. One CA signs both sides:

```sh
# <out-dir>, then every name the apiserver may dial (DNS names and IPs).
hack/audit-webhook-certs.sh ./audit-certs \
    olaitan-audit-webhook.olaitan.svc.cluster.local 127.0.0.1
```

The Service name is `<fullname>-audit-webhook.<namespace>.svc.cluster.local`.
`<fullname>` is the release name when it already contains `olaitan`, and
`<release>-olaitan` otherwise (or `fullnameOverride` when set). For
release `audit` in namespace `security`, pass
`audit-olaitan-audit-webhook.security.svc.cluster.local`. With no names the
script uses the defaults for release `olaitan` in namespace `olaitan`.
Only `127.0.0.1` is dialled by the apiserver on the node-local path; the
Service name matters for in-cluster clients such as the port-forward in
step 5.

The script refuses to write into a directory that already holds an audit
CA, so a second run cannot replace the CA your existing certificates chain
to. Every file it writes is readable by the owner only:

| File | What it is |
|------|------------|
| `audit-ca.crt` | The CA certificate. Goes into both `caBundle` and `clusterCAData`. |
| `audit-ca.key` | The CA private key. Anyone holding it can mint a client certificate the receiver accepts, or a serving certificate the apiserver trusts. Move it offline, or delete it once the chart is installed; you need it again only to issue new certificates from the same CA. |
| `audit-ca.srl` | The CA's serial-number counter. Keep it with `audit-ca.key`. |
| `audit-server.crt`, `audit-server.key` | The receiver's serving certificate and key. |
| `audit-client.crt`, `audit-client.key` | The apiserver's client certificate (`CN=kube-apiserver`, the CN the receiver pins) and key. |
| `audit-webhook-values.yaml` | Every field above, base64-encoded on one line, for `helm install -f`. It embeds the server and client private keys, so treat it as a secret. |

`AUDIT_CLIENT_CN` and `AUDIT_CERT_DAYS` override the client CN and the
lifetime in days.

### 2. (Optional) use your cluster's own CA instead

If you would rather have the apiserver present a client certificate
signed by the cluster CA, set `clusterCAData` to THAT CA (the one that
signed the client certificate you are using), not to the audit CA:

```sh
sudo base64 -w0 /etc/kubernetes/pki/ca.crt   # -> auditWebhook.clusterCAData
```

`caBundle` stays the CA that signed the receiver's serving certificate.
The two values answer different questions: `caBundle` is what the
apiserver trusts, `clusterCAData` is what the receiver trusts.

### 3. Install the chart with audit-webhook enabled

```sh
helm install olaitan ./deploy/helm/olaitan \
    --namespace olaitan --create-namespace \
    -f ./audit-certs/audit-webhook-values.yaml \
    --set auditWebhook.hostPort=31443 \
    --set auditWebhook.serverAddress=127.0.0.1:31443 \
    --set collector.runOnControlPlane=true \
    --set secrets.redisPassword=<dev-only>
```

This renders the policy ConfigMap, the kubeconfig Secret, and the TLS
Secret. The collector DaemonSet publishes the receiver on every node,
control-plane nodes included, at the `hostPort` (31443 above) on
`127.0.0.1`. The receiver itself still listens on `containerPort` (8443)
inside the pod.

### 4. Wire the apiserver

The apiserver's audit-webhook backend is configured through two flags
the kubeadm config patches inject:

- `--audit-policy-file=/etc/kubernetes/audit/policy.yaml`
- `--audit-webhook-config-file=/etc/kubernetes/audit/webhook-kubeconfig.yaml`

Both files must exist on the control-plane node and be readable by the
apiserver process. Copy them out of the chart-rendered Secret and
ConfigMap (the names below are for release `olaitan` in namespace
`olaitan`; substitute `-n <namespace>` and `<fullname>-audit-policy` /
`<fullname>-audit-webhook-kubeconfig` for any other):

```sh
sudo mkdir -p /etc/kubernetes/audit
kubectl -n olaitan get configmap olaitan-audit-policy \
    -o jsonpath='{.data.policy\.yaml}' | sudo tee /etc/kubernetes/audit/policy.yaml >/dev/null
kubectl -n olaitan get secret olaitan-audit-webhook-kubeconfig \
    -o jsonpath='{.data.webhook-kubeconfig\.yaml}' | base64 -d \
    | sudo tee /etc/kubernetes/audit/webhook-kubeconfig.yaml >/dev/null
sudo chmod 0644 /etc/kubernetes/audit/policy.yaml
sudo chmod 0600 /etc/kubernetes/audit/webhook-kubeconfig.yaml
```

Then apply the kubeadm patch (sample at
`hack/audit-apiserver-patch.yaml`):

```sh
sudo cp hack/audit-apiserver-patch.yaml /etc/kubernetes/patches/kube-apiserver+json.yaml
sudo kubeadm init phase control-plane apiserver --patches /etc/kubernetes/patches/
```

The apiserver pod restarts and begins pushing audit batches to the
Olaitan receiver.

### Upgrading

The apiserver reads the webhook kubeconfig only when it starts, and it
reads it from the control-plane host, not from the cluster. After any
`helm upgrade` that changes the certificates, `auditWebhook.serverAddress`
or `auditWebhook.hostPort`:

1. Re-run the `kubectl ... | sudo tee /etc/kubernetes/audit/...` commands
   from step 4 on every control-plane host, so the copied kubeconfig
   matches the new Secret.
2. Restart kube-apiserver on each of those hosts. It is a static pod, so
   move its manifest out of the kubelet's manifest directory and back:

   ```sh
   sudo mv /etc/kubernetes/manifests/kube-apiserver.yaml /etc/kubernetes/
   # wait until the apiserver container has stopped (crictl ps)
   sudo mv /etc/kubernetes/kube-apiserver.yaml /etc/kubernetes/manifests/
   ```

Until both steps are done the apiserver keeps dialling with the old
address and certificates, and the receiver rejects or never sees it.

The receiver side needs no manual step. The receiver reads its serving
cert and client CA once, when it starts, so the collector DaemonSet's
pod template carries a `checksum/audit-tls` annotation: the sha256 of
the data of the `<release>-audit-tls` Secret the chart renders. Changing
`auditWebhook.servingCert`, `servingKey` or `clusterCAData` changes the
checksum and the DaemonSet rolls on its own. Upgrades that change no
cert leave the collector running.

### 5. Verify

Confirm the apiserver is dialling the receiver successfully:

```sh
# Receiver logs should show "audit: stream connected"-style entries
# once the first batch arrives.
kubectl -n olaitan logs -l app.kubernetes.io/component=collector --tail=50

# Health endpoint (in-process tracker, surfaced via /metrics in Story 1.12)
kubectl -n olaitan port-forward svc/olaitan-audit-webhook 18443:8443 &
curl -sk https://localhost:18443/healthz   # 204 No Content
```

## Tuning

- `auditWebhook.policy.custom` (Helm value) overrides the baked-in
  default policy byte-for-byte. Use this when your cluster has a high
  controller-manager noise floor and the default filter does not cover
  it.
- `detection.sources.audit.max_payload_bytes` (in `config/olaitan.yaml`,
  default 8 MiB) caps the request body. Reject-413s do not retry on
  the apiserver side, so a consistently 413-ing receiver indicates a
  misconfigured `--audit-webhook-batch-max-size` upstream.
- `detection.sources.audit.staleness_timeout` (in `config/olaitan.yaml`,
  default 5m) flips the source unhealthy when no successful publish
  has landed. Lower this for low-traffic test clusters; raise it for
  clusters with conservative audit policies that emit infrequent
  events.
- `detection.sources.audit.publish_retry` (in `config/olaitan.yaml`)
  tunes the per-publish bounded retry. Defaults: 100ms..1s, equal-
  jitter at 1.0, 3 attempts. Aligned with the in-code defaults to
  avoid `helm install --debug` rendering values that disagree with
  what the Go adapter actually uses.

Edits to `config/olaitan.yaml` MUST be followed by `make helm-prepare`
before the next `helm install` / `helm upgrade` because the chart
copies the file into the chart's `files/` directory at package time.

### Dual-flag relationship (auditWebhook.enabled vs detection.sources.audit.enabled)

The chart-side `auditWebhook.enabled` Helm value gates rendering of
the audit-webhook resources (Service, Secrets, policy ConfigMap, port
+ TLS volume on the DaemonSet). The runtime-side
`detection.sources.audit.enabled` boolean inside `config/olaitan.yaml`
gates whether the collector subcommand actually starts the receiver
goroutine.

The chart's `templates/configmap.yaml` automatically flips the
runtime flag to `true` whenever `auditWebhook.enabled=true` (via a
targeted regex overlay on the rendered configmap), so operators only
need to flip the Helm flag. The static value in `config/olaitan.yaml`
stays `false` so dev-local runs (without Helm) leave the receiver
dormant.

## Future migration: cert-manager

Path A in Story 1.7 Task 7 (cert-manager-issued serving cert via a
`Certificate` resource) is deferred. When cert-manager is available
operationally the chart will gain a `auditWebhook.certManager.enabled`
flag that swaps the operator-supplied `servingCert` / `servingKey`
inputs for a cert-manager-managed Secret of the same name.
