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

### 1. Generate the receiver serving cert + signing CA

The receiver listens at the Service FQDN:

```
<release>-olaitan-audit-webhook.<namespace>.svc.cluster.local
```

Generate a self-signed CA, sign a serving cert for that FQDN, and a
client cert with `CN=kube-apiserver` for mTLS:

```sh
# CA
openssl genpkey -algorithm ED25519 -out audit-ca.key
openssl req -x509 -new -nodes -key audit-ca.key -subj "/CN=olaitan-audit-ca" \
    -days 365 -out audit-ca.crt

# Receiver serving cert
openssl genpkey -algorithm ED25519 -out audit-server.key
openssl req -new -key audit-server.key \
    -subj "/CN=olaitan-audit-webhook.olaitan.svc.cluster.local" \
    -out audit-server.csr
openssl x509 -req -in audit-server.csr -CA audit-ca.crt -CAkey audit-ca.key \
    -CAcreateserial -days 365 -out audit-server.crt \
    -extfile <(printf "subjectAltName=DNS:olaitan-audit-webhook.olaitan.svc.cluster.local")

# Client cert (presented by the apiserver during mTLS)
openssl genpkey -algorithm ED25519 -out audit-client.key
openssl req -new -key audit-client.key -subj "/CN=kube-apiserver" -out audit-client.csr
openssl x509 -req -in audit-client.csr -CA audit-ca.crt -CAkey audit-ca.key \
    -CAcreateserial -days 365 -out audit-client.crt
```

### 2. Extract the cluster CA

The receiver requires-and-verifies the apiserver's client cert. On a
kubeadm cluster the cluster CA at `/etc/kubernetes/pki/ca.crt` signs
the apiserver components; extract and base64 it for the chart:

```sh
sudo base64 -w0 /etc/kubernetes/pki/ca.crt > audit-cluster-ca.b64
```

(The apiserver presents a client cert signed by the cluster CA when it
calls webhook backends; the receiver pins that CA in its
`tls.RequireAndVerifyClientCert` pool.)

### 3. Install the chart with audit-webhook enabled

```sh
helm install olaitan ./deploy/helm/olaitan \
    --namespace olaitan --create-namespace \
    --set auditWebhook.enabled=true \
    --set-file auditWebhook.servingCert=<(base64 -w0 audit-server.crt) \
    --set-file auditWebhook.servingKey=<(base64 -w0 audit-server.key) \
    --set-file auditWebhook.caBundle=<(base64 -w0 audit-ca.crt) \
    --set-file auditWebhook.apiserverClientCert=<(base64 -w0 audit-client.crt) \
    --set-file auditWebhook.apiserverClientKey=<(base64 -w0 audit-client.key) \
    --set-file auditWebhook.clusterCAData=<(cat audit-cluster-ca.b64) \
    --set secrets.redisPassword=<dev-only>
```

This renders the policy ConfigMap, the kubeconfig Secret, and the TLS
Secret. The collector DaemonSet now exposes port 8443 on every node.

### 4. Wire the apiserver

The apiserver's audit-webhook backend is configured through two flags
the kubeadm config patches inject:

- `--audit-policy-file=/etc/kubernetes/audit/policy.yaml`
- `--audit-webhook-config-file=/etc/kubernetes/audit/webhook-kubeconfig.yaml`

Both files must exist on the control-plane node and be readable by the
apiserver process. Copy them out of the chart-rendered Secret and
ConfigMap:

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

- `auditWebhook.policy.custom` overrides the baked-in default policy
  byte-for-byte. Use this when your cluster has a high
  controller-manager noise floor and the default filter does not cover
  it.
- `auditWebhook.receiver.maxPayloadBytes` (default 8 MiB) caps the
  request body. Reject-413s do not retry on the apiserver side, so a
  consistently 413-ing receiver indicates a misconfigured
  `--audit-webhook-batch-max-size` upstream.
- `auditWebhook.receiver.stalenessTimeout` (default 5m) flips the
  source unhealthy when no inbound traffic arrives. Lower this for
  low-traffic test clusters; raise it for clusters with conservative
  audit policies that emit infrequent events.

## Future migration: cert-manager

Path A in Story 1.7 Task 7 (cert-manager-issued serving cert via a
`Certificate` resource) is deferred. When cert-manager is available
operationally the chart will gain a `auditWebhook.certManager.enabled`
flag that swaps the operator-supplied `servingCert` / `servingKey`
inputs for a cert-manager-managed Secret of the same name.
