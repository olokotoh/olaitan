# Application log sidecar (Story 1.9 / FR5)

This document describes how to opt a workload in to Olaitan's application
log sidecar adapter, the cooperation contract the application must
honour, the security boundary of the MutatingAdmissionWebhook, and how
to troubleshoot a stuck injection.

## What ships with the chart

When `applogSidecar.enabled=true` the chart deploys four resources
beyond the agent DaemonSet:

1. `Deployment <fullname>-applog-injector` running the multi-call
   binary subcommand `olaitan applog-injector`. Default replica count
   is `2` for high availability per the K8s admission-webhook good-
   practice guidance.
2. `Service <fullname>-applog-injector` (ClusterIP, port 443 -> sidecar
   8443) routing apiserver admission traffic to the webhook pods.
3. `MutatingWebhookConfiguration <fullname>-applog-injector` with
   `failurePolicy: Ignore`, `sideEffects: None`,
   `reinvocationPolicy: Never`, and a `namespaceSelector` excluding
   `kube-system` and `kube-public` by default.
4. `Secret <fullname>-applog-injector-tls` (or a cert-manager
   `Certificate` resource when `applogSidecar.tls.certManagerEnabled=
   true`) providing the webhook's serving cert + key.

The Olaitan agent DaemonSet pod-spec is unchanged by Story 1.9 -- the
sidecar runs in operator workload pods, not the agent pod.

## Operator workflow

1. Generate or provision TLS material for the webhook. Two paths:
   - **Path A (production, recommended)**: cert-manager.
     Set `applogSidecar.tls.certManagerEnabled=true` and
     `applogSidecar.tls.issuerName=<your Issuer>`. The chart renders
     a cert-manager `Certificate` resource; cert-manager populates the
     Secret and the apiserver-side caBundle automatically via the
     `cert-manager.io/inject-ca-from` annotation.
   - **Path B (dev / air-gapped)**: manual self-signed cert.
     Generate a CA, sign a serving cert valid for the SAN
     `<fullname>-applog-injector.<namespace>.svc`, then populate
     `applogSidecar.tls.servingCert` (PEM, base64-encoded),
     `applogSidecar.tls.servingKey` (PEM, base64-encoded), and
     `applogSidecar.tls.caBundle` (PEM, base64-encoded). Set
     `applogSidecar.tls.certManagerEnabled=false`.

2. Deploy with `applogSidecar.enabled=true`:

   ```sh
   helm upgrade olaitan ./deploy/helm/olaitan \
     --set applogSidecar.enabled=true \
     --set applogSidecar.tls.certManagerEnabled=true \
     --set applogSidecar.tls.issuerName=olaitan-ca
   ```

3. Verify the webhook is up:

   ```sh
   kubectl -n olaitan get deploy/olaitan-applog-injector
   kubectl -n olaitan logs deploy/olaitan-applog-injector -c applog-injector --tail=20
   curl -k https://olaitan-applog-injector.olaitan.svc:443/healthz   # via port-forward or in-cluster
   ```

4. Annotate the target workload Pod (or its owning Deployment /
   StatefulSet template):

   ```yaml
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: payments
   spec:
     template:
       metadata:
         annotations:
           olaitan.io/log-sidecar: "enabled"
           # Optional: when the pod has multiple containers, name the
           # one whose stdout/stderr should be tailed:
           olaitan.io/log-sidecar-container: "payments"
       spec:
         volumes:
           - name: olaitan-applog-shared
             emptyDir: {}
         containers:
           - name: payments
             image: myreg/payments:1.0
             volumeMounts:
               - name: olaitan-applog-shared
                 mountPath: /var/log/app
             # The webhook injects the volumeMount automatically;
             # this manual entry is shown for clarity.
   ```

5. **Cooperation contract**: the application must arrange to write
   its stdout and stderr to `/var/log/app/stdout.log` and
   `/var/log/app/stderr.log` in the shared `olaitan-applog-shared`
   emptyDir volume. The webhook does NOT modify the application's
   `command` or `args`; the operator is responsible for the redirect.
   Common patterns:

   - **Tee-based shim** in the entry-point script:
     ```sh
     exec /app/payments 1> >(tee /var/log/app/stdout.log) 2> >(tee /var/log/app/stderr.log >&2)
     ```
   - **Logging-library configuration** that writes both to stdout AND
     to the shared file (e.g. logrus Hook, slog MultiHandler).
   - **Process supervisor** like `s6-overlay` that handles the
     redirect.

6. Verify the sidecar is injected:

   ```sh
   # Native sidecar mode (K8s 1.28+):
   kubectl get pod <pod> -o jsonpath='{.spec.initContainers[*].name}' | grep olaitan-applog-sidecar
   # Fallback (containers) mode:
   kubectl get pod <pod> -o jsonpath='{.spec.containers[*].name}' | grep olaitan-applog-sidecar
   ```

7. Verify log lines appear on the bus:

   ```sh
   kubectl -n olaitan exec deploy/olaitan-aggregator -c aggregator -- \
     nats sub 'olaitan.events.raw.applog' --count=10
   ```

## Native sidecar (KEP-753) requirement

The default `applogSidecar.useNativeSidecar=true` injects the sidecar
into `spec.initContainers` with `restartPolicy: Always`, which the
kubelet treats as a sidecar that runs alongside the application
containers and shuts down gracefully after them. This requires the
`SidecarContainers` feature gate, which is **on by default in
Kubernetes 1.29** and graduates to beta in the 1.29 timeline per
KEP-753.

For clusters older than 1.28 or with the feature gate explicitly
disabled, set `applogSidecar.useNativeSidecar=false`. The webhook
then injects into `spec.containers` instead. The trade-off: a
regular container in `containers` does not get the graceful-shutdown-
after-main-container-exit behaviour of a native sidecar, so the
sidecar may be terminated before it has finished publishing the
application's last log lines. This is acceptable for non-critical
log-collection.

To check whether your cluster supports native sidecars:

```sh
kubectl get nodes -o jsonpath='{.items[*].status.nodeInfo.kubeletVersion}'
# 1.29+ has the gate on by default.
```

## Security boundary

The MutatingAdmissionWebhook sits on the apiserver path and can mutate
every Pod cluster-wide. Threat model:

- **Compromise of the webhook pod** lets an attacker inject malicious
  sidecars into every annotated pod. Mitigations:
  - The webhook image is the same `olaitan-agent` image (already
    under Trivy CVE scan per NFR13).
  - The webhook ServiceAccount has minimum-privilege RBAC: no
    `pods.update` outside the admission path.
  - The Service is namespaced (ClusterIP only) and not exposed
    externally.
  - `failurePolicy: Ignore`: a webhook outage does NOT block Pod
    admission cluster-wide. Operators trade missed sidecar injections
    for cluster availability.
  - `namespaceSelector`: excludes `kube-system` / `kube-public` by
    default; defended in code as well (the webhook handler returns
    no patch for system namespaces independently of the selector).
  - Replica count default 2 (HA); single-replica is a SPOF.
  - Pod Security: the webhook Pod runs nonroot, read-only root
    filesystem, all capabilities dropped, no privilege escalation.

- **Stale or untrusted serving cert** would let an attacker MITM the
  apiserver-to-webhook hop. Mitigations:
  - Path A (cert-manager) rotates the Certificate every 30 days
    before expiry.
  - Path B operators are expected to rotate the manually-provided
    Secret periodically.

## Troubleshooting

- **Sidecar not injected after annotation**: check the webhook logs
  (`kubectl -n olaitan logs deploy/olaitan-applog-injector`). Common
  causes:
  - `kube-system` / `kube-public` pods (system-namespace
    exclusion).
  - The webhook never received the AdmissionReview because the
    `MutatingWebhookConfiguration.clientConfig.service` does not
    resolve. Verify with
    `kubectl get mutatingwebhookconfiguration olaitan-applog-injector -o yaml`.
  - `failurePolicy: Ignore` swallowed an error. The webhook logs
    every skipped pod with the reason.
- **AdmissionReview decode error**: the apiserver may be sending an
  unexpected API version. Check the `admissionReviewVersions` field
  on the configuration; v1 is the only supported version.
- **Cert / TLS issues**:
  - Path A (cert-manager): verify the Issuer is Ready
    (`kubectl describe issuer <name>`). Verify the Certificate is
    Ready (`kubectl describe cert olaitan-applog-injector-tls`).
  - Path B: verify the manual Secret carries `tls.crt` and `tls.key`
    (`kubectl -n olaitan get secret olaitan-applog-injector-tls -o yaml`).
    Verify the apiserver-side caBundle on the
    MutatingWebhookConfiguration matches the CA that signed the
    serving cert.
- **Sidecar injected but no log events appearing on
  `olaitan.events.raw.applog`**: check the sidecar's stdout
  (`kubectl logs <pod> -c olaitan-applog-sidecar`). Common causes:
  - The application is not writing to `/var/log/app/stdout.log` /
    `/var/log/app/stderr.log` (cooperation contract violation).
  - NATS connection failure (the sidecar logs the cause).
  - Adapter dropped lines under back-pressure shedding (the
    `applog_lines_shed_total` counter increments; see Story 1.12 for
    the Prometheus surface).

## Unsupported pod shapes

The webhook does not inject the sidecar into the following pod shapes,
even when the annotation is present:

- **Init-only pods** -- pods whose `spec.containers` is empty (only
  init containers). The native-sidecar pattern (KEP-753) places the
  sidecar in `spec.initContainers` alongside the application's own
  init containers, but the cooperation contract requires a peer
  application container to mount the shared volume and write its
  stdout / stderr into it. An init-only pod has no such peer. The
  webhook returns `Allowed: true` with no patch and bumps the
  `applog_admission_unsupported_shape_total` counter; the operator
  sees a WARN log noting the namespace and pod name. Future work
  (`gds_*` future-work backlog): support init-only pods by either
  scoping the sidecar to a specific init container or by tailing
  kubelet-managed `/var/log/pods` (option (ii) hostPath below).
- **Pods in `kube-system` / `kube-public`** (defended in code and at
  the chart's `namespaceSelector`).

## Future-hardening alternatives

The Story 1.9 implementation chose option (i) of the design space:
shared `emptyDir` volume + cooperating application. Two future-
hardening alternatives are documented but not implemented:

- **Option (ii) hostPath** mode: tail
  `/var/log/pods/<ns>_<pod>_<uid>/<container>/0.log` directly via a
  hostPath mount on the workload pod. Works for any application
  without cooperation but requires hostPath privilege on every
  workload pod.
- **MutatingAdmissionPolicy (CEL-based)** as an alternative to the
  webhook server, available in K8s 1.30+. Would remove the webhook
  Deployment and the TLS surface entirely, at the cost of expressing
  the JSON Patch in CEL.
