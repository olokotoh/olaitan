# containerd CRI Lifecycle Sensor

This document covers the operator workflow for enabling the containerd
CRI lifecycle adapter shipped in Story 1.8 (FR3).

## What it does

When enabled, every Olaitan collector pod (one per node) opens a gRPC
stream to the local containerd CRI runtime via
`RuntimeService.GetContainerEvents` and forwards every container
lifecycle event (created, started, stopped, deleted) onto the NATS
subject `olaitan.events.raw.runtime` with at-least-once semantics.

Downstream consumers:

- The OLT Sigma rule engine (Story 1.15) matches restart-frequency
  rules against the resulting event stream.
- The Welford baseline engine (Story 1.17) invalidates per-workload
  baselines when it observes a sandbox restart
  (`event_type:started` with `attempt:N` where `N > 0`, or
  `event_type:deleted` followed by `event_type:started` for the same
  pod sandbox UID).
- Future on-demand workload posture cache (Story 1.11) drops cache
  entries on pod-replacement events.

## Supported versions

| Component  | Supported   | Notes                                                                                  |
|------------|-------------|----------------------------------------------------------------------------------------|
| containerd | 1.7.x       | `GetContainerEvents` is GA in containerd 1.7's legacy CRI server (PR #7073).           |
| containerd | 2.0.x       | Should work but is outside the test scope of Story 1.8; report any drift via an issue. |
| containerd | < 1.7       | Not supported. The pre-1.7 CRI server lacks `GetContainerEvents` GA.                   |
| Kubernetes | 1.26+       | CRI v1 only. v1alpha2 was removed in 1.26 and is not negotiated.                       |
| Sandbox Server | not supported | containerd 1.7's experimental Sandbox Server lacks `GetContainerEvents` per upstream issue #7658. The default legacy CRI server path is what stock kubeadm 1.29 uses; this is the only path Olaitan targets. |

## How to enable

1. Confirm the host CRI socket path. On stock kubeadm 1.29 with
   containerd 1.7 the path is `/run/containerd/containerd.sock`. On
   k3s, microk8s, or custom containerd builds the path differs.

   ```sh
   sudo ls -l /run/containerd/containerd.sock
   ```

2. Set the chart value (default is disabled):

   ```yaml
   containerdSensor:
     enabled: true
     socketPath: /run/containerd/containerd.sock  # adjust if non-standard
   ```

3. Set the matching runtime knob in `config/olaitan.yaml` (the chart
   does NOT overlay Helm values onto the agent's runtime config -- the
   two flags must agree explicitly):

   ```yaml
   detection:
     sources:
       containerd:
         enabled: true
         socket_path: "/run/containerd/containerd.sock"
   ```

4. Re-render and apply the chart:

   ```sh
   make helm-prepare
   helm upgrade olaitan deploy/helm/olaitan --namespace olaitan -f my-values.yaml
   ```

5. Verify the source is healthy:

   ```sh
   kubectl logs -n olaitan -l app.kubernetes.io/component=collector \
     | grep "cri:"
   ```

   Look for `cri: stream connected` followed by per-event publish
   confirmations. Story 1.12 will surface a Prometheus
   `source_healthy{source="runtime"}` gauge for steady-state
   monitoring.

## Health semantics

CRI lifecycle events are sparse by design. A stable cluster with no
Pod churn can go hours without an event. The adapter's staleness
watchdog therefore differs from the Falco and audit-webhook
adapters: it only flips the source unhealthy when the gRPC
connection is NOT in the Ready state AND staleness exceeds the
configured timeout. "No events for an hour on a connected stream" is
considered healthy.

When the adapter loses the CRI connection (containerd restart,
operator removed the socket, network blip) the watchdog flips the
source unhealthy after the configured `staleness_timeout` (default
5m) and the outer reconnect loop continues with exponential backoff.

## Troubleshooting

- **Adapter never reaches `cri: stream connected`.** Check the host
  socket exists and is reachable from the pod:

  ```sh
  sudo ls -l /run/containerd/containerd.sock
  # Expected: srw-rw---- 1 root root ... /run/containerd/containerd.sock
  ```

  The default mode `0660` requires the agent pod to either run as
  root or share the socket's group. The current chart pod-spec runs
  the collector as UID 65532 (nonroot). Operators have two choices:

  1. Override the collector container's `securityContext.runAsUser`
     to 0 for the collector pod when the CRI sensor is enabled
     (acceptable per NFR14: the agent already needs root for eBPF
     probe loading via Falco). This is a chart override the operator
     applies via their values overlay.
  2. Change the socket's group ownership on each node and run the
     pod with that group.

  Future hardening: a follow-up story will add a chart-level
  `containerdSensor.runAsRoot` toggle that flips the relevant
  container's securityContext when enabled. For now, the default-
  disabled `containerdSensor.enabled` keeps existing nonroot deploys
  unaffected.

- **Adapter logs `permission denied`.** Same root cause as above;
  see the socket-mode discussion. The adapter treats EACCES as a
  terminal error (`retry.Permanent`) so the pod CrashLoops loudly
  rather than busy-looping.

- **`cri: stream eof` followed by reconnect.** Expected behaviour
  during containerd restarts. The outer reconnect loop backs off
  per the configured `connect_retry` strategy (defaults 1s..30s with
  full equal-jitter, unlimited attempts).

## Security boundary

Mounting `/run/containerd/containerd.sock` (via the parent directory)
into the agent pod gives the agent privileged access to the
container runtime. An attacker who escapes to the agent pod can
speak the full CRI to containerd: list containers, exec into any
container on the node, pull arbitrary images.

This is privilege equivalent to what Falco's `/run/falco/falco.sock`
mount already grants (Falco's Unix socket exposes equivalent
privilege through Falco's own grpc surface), so the threat model is
unchanged from the post-Story-1.6 baseline. The Olaitan threat model
assumes an attacker who has compromised the agent pod has already
won the per-node game; cluster-level isolation (RBAC, NetworkPolicy,
audit subjects) is what limits blast radius from a node compromise.

If a future operator wants tighter isolation for Olaitan agents, the
answer is to deploy with `containerdSensor.enabled: false` (the
default) and lose FR3 functionality. There is no half-way mode in
containerd 1.7 (no read-only-CRI proxy).
