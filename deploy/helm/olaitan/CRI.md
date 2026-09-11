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

3. (Story 1.8 P27: no longer required.) Pre-P27 operators had to
   set the matching runtime knob in `config/olaitan.yaml` separately,
   in lockstep with the Helm flag. Post-P27 the chart's ConfigMap
   bridges every `containerdSensor.*` knob (`enabled`, `socketPath`,
   `dialTimeout`, `stalenessTimeout`, `connectRetry`, `publishRetry`)
   into the rendered `detection.sources.containerd` block, so a
   single `helm upgrade --set containerdSensor.foo=...` flips both
   the host-path mount (gating) and the adapter's runtime behaviour.
   Operators with a customised `config/olaitan.yaml` who prefer to
   author runtime knobs in YAML still can: the bridge is regex-based
   and only overrides keys whose chart value is set, so an unset
   chart value leaves the file's value as-is.

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

   Look for one `cri: stream connected` line per node after the
   sensor flips on. The adapter does NOT log a line per published
   event on the success path -- a quiet log between connects is the
   expected steady state. Drops are surfaced via two log lines plus
   the matching counters (`Adapter.TranslateErrors()` for malformed
   events, `Adapter.PublishDrops()` for permanent publish failures);
   Story 1.12 will bind those counters to Prometheus together with
   the `source_healthy{source="runtime"}` gauge so steady-state
   monitoring lives off metrics rather than log-grep.

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

  The default mode `0660` needs the connecting process to be root or
  in the socket's group. Since Story 10.9 the chart handles this without
  root: with `containerdSensor.enabled=true` the collector pod joins
  `containerdSensor.socketGroup` (default `0`, the group on stock
  containerd) as a supplemental group and keeps running as UID 65532.
  If your socket has a different group, set `socketGroup` to its GID
  (`stat -c %g /run/containerd/containerd.sock`). Verified on kind
  (containerd 2.x): the stream connects and pod creates arrive as
  runtime events.

- **`optional source stopped permanently ... source=runtime ... permission denied`.**
  The collector could not open the socket; the log names the path and
  points at `socketGroup`. Since Story 10.9 this marks the runtime
  source unhealthy (`olaitan_source_healthy{source="runtime"} 0`) but
  no longer crash-loops the collector: Falco and the other sources keep
  running. Before Story 10.9 the same condition silently stopped the
  sensor ten seconds after start (the dial timeout was mistaken for a
  shutdown).

- **`cri: stream eof` followed by reconnect.** Expected behaviour
  during containerd restarts. The outer reconnect loop backs off
  per the configured `connect_retry` strategy (defaults 1s..30s with
  full equal-jitter, unlimited attempts).

## Security boundary

Mounting `/run/containerd/containerd.sock` (via the parent directory)
into the agent pod gives the agent privileged access to the
container runtime. An auditor reviewing this chart must understand
that the host-path mount enables, at a minimum, the following CRI
operations against the local containerd:

- `RuntimeService.ListContainers` -- enumerate every container on
  the node, including those owned by other namespaces.
- `RuntimeService.ContainerStatus` / `PodSandboxStatus` -- read
  per-container state, including labels, env, and image references.
- `RuntimeService.ExecSync` and `Exec` -- run arbitrary commands
  inside any running container on the node. This is the load-
  bearing privilege: an attacker who reaches the agent pod can
  pivot into any workload on that node.
- `ImageService.PullImage` and `ListImages` -- pull arbitrary
  images and inspect the local image cache.
- `RuntimeService.RunPodSandbox` / `CreateContainer` /
  `StartContainer` -- launch new workloads on the node.

The mount is read-only at the pod-spec level (`readOnly: true` in
the volumeMount, see `templates/daemonset.yaml`) so the agent
cannot create or replace the socket file itself, but Unix-socket
RPC permissions are governed by the inode mode, not by the bind-
mount flag -- once any process inside the agent pod can `connect(2)`
to the socket, the full CRI surface above is reachable. The K8s
ecosystem has standardised on the Kyverno
`disallow-cri-sock-mount` policy as the upstream pattern for
flagging this mount class; clusters running Kyverno will need an
explicit exception for the Olaitan collector DaemonSet.

Since Story 10.2 this is the collector's ONLY host mount: Falco now
reaches the collector over HTTP, so the Falco socket mount that used
to sit alongside it is gone. Enabling the containerd sensor therefore
adds host access the default install does not have; weigh it as such. The Olaitan threat model
assumes an attacker who has compromised the agent pod has already
won the per-node game; cluster-level isolation (RBAC, NetworkPolicy,
audit subjects) is what limits blast radius from a node compromise.

If a future operator wants tighter isolation for Olaitan agents, the
answer is to deploy with `containerdSensor.enabled: false` (the
default) and lose FR3 functionality. There is no half-way mode in
containerd 1.7 (no read-only-CRI proxy).
