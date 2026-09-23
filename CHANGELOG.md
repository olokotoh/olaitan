# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Release-candidate tags are pre-releases: they do not move `latest`, and the
public API and Helm values may still change between them. `v1.0.0` is reserved
for the point at which the evaluation campaign has produced detection-latency
and false-positive numbers; see [Unreleased](#unreleased).

## [Unreleased]

> **Known gap.** Detection-latency (MTTD) and false-positive-rate numbers are
> not yet measured against a live cluster. The harness, scenarios,
> pre-registered analysis plan and reproducibility envelope are complete; the
> campaign that fills them in is outstanding. No performance figure in this
> repository should be cited until it is.

### Added

- **A kind cluster the Calico flow sensor can actually run against**
  (#140). `hack/install-calico-kind.sh` creates or reuses a kind cluster
  from `hack/kind-calico-config.yaml` (kindnetd off, pod CIDR
  10.244.0.0/16), installs the pinned Tigera operator and an Installation
  whose IPPool CIDR is substituted to match that pod CIDR, so Goldmane
  exists and pods get addresses the cluster routes. It waits for Goldmane
  with a bounded timeout and writes the Path B `calicoSensor.tls` values
  from the operator's CA bundle and client key pair. It reuses an existing
  cluster, which is the certificate-refresh path, refuses to reuse one
  that is not this config, and refuses to write over certificate material
  it did not create. **The client identity on this path is borrowed from
  Calico's own observability UI, so Goldmane cannot tell the two consumers
  apart: dev sandbox only, and CNI.md says why at length.**
  `tests/e2e/fixtures/calico-flow-traffic.yaml` supplies the real traffic
  Goldmane needs before it reports anything: a client Deployment opening a
  TCP connection to a Service ClusterIP once a second, which is what a
  Goldmane flow record is made of. A client that reaches nothing exits
  rather than looping silently. `docs/helm-values.md` now carries the
  whole `calicoSensor` block, all 26 values including the `connectRetry`
  and `publishRetry` knobs; it previously carried none of them.

- Repository hygiene for public use: `SECURITY.md` documenting the agent's
  blast radius and the LLM tier's prompt-injection threat model,
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue templates, and a README
  rewritten for operators rather than examiners.

### Changed

- **The containerd sensor works without root and can no longer take the
  collector down** (#138). With `containerdSensor.enabled=true` the
  collector joins the socket's group (`containerdSensor.socketGroup`,
  default 0) and stays UID 65532. A socket it cannot open is logged at
  ERROR and marks only the runtime source unhealthy; it used to crash-loop
  the collector, Falco ingestion included; a failed optional sensor is now
  restarted with capped backoff. Also fixed, for every adapter:
  `retry.Do` treated an attempt's own timeout (a dial or a 2s publish
  deadline) as cancellation and stopped retrying, so one slow NATS publish
  or a dial timeout silently ended the containerd sensor for the life of
  the pod.
- **The applog sidecar can reach NATS and is visible** (#139). The admission
  webhook injected sidecars with no `NATS_URL`, so every injected sidecar
  exited at start and no application log line ever reached EVENTS_RAW. The
  webhook now requires `OLAITAN_WEBHOOK_SIDECAR_NATS_URL` (the chart sets it
  to the release's NATS Service FQDN, or `endpoints.nats` when set) and passes
  it to each sidecar. Nothing observed the sidecars either, so a dead one was
  silent: each now publishes a 30s heartbeat on `olaitan.health.applog.<node>`, and
  the collector on the same node reports `olaitan_source_healthy{source="applog"}`,
  `olaitan_sensor_events_total{source="applog"}` and the new
  `olaitan_sensor_applog_sidecars{state}` gauge. Neither the webhook nor the
  sidecar could start in the first place: both ran a bare `olaitan`, which
  the distroless image cannot resolve (`executable file not found in $PATH`),
  so `applogSidecar.enabled=true` left the webhook crash-looping. Both now run
  `/olaitan`. A sidecar that has not logged yet reports starting from its
  very first heartbeat, not unhealthy; it says goodbye before its NATS
  connection closes, so a rollout no longer leaves its sidecars counted
  stale; and a sidecar whose every publish fails reports unhealthy instead
  of starting forever. A sidecar that exits on an error sends no goodbye, so a
  crash-looping sidecar is counted stale. With `applogSidecar.enabled=true`,
  the render now fails when any server in `endpoints.nats` is a short
  (unqualified) name such as `nats://nats:4222` or a loopback address such as
  `localhost`: the sidecar runs in the workload's namespace, where neither
  reaches NATS. It also fails when `endpoints.nats` carries credentials
  (`user:pass@` or `user@`), because the webhook would copy them as a plain
  env var into every workload pod; NATS authentication is tracked in Epic 14
  (#130). After upgrading, restart annotated workloads: pods injected by
  the older webhook keep the old sidecar until they are recreated.
- **Falco is ON in every test** (#106). All six e2e Makefile targets and
  four CI jobs installed with Falco switched off, on the claim that its eBPF
  probe could not load inside kind. That was false on any BTF kernel, and it
  meant the Falco path never ran under test. They now install with
  `values-kind.yaml`; a new e2e test requires the collector to report
  Falco healthy, and a helm-suite guard fails the build if a test path
  switches Falco off again.
- **A real attack now produces evidence on a default install** (#105). Until
  now the only thing that could start an investigation was two sensors
  agreeing about a pod, and the default install runs one (Falco), so a real
  in-pod attack never got past the raw event stream. A Falco alert at
  Warning or above on a pod now starts an investigation on its own, as a
  `rule_match` (Warning 50, Error 75, Critical 90, Alert/Emergency 95 on
  the OLT scale, so one alert of any priority moves a workload to
  SUSPICIOUS and never alone to RESTRICTED). Falco-triggered packages are
  evaluated by the OLT rules engine. Tunable with
  `correlator.falcoTriggerMinPriority` (`off`, or `warning` upward). Falco's
  fields are also projected onto the OLT canonical names (`process.exe`,
  `file.path`, `network.dst_ip` ...), so OLT rules can match real Falco
  events for the first time. Events with no pod are dropped and counted
  (`olaitan_correlator_host_events_dropped_total`) instead of logged as a
  WARN each. Excluded namespaces never open a Falco-triggered investigation.
  The kind overlay exempts kind's own container-creation mount hook from
  Falco's "Drop and execute new binary in container".
- **Falco pinned to 0.45.0-rc1 (chart 9.1.0), the first release that stays up
  on kernel 7.x** (#103). 0.43.1 and 0.44.x exit every few minutes there
  (falcosecurity/falco#3955, fixed by falcosecurity/libs#3086). Soaked on
  kernel 7.0 with 0 restarts. `hack/preflight.sh` now judges each node kernel
  against the pin (`hack/falco-support.env`) and prints BLOCKER for a pairing
  known to crash. Moves to 0.45.0 GA when it ships.
- **BREAKING: Falco alerts now reach the collector over HTTP, not gRPC** (#104).
  Falco 0.44.0 removed its gRPC output, and the Falco releases that stay up on
  kernel 7.x are all newer. Falco's `http_output` now POSTs each alert to the
  collector through the node-local `<release>-falco-ingest` Service, with a
  generated token (`secrets.falcoHttpToken`, stored as `falco-http-token` in
  the release Secret) in the URL path. Works for any release name and
  namespace; `falcoIngest.extraFrom` adds NetworkPolicy peers. `endpoints.falco` and
  `falcoSocketPermissions` are gone, and with them the collector's hostPath
  mount and the root socket-permission container. An operator running their
  own Falco points its `http_output.url` at the Service instead. Falco's
  periodic metrics snapshot is now the collector's Falco heartbeat. New
  metrics: `olaitan_sensor_falco_http_requests_total{code}`,
  `olaitan_sensor_falco_alerts_received_total`,
  `olaitan_sensor_falco_heartbeats_total`,
  `olaitan_sensor_falco_publish_drops_total`.

### Fixed

- **Rotating a chart-rendered TLS cert now restarts the pods that serve
  it** (#148). The applog injector and the audit receiver read their
  serving cert once, at start-up, so a `helm upgrade` that changed only
  the cert left them serving the old one; for the applog webhook
  (`failurePolicy: Ignore`) that meant pods admitted with no sidecar and
  no admission logged. The Calico adapter re-reads its files only on its next
  reconnect. The injector Deployment now carries
  `checksum/applog-tls` and the collector DaemonSet `checksum/audit-tls`
  and `checksum/cni-tls` (Calico Path B): the sha256 of the rendered
  Secret's data, so only a cert change rolls the pods, not a
  chart-version bump. Secrets the chart does not render (applog
  cert-manager Path A, `calicoSensor.tls.certManagerSecretName`) get no
  checksum; APPLOG.md and CNI.md say how those reload. APPLOG.md and
  AUDIT.md give the upgrade order for a CA change (old and new CA, then
  the new cert, then the new CA alone). Under applog
  `failurePolicy: Fail` that order is mandatory, because the injector's
  own pods pass through its webhook (#159). AUDIT.md also states the
  cost of the collector roll: a brief gap for every source on the node.

- **A cert-manager-issued certificate now works for the Calico flow
  sensor** (#140). Path A mounted the cert-manager Secret unchanged, but
  a `kubernetes.io/tls` Secret carries `tls.crt` and `tls.key` while the
  adapter opens `/etc/olaitan/cni/client.crt` and `client.key`, and a
  missing file there is terminal, so every Path A install CrashLooped
  the collector. The volume projects the cert-manager keys onto the
  names the adapter reads. All three source keys are values, not chart
  constants: `calicoSensor.tls.certManagerCertKey` (default `tls.crt`),
  `certManagerKeyKey` (default `tls.key`) and `certManagerCAKey` (default
  `ca.crt`), so a Secret that is not from cert-manager, which used to work
  because it was mounted unprojected, can still be mapped. Each is checked
  at render against the charset a Kubernetes Secret key can hold, so a bad
  name fails with a message naming the value instead of leaving the pod in
  `ContainerCreating`. Path B is unchanged.

- **The audit webhook can actually receive an event** (#137). Three
  defects meant the kube-apiserver never reached the receiver on a
  self-managed cluster, so `source_healthy{source="audit"}` was never 1.
  The audit Service selected the aggregator while the receiver listens in
  the collector DaemonSet; the kubeconfig hardcoded a cluster-DNS name the
  apiserver cannot resolve on the host network (`auditWebhook.serverAddress`
  and `auditWebhook.hostPort` now give it an address it can reach, both
  validated at render); and AUDIT.md signed the apiserver's client
  certificate with a private CA while pointing `clusterCAData` at the
  cluster CA, so mTLS failed. `hack/audit-webhook-certs.sh` issues both
  sides from one CA and writes a values file the chart accepts as is.
  `auditWebhook.hostIP` (default `127.0.0.1`) keeps the node port off the
  node's other interfaces, and the render fails when `serverAddress`,
  `hostPort` and `collector.runOnControlPlane` do not agree.

## [v1.0.0-rc3] - 2026-08-30

### Fixed

- The chart-publishing job in the release workflow now authenticates to cosign
  before signing, so chart signatures are produced rather than skipped (#95).

## [v1.0.0-rc2] - 2026-08-29

### Added

- **Release pipeline** (#94). Tagging `v*` now publishes a multi-arch
  (`linux/amd64`, `linux/arm64`) image to `ghcr.io/olokotoh/olaitan` and the
  Helm chart to `oci://ghcr.io/olokotoh/charts`, with a keyless cosign signature
  and an SPDX SBOM on the image. Chart signing was configured here but did not
  actually produce a signature until the cosign authentication fix in rc3, so
  the rc2 chart is unsigned. Installing no longer requires cloning or building.
- `:edge` image tag published on every green push to `main`.
- Version stamping: `olaitan version` reports the release tag rather than
  `dev`.

### Changed

- Pre-release tags (`-rc`, `-alpha`, `-beta`) are marked as pre-releases and
  do not move `latest`.

## [v1.0.0-rc1] - 2026-08-18

First tagged artefact, covering the work of Epics 1 through 7.

### Added

- **Five-source telemetry collection**: Falco eBPF syscalls, Kubernetes API
  audit webhook, CRI runtime events, Calico CNI flows via Goldmane, and
  application logs.
- **Three-tier detection**: an OLT-dialect Sigma rule engine with hot reload,
  Welford statistical baselines with restart-aware warm-up, and an optional
  multi-agent LLM analyst tier.
- **Trust-bounded LLM integration**: a trust ladder that caps the analyst
  tier's contribution to a workload's score, with the bound covered by a
  dedicated harness.
- **Graduated isolation state machine**: CLEAN, SUSPICIOUS, RESTRICTED,
  QUARANTINED, PRESERVED_KILLED, enforced through generated NetworkPolicies,
  with cooldown-gated de-escalation and operator override.
- **Helm chart** with pinned Falco, NATS and Redis subcharts, plus production,
  air-gapped and evaluation overlays.
- **Six Grafana dashboards** and an operator runbook covering ten scenarios.
- **Reproducible evaluation harness** (`cmd/olaitan-eval`), a pre-registered
  analysis plan, and an analysis pipeline.

[Unreleased]: https://github.com/olokotoh/olaitan/compare/v1.0.0-rc3...HEAD
[v1.0.0-rc3]: https://github.com/olokotoh/olaitan/compare/v1.0.0-rc2...v1.0.0-rc3
[v1.0.0-rc2]: https://github.com/olokotoh/olaitan/compare/v1.0.0-rc1...v1.0.0-rc2
[v1.0.0-rc1]: https://github.com/olokotoh/olaitan/tree/v1.0.0-rc1
