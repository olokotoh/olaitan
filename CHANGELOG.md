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

- **`make up` / `make down`** (Story 12.3, #120). `make up` checks the host
  first (tools, Docker, BTF, the Falco pin against the kernel, inotify
  limits, PyYAML when the node list is trimmed, an existing cluster) and
  stops with the exact fix for every blocker before anything is created.
  Then it brings up kind-full with the full profile and Falco on, reads
  `/etc/shadow` in a throwaway pod, and prints the aggregator's first
  decision about it with the time since `make up` started (non-zero exit
  over 900 s, `UP_BUDGET`). `make down` removes the cluster, node
  containers, kind kubeconfig entries, `$(FULL_OUT_DIR)` and
  `hack/.audit-full`, then checks nothing is left.
- **`make quickstart`** (Story 12.2, #119). From a clone: a fresh kind
  cluster, the published chart with Falco on, a real `cat /etc/shadow` in a
  throwaway pod in a scored namespace, and the agent's first decision about
  that pod, printed with the time since `kind create cluster` (non-zero exit
  over ten minutes). Nothing is published to NATS; the transition is read
  from the aggregator's log. `make quickstart-clean` deletes the cluster.
  It checks that the chart version is published before it creates the
  cluster. `QUICKSTART_CHART=local` (and `QUICKSTART_IMAGE`) use the
  checkout instead.

- **Stranger-path check on every release and nightly** (Story 12.5, #122).
  `.github/workflows/stranger.yml` runs `hack/stranger.sh`, which reads
  README.md when it runs and executes its install block as written, on a
  fresh kind cluster (kind v0.30.0, current helm, inotify raised): the helm
  path ("Try it on kind") and the kubectl path (`## Install`, the
  `install.yaml` commands; skipped only for v1.0.0-rc4 and earlier, which
  have no `install.yaml`). It then requires every workload rolled out,
  every pod Ready with a Falco pod among them, and, after a real
  `cat /etc/shadow` in a throwaway pod, both a Falco alert on that read and
  an FSM transition for its namespace. Nothing is injected. It runs nightly
  on main's README, by hand, on PRs that change it, and from `release.yml`
  on every tag (the tagged commit), after the GitHub Release exists. If it
  fails, is cancelled or times out there, the run fails, `latest` does not
  move, and the release is marked failed (pre-release, title and a banner
  linking the run); marking twice leaves one banner, and a green rerun
  takes the mark off without clearing a real pre-release. Only a banner at
  the start of a line counts as a mark, CRLF notes from the web UI are
  handled, a banner a human edited falls back to the preflight pre-release
  value, and notes with a begin marker but no end marker are left unchanged
  and fail the job with an error. The release job sets the title (the tag)
  explicitly and `unmark-failed` strips a FAILED title even when the notes
  carry no banner, so "Re-run all jobs" after a mark cannot leave a
  FAILED-titled release to become Latest. The GitHub
  Release is created without "Latest" and becomes Latest only in `promote`,
  after the check passed and only for the highest stable tag. Every failure
  names its phase (readme, install, infra: cluster / rollout / pull / exec /
  kubectl logs, product: no Falco alert / no FSM transition) in the log, as
  an annotation and in the job summary, and kubectl errors are kept.

- **`install.yaml` on every release** (Story 12.4, #121). The release
  workflow renders the chart it publishes, with default values, into one
  file for `kubectl apply -f`, checks that it runs the released image by
  digest and holds no generated credential, adds it to `checksums.txt` and
  attaches it to the GitHub release. The file creates the `olaitan`
  namespace, namespaces the NATS objects (the subchart renders none) and
  leaves out the NATS `helm test` Pod and the chart's Secret
  `olaitan-secrets`: a published file would give every install the same
  Redis password and Falco token (D5). The install is two steps: create the
  namespace and `olaitan-secrets` with fresh random values, then apply the
  file. The README covers upgrading (apply, then `kubectl rollout restart`;
  the apply never touches the Secret), rotating the two values, and the API
  server NetworkPolicy rule, which names `10.96.0.1` because a rendered file
  cannot look the address up (k3s, minikube, Calico and Cilium need the
  `kubectl patch` it gives). `hack/render-install-manifest.sh` does the
  rendering; the helm test suite runs it on every CI run. v1.0.0-rc4
  predates this and has no `install.yaml`. Deferred review items: #180.

## [v1.0.0-rc4] - 2026-09-24

The first release since rc3 that installs with the README command and no
flags. On rc3 that command failed (#96 and the Falco driver, below); rc4 was
verified before release on a fresh single-node kind with the chart packaged
the way the release packages it. The verification output is in PR #174.

### Added

- **The Helm chart installs with no flags on a fresh cluster** (Epic 9).
  `helm install olaitan oci://ghcr.io/olokotoh/charts/olaitan --version
  1.0.0-rc4 --namespace olaitan --create-namespace` needs no values: the
  bundled Redis gets a generated password (an explicit
  `secrets.redisPassword` still wins, and an upgrade reuses the existing
  one), the tree chart's image defaults to `edge` instead of a tag that was
  never published, and the default JetStream sizing fits the default NATS
  volume (see Fixed, #96).
- **`hack/preflight.sh`** (Story 9.1). Probes storage, privileged-workload
  admission, NetworkPolicy enforcement, each optional source and the node
  kernel against the pinned Falco, and prints `yes` / `no` / `BLOCKER` with
  the flag that fixes each. It changes nothing. NOTES.txt reports the same
  from inside the release after install.
- **Per-platform overlays** (Story 9.4): `values-kind.yaml`,
  `values-minikube.yaml`, `values-k3s.yaml`, `values-eks.yaml`,
  `values-aks.yaml`, `values-gke.yaml`, `values-openshift.yaml`, each
  carrying only that platform's deltas, and the OpenShift SCC binding
  shipped in the chart. `docs/platform-support-matrix.md` separates
  `verified` (installed and observed) from `template-verified` (renders
  only).
- **kind-full, one profile where all five sources run at once** (Story
  10.5): `hack/kind-full.yaml`, `values-full.yaml` and
  `hack/install-full-kind.sh`, on Calico so NetworkPolicy is enforced.
  `make e2e-full` runs it.
- **The full profile runs a real LLM tier with no API key** (Story 10.6):
  an in-cluster Ollama with `qwen2.5:3b-instruct`, image pinned by digest,
  model pulled by a Job under its own NetworkPolicy.
  `values-llm-deepseek.yaml` and `values-llm-claude.yaml` switch to a
  hosted model with the key in a Secret you create. On CPU the in-cluster
  model takes 15 to 30 minutes per incident; the README says so.
- **A NATS outage no longer loses Falco alerts** (#135). Falco's
  `http_output` does not retry a failed POST, and the collector used to
  publish inside the request and answer `503` after about 9s of NATS
  refusing, so every alert raised during a NATS restart was gone. The
  collector now answers once the alert is in a bounded in-memory queue
  (`falcoIngest.buffer.maxAlerts`, default 4096, and
  `falcoIngest.buffer.maxBytes`, default 16 MiB of marshalled events, per
  collector pod) and one worker publishes it to EVENTS_RAW in order,
  retrying with backoff until NATS takes it. When the queue is full the
  oldest alerts are dropped and counted in
  `olaitan_sensor_falco_buffer_dropped_total`; `olaitan_sensor_falco_buffer_depth`
  and `olaitan_sensor_falco_buffer_bytes` show what is waiting. Shutdown
  stops listening, drains for up to 10s and logs what it could not publish.
  `503` from the Falco ingest now means only "shutting down". The queue is
  in memory, so a collector crash still loses what it holds.

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

- **Every image is pinned by tag and digest** (#123, Story 12.6), guarded
  in CI, and the release stamps the Olaitan image's own digest into the
  published chart. **Redis is no longer the Bitnami subchart**: Bitnami
  stopped publishing versioned free `bitnami/redis` tags, so the chart now
  runs its own Redis on the official `redis` image, keeping the Bitnami
  resource names, labels and volume claim so an existing release upgrades
  in place and keeps its data. Upgrading across this change: do not use
  `--reuse-values` (use `--reset-then-reuse-values`), and move any
  `redis.master.*` or `global.storageClass` values to the keys the render
  error names. The runbook has the full key map.
- Dependencies bumped for CVEs: `golang.org/x/crypto` (CVE-2026-56854,
  CRITICAL) and `google.golang.org/grpc` 1.83.2.

### Fixed

- **The default install can create its JetStream streams** (#96). The
  aggregator declared 160 GiB of stream retention against the 10 Gi NATS
  volume the chart ships, and JetStream reserves up front, so a default
  install crash-looped with `err_code=10047 insufficient storage resources
  available`. `nats.streamMaxBytesOverride` now defaults to 512 MiB per
  stream (13 streams, 6.5 GiB), and a helm test reads the rendered cap, the
  NATS `max_file_store` and volume claim and the stream list from the code,
  and fails if the sum no longer fits. Running real retention means raising
  `nats.config.jetstream.fileStore.pvc.size` and clearing the override
  together. The install notes used to name `nats.persistence.size`, which the
  bundled NATS chart ignores; they now name the key that moves both the store
  and the claim, and a helm test checks that it does. Only EVENTS, EVENTS_RAW
  and EVIDENCE have production caps of their own, so with the override
  cleared the other ten streams are unbounded; size the volume for that.
- **Every printed install command pins the chart version.** The closing hint
  of `hack/preflight.sh` and the platform overlay headers ran
  `helm install oci://...` with no `--version`, which resolves nothing while
  the registry holds only release candidates. They now carry the version, a
  helm test ties every one of them to Chart.yaml, and the release refuses a
  tag that is not Chart.yaml's version.
- **The collector can reach Falco on clusters where the two run as
  different users** (Story 9.6), found on a 3-node kubeadm cluster where the
  primary source was dead while every pod looked healthy. Superseded in
  this release by the HTTP ingest (#104), which needs no shared socket.
- **`hack/check-netpol-enforcement.sh` reported "NOT ENFORCED" on every
  cluster**, including ones that enforce, because it matched the wrong
  timeout text. It now matches every refusal form and self-tests its
  matcher first.
- **The report archive works without forensics** (#149, Story 10.7): its S3
  credentials followed `forensics.enabled` alone.
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

[Unreleased]: https://github.com/olokotoh/olaitan/compare/v1.0.0-rc4...HEAD
[v1.0.0-rc4]: https://github.com/olokotoh/olaitan/compare/v1.0.0-rc3...v1.0.0-rc4
[v1.0.0-rc3]: https://github.com/olokotoh/olaitan/compare/v1.0.0-rc2...v1.0.0-rc3
[v1.0.0-rc2]: https://github.com/olokotoh/olaitan/compare/v1.0.0-rc1...v1.0.0-rc2
[v1.0.0-rc1]: https://github.com/olokotoh/olaitan/tree/v1.0.0-rc1
