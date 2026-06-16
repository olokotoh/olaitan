# Pre-built Grafana dashboards

Six importable Grafana dashboards for the Olaitan Prometheus surface
(`:9090/metrics`, FR50). An operator imports a dashboard JSON and gets an
immediate operational view without authoring panels by hand (Story 6.7).

## Dashboards

| File | Covers | Stories |
|------|--------|---------|
| `dashboards/01-source-health.json` | Per-source health, ingest rates, sampling, per-adapter loss, posture cache. | 1.7-1.13 |
| `dashboards/02-detection.json` | Rule matches, baseline deviations, the per-technique view, correlator throughput, ThreatScore contributions. | 1.15-1.18, 2.1 |
| `dashboards/03-fsm-state.json` | FSM state distribution, transition rate, dwell histograms, operator overrides, NetworkPolicy enforcement. | 2.2-2.9 |
| `dashboards/04-llm-tier.json` | Provider health, per-role latency, fallback rate, cap violations, prompt versions, circuit breaker. | 3.2-3.15 |
| `dashboards/05-forensics.json` | DFIR generation rate, S3 write latency, deferred-queue depth, settling windows, forensic capture, webhook delivery. | 4.2-4.9 |
| `dashboards/06-overview.json` | High-level cross-cutting view, one panel per pillar. | all |

## Pinned Grafana version (AC3)

Every dashboard pins `schemaVersion: 39`, which corresponds to **Grafana
11.1.x**. Grafana 11.x is the last release line that uses the classic
dashboard JSON model (the panel-array + `gridPos` layout these files use);
Grafana 12 introduced a reworked dashboard schema. Pinning 39 keeps the
committed JSON the stable source of truth: a panel change regenerates and
re-commits the JSON at the same schemaVersion, and the CI guard (below)
rejects any drift from the pin.

If you run a newer Grafana, the import wizard migrates the schema forward on
load; the committed file stays at 39 so it imports cleanly into 11.1.x and
upgrades deterministically.

## Importing

Each dashboard declares a templated `${DS_PROMETHEUS}` datasource (no
hard-coded datasource UID), so the import prompts you to pick your Prometheus
datasource.

1. In Grafana, go to **Dashboards -> New -> Import**.
2. Upload one of the `dashboards/*.json` files (or paste its contents).
3. When prompted, select the Prometheus datasource that scrapes the Olaitan
   `:9090/metrics` surface.
4. Repeat per dashboard. Each carries a stable `uid` (for example
   `olaitan-source-health`), so a re-import updates the existing dashboard
   rather than creating a duplicate.

The dashboards are not wired into the Helm chart; they are imported manually.
A future story could mount them as a sidecar-provisioned ConfigMap.

## Panel grounding and the CI guard (AC2)

Every panel PromQL expression references a metric the agent actually exports.
The canonical metric reference is `docs/metrics.md` (forensic tier) plus
`docs/runbook.md` Section 1 (collector, correlator, rule, baseline, score,
FSM, override, NetworkPolicy, and LLM metric catalogue), which in turn match
the registrations in `internal/` and `cmd/`.

This grounding is mechanically enforced. `cmd/olaitan-dashboard-lint` (run via
`make dashboard-lint` and as an always-on CI step) asserts that:

- every `dashboards/*.json` parses as valid JSON and carries the pinned
  `schemaVersion` (39); and
- every metric name in any panel `targets[].expr` (and in any
  `templating.list[].query`/`.definition`) exists in the canonical metric set
  **derived from the code**, minus the Story 4.9 retired names.

The canonical set is derived by parsing `internal/` and `cmd/` with `go/ast`
and collecting only `olaitan_*` names that reach a real Prometheus
registration site (a `prometheus.*Opts{Name: ...}` field, an argument to a
`Register*`/`register*` registrar call, or a metric-table struct literal),
resolving name-constants to their literal value. `*_test.go` files are
excluded, so a name that exists only in a negative test, a test fixture, a doc
comment, or a YAML/JSON struct tag is **not** treated as a real metric and a
dashboard that references it fails the build. Since the set is derived from the
registration sites, adding a real metric auto-allows a panel for it and a
fabricated metric name is rejected.

## Sampling

Source sampling under load is not a separate metric family. When a source sheds
ingest under backpressure, that is surfaced as the application-log line-shed
rate (`olaitan_sensor_applog_lines_shed_total`), shown in the **sampling /
line-shed** panel of `01-source-health`. Read a non-zero shed rate there as the
"sampling is active" signal.

## Alerting (AC2)

The dashboards ship Grafana **color `thresholds` steps** (the green/red bands
that mark alert-worthy values), **not** embedded Grafana alert RULES: there are
zero `alert` blocks in the dashboard JSON. This is intentional. Grafana 11
moved alerting to **unified alerting**, where alert rules are a separate
resource (their own provisioning files / API objects) and are no longer carried
inside the dashboard panel JSON. The color `thresholds` steps therefore mark
the alert-worthy bands, and `docs/runbook.md` documents those bands as the
alert predicates (for example, "page on any non-zero cap-violation"). Operators
wire the actual alert rules via Grafana unified alerting (or Prometheus
alerting rules) using the predicates the runbook lists; the dashboards give the
visual thresholds, the runbook gives the alert definitions.

## Honest metric note: the per-technique "heatmap"

There is **no** dedicated per-technique heatmap metric. The detection
dashboard's per-technique panel is grounded in the real `attack_technique`
label of `olaitan_decision_rules_matches_by_attribute_total` (a MITRE ATT&CK
technique ID, rendered as `sum by (attack_technique)(rate(...))`). Rules
carrying no MitreTags appear under the `unknown` series. This is the honest
closest real surface, not a fabricated metric.
