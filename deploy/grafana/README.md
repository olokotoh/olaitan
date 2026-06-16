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
- every metric name in any panel `targets[].expr` exists in the canonical
  metric set **derived from the code** (the `olaitan_*` literals registered
  across `internal/` and `cmd/`), minus the Story 4.9 retired names.

A dashboard that references a non-existent or retired metric fails the build.
Since the canonical set is derived from the code, adding a real metric
auto-allows a panel for it and a fabricated metric name is rejected.

## Honest metric note: the per-technique "heatmap"

There is **no** dedicated per-technique heatmap metric. The detection
dashboard's per-technique panel is grounded in the real `attack_technique`
label of `olaitan_decision_rules_matches_by_attribute_total` (a MITRE ATT&CK
technique ID, rendered as `sum by (attack_technique)(rate(...))`). Rules
carrying no MitreTags appear under the `unknown` series. This is the honest
closest real surface, not a fabricated metric.
