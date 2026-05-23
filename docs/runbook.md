# Olaitan operator runbook

Scope: this runbook is the operator-facing reference for the Olaitan deterministic-detection layer. Story 1.18 lays down **Section 1 only** (the metric catalogue). Sections 2 through 10 cover the ten common operational scenarios from NFR34 (incident triage, false-positive tuning, rule corpus management, baseline reset, etc.) and are filled in by Story 6.8.

Audience: SREs, on-call engineers, and SOC analysts consuming the Prometheus surface at `:9090/metrics`. The runbook assumes familiarity with PromQL, Kubernetes, and the Olaitan three-ring (collector, correlator, decision) architecture described in `docs/architecture.md`.

References: FR50 (Prometheus surface mandatory), NFR32 (every metric documented with type, unit, label set), NFR34 (operator runbook covers 10 scenarios), NFR42 (traceability matrix update required per PR).

---

## Section 1. Deterministic-detection metric catalogue

This section enumerates every metric registered by the deterministic-detection layer (the collector, correlator, rule engine, and baseline engine rings). Each entry carries six fields: name, type, unit, label set with cardinality envelope, the Help string copied verbatim from the registration, and two sample PromQL queries (one aggregate for normal-operations dashboards, one alerting predicate for the troubleshooting case).

The catalogue is organised by registering ring + story, in commit chronology so the reader can correlate names with the introducing PR.

### 1.1 Collector ring (Story 1.12)

#### `olaitan_source_healthy`

- **Type:** gauge
- **Unit:** dimensionless (1.0 = healthy, 0.0 = stalled)
- **Labels:** `source` (one of `falco`, `audit`, `runtime`, `network`, `applog`; cardinality 5)
- **Help:** Binary health gauge for an Olaitan sensor source; 1.0 means the upstream stream is producing events, 0.0 means it is disconnected or stalled (FR8).
- **Sample PromQL (aggregate):** `min(olaitan_source_healthy) by (source)` (per-source health rollup for the operations dashboard).
- **Sample PromQL (alert):** `min(olaitan_source_healthy) by (source) == 0` for 5 minutes (page on a sustained source outage).

#### `olaitan_sensor_events_total`

- **Type:** counter
- **Unit:** count
- **Labels:** `source` (cardinality 5)
- **Help:** Cumulative count of normalised events the sensor adapter has successfully published to NATS JetStream (FR50).
- **Sample PromQL (aggregate):** `sum(rate(olaitan_sensor_events_total[5m])) by (source)` (per-source ingest rate).
- **Sample PromQL (alert):** `rate(olaitan_sensor_events_total{source="audit"}[5m]) < 0.01` for 10 minutes (page when audit ingest collapses).

#### `olaitan_sensor_posture_cache_hit_total` through `olaitan_sensor_posture_unavailable_total`

- **Type:** counter (six metrics under this prefix)
- **Unit:** count
- **Labels:** none
- **Help:** Cumulative posture-client outcome counters (Story 1.11). One metric per outcome: `cache_hit_total`, `cache_miss_total`, `cache_bypass_total`, `api_errors_total`, `orphan_pods_total`, `unavailable_total`.
- **Sample PromQL (aggregate):** `rate(olaitan_sensor_posture_cache_hit_total[5m]) / (rate(olaitan_sensor_posture_cache_hit_total[5m]) + rate(olaitan_sensor_posture_cache_miss_total[5m]))` (cache hit ratio).
- **Sample PromQL (alert):** `rate(olaitan_sensor_posture_api_errors_total[5m]) > 0.1` for 5 minutes (page on sustained K8s API error rate).

#### `olaitan_sensor_posture_disabled`

- **Type:** gauge
- **Unit:** dimensionless (constant 1.0 when set)
- **Labels:** none
- **Help:** Set to 1.0 when posture.enabled=false; the six olaitan_sensor_posture_*_total counters are not registered in this case.
- **Sample PromQL (aggregate):** `olaitan_sensor_posture_disabled` (presence indicator on dashboards).

### 1.2 Correlator ring (Story 1.18 NEW)

#### `olaitan_correlator_evidence_packages_total`

- **Type:** counter_vec
- **Unit:** count
- **Labels:** `trigger_type` (one of `multi_signal`, `rule_match`, `baseline_deviation`; cardinality 3)
- **Help:** Cumulative EvidencePackage publish attempts grouped by trigger type. Label values are the three trigger.TypeMultiSignal/TypeRuleMatch/TypeBaselineDeviation constants (multi_signal, rule_match, baseline_deviation).
- **Sample PromQL (aggregate):** `sum(rate(olaitan_correlator_evidence_packages_total[5m])) by (trigger_type)` (per-trigger-type publish rate).
- **Sample PromQL (alert):** `rate(olaitan_correlator_evidence_packages_total{trigger_type="multi_signal"}[15m]) > 10` for 5 minutes (page on multi-signal storm suggesting a noisy adapter).

#### `olaitan_correlator_window_size_bytes`

- **Type:** histogram
- **Unit:** bytes
- **Labels:** none (buckets `[1024, 4096, 8192, 16384, 32768, 65536, 131072, 262144]`)
- **Help:** On-wire size in bytes of the EvidencePackage at publish time (post-overflow-summarisation). Buckets cover the assembler.DefaultMaxPackageBytes 128 KiB cap; observations above 131072 indicate the cap-enforcement path was bypassed or failed.
- **Sample PromQL (aggregate):** `histogram_quantile(0.99, sum(rate(olaitan_correlator_window_size_bytes_bucket[5m])) by (le))` (p99 publish size).
- **Sample PromQL (alert):** `histogram_quantile(0.99, sum(rate(olaitan_correlator_window_size_bytes_bucket[5m])) by (le)) > 131072` for 5 minutes (page on the 128 KiB cap being bypassed).

#### `olaitan_correlator_overflow_summarised_total`

- **Type:** counter
- **Unit:** count
- **Labels:** none
- **Help:** Cumulative EvidencePackages whose Events slice was reduced by the assembler size-cap enforcement path (pkg.Overflow non-nil). Increment is one per publish, not per dropped event; for per-event accounting see pkg.Overflow.DroppedEventCount carried inline on the package.
- **Sample PromQL (aggregate):** `rate(olaitan_correlator_overflow_summarised_total[15m])` (overflow rate).
- **Sample PromQL (alert):** `rate(olaitan_correlator_overflow_summarised_total[15m]) > 0.05` for 30 minutes (page on sustained overflow rate suggesting an over-broad rule fan-out or a noisy adapter).

### 1.3 Rule engine ring (Stories 1.15, 1.18)

#### `olaitan_decision_rules_loaded`

- **Type:** gauge
- **Unit:** count
- **Labels:** none
- **Help:** Current count of OLT Sigma rules in the active corpus; refreshed on every hot-reload (FR15).
- **Sample PromQL (aggregate):** `olaitan_decision_rules_loaded` (corpus size on the dashboard).
- **Sample PromQL (alert):** `olaitan_decision_rules_loaded == 0` for 5 minutes (page on an empty corpus; either the ConfigMap was unmounted or every rule failed validation).

#### `olaitan_decision_rules_evaluations_total`

- **Type:** counter
- **Unit:** count
- **Labels:** `outcome` (one of `match`, `miss`, `error`; cardinality 3)
- **Help:** Per-package rule-evaluation outcome counter (FR50). One outcome per handled package: match (>=1 rule fired and every fan-out emit succeeded), miss (no rules fired), or error (package decode failed or any per-match emit failed). For per-match cardinality see olaitan_decision_rules_matches_total.
- **Sample PromQL (aggregate):** `sum(rate(olaitan_decision_rules_evaluations_total[5m])) by (outcome)` (per-outcome rate).
- **Sample PromQL (alert):** `rate(olaitan_decision_rules_evaluations_total{outcome="error"}[5m]) > 0.1` for 5 minutes (page on sustained emit-failure rate).

#### `olaitan_decision_rules_matches_total`

- **Type:** counter
- **Unit:** count
- **Labels:** none (aggregate per-package counter)
- **Help:** Cumulative rule matches emitted by the engine; increments by the number of matches per handled package (per-match cardinality, complementing the per-package evaluations_total{outcome=match}).
- **Sample PromQL (aggregate):** `rate(olaitan_decision_rules_matches_total[5m])` (overall match rate).

#### `olaitan_decision_rules_matches_by_attribute_total` (Story 1.18 NEW)

- **Type:** counter_vec
- **Unit:** count
- **Labels:** `rule_id` (bounded by corpus size; ~50 at FYP scale), `severity_bucket` (one of `low`, `medium`, `high`, `critical`; cardinality 4), `attack_technique` (MITRE ATT&CK technique ID, bounded by ATT&CK for Containers; ~30 leaf techniques as of ATT&CK v18, plus the sentinel `unknown` for empty MitreTags)
- **Help:** Per-(rule_id, severity_bucket, attack_technique) rule-match counter (AC2 of Story 1.18). Complements the unlabelled olaitan_decision_rules_matches_total: `sum without (rule_id, severity_bucket, attack_technique)(rate(matches_by_attribute_total[5m]))` reproduces the aggregate. A rule carrying N MitreTags increments this counter N times (one per technique); a rule with empty MitreTags emits one bump with `attack_technique="unknown"`.
- **Sample PromQL (aggregate):** `topk(10, sum(rate(olaitan_decision_rules_matches_by_attribute_total[1h])) by (rule_id))` (top-10 most-firing rules).
- **Sample PromQL (alert):** `rate(olaitan_decision_rules_matches_by_attribute_total{severity_bucket="critical"}[5m]) > 0.1` for 5 minutes (page on sustained critical-severity rule-match rate).

#### `olaitan_decision_rules_reloads_total`

- **Type:** counter
- **Unit:** count
- **Labels:** `outcome` (one of `success`, `rejected`; cardinality 2)
- **Help:** Cumulative rule-corpus reload attempts grouped by outcome (FR49).
- **Sample PromQL (aggregate):** `rate(olaitan_decision_rules_reloads_total[1h])` (reload activity).
- **Sample PromQL (alert):** `rate(olaitan_decision_rules_reloads_total{outcome="rejected"}[1h]) > 0` for 1 hour (page on sustained reload rejections; the corpus is being edited but never accepted).

#### `olaitan_decision_rules_skipped_self_total`

- **Type:** counter
- **Unit:** count
- **Labels:** none
- **Help:** Cumulative inbound packages skipped because their trigger type was rule_match (re-entrancy guard).
- **Sample PromQL (aggregate):** `rate(olaitan_decision_rules_skipped_self_total[1h])` (re-entrancy activity; expected to be near zero in steady state).

#### `olaitan_decision_rules_evaluation_seconds`

- **Type:** histogram
- **Unit:** seconds
- **Labels:** none (buckets `[0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250]`, NFR3-sized)
- **Help:** Per-package rule-engine evaluation latency in seconds; histogram buckets are sized against NFR3 (p99 <= 100 ms).
- **Sample PromQL (aggregate):** `histogram_quantile(0.99, sum(rate(olaitan_decision_rules_evaluation_seconds_bucket[5m])) by (le))` (p99 evaluation latency).
- **Sample PromQL (alert):** `histogram_quantile(0.99, sum(rate(olaitan_decision_rules_evaluation_seconds_bucket[5m])) by (le)) > 0.1` for 5 minutes (page on NFR3 budget breach).

### 1.4 Baseline engine ring (Stories 1.17, 1.18)

#### `olaitan_decision_baseline_evaluations_total`

- **Type:** counter
- **Unit:** count
- **Labels:** `outcome` (one of `deviation`, `normal`, `error`; cardinality 3)
- **Help:** Per-package baseline-evaluation outcome counter. One outcome per handled package: deviation (>=1 metric crossed sigma and every emit succeeded), normal (no metric crossed sigma), error (decode failed or any per-metric emit failed). For per-metric cardinality see olaitan_decision_baseline_deviations_total.
- **Sample PromQL (aggregate):** `sum(rate(olaitan_decision_baseline_evaluations_total[5m])) by (outcome)`.
- **Sample PromQL (alert):** `rate(olaitan_decision_baseline_evaluations_total{outcome="error"}[5m]) > 0.1` for 5 minutes.

#### `olaitan_decision_baseline_deviations_total` (Story 1.18 LABEL ADDED)

- **Type:** counter_vec
- **Unit:** count
- **Labels:** `metric` (one of the five default extractors: `outbound_unique_dst_ips`, `distinct_exec_paths`, `outbound_bytes`, `audit_events_per_min`, `container_restarts_per_hour`; cardinality 5), `sigma_bucket` (one of `3-5`, `>=5`, `>=10`; cardinality 3)
- **Help:** Per-(metric, sigma_bucket) baseline-deviation counter. Story 1.17 introduced the unlabelled-per-metric form; Story 1.18 AC3 adds the sigma_bucket label (one of "3-5", ">=5", ">=10"). Complements per-package evaluations_total{outcome=deviation}.
- **Sample PromQL (aggregate):** `sum(rate(olaitan_decision_baseline_deviations_total[5m])) by (metric, sigma_bucket)`.
- **Sample PromQL (alert):** `rate(olaitan_decision_baseline_deviations_total{sigma_bucket=">=10"}[5m]) > 0.05` for 10 minutes (page on sustained >=10 sigma deviation rate suggesting an unusual workload pattern).

#### `olaitan_decision_baseline_skipped_self_total`

- **Type:** counter
- **Unit:** count
- **Labels:** none
- **Help:** Cumulative inbound packages skipped because their trigger type was baseline_deviation (re-entrancy guard).
- **Sample PromQL (aggregate):** `rate(olaitan_decision_baseline_skipped_self_total[1h])`.

#### `olaitan_decision_baseline_warmup_active`

- **Type:** gauge
- **Unit:** count
- **Labels:** none (per BI-2 of Story 1.18; `architecture.md:476` forbids the `{workload}` label suggested by AC3's literal text because workload-keyed labels have unbounded cardinality)
- **Help:** Count of workloads currently within an active warm-up window (FR18). Sampled from the Warmup controller cache; cardinality bounded by the workload set under the controller's reach.
- **Sample PromQL (aggregate):** `olaitan_decision_baseline_warmup_active`.
- **Per-workload telemetry:** the per-workload warm-up detail (which specific workloads are in warm-up at any given moment) is surfaced through the `AUDIT.transitions` subject documented in `architecture.md:380`, not through Prometheus. SIEM-side consumers subscribe to the audit subjects when they need pod-level granularity.

#### `olaitan_decision_baseline_evaluation_seconds`

- **Type:** histogram
- **Unit:** seconds
- **Labels:** none (buckets `[0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250]`, NFR3-sized)
- **Help:** Per-package baseline-engine evaluation latency in seconds; histogram buckets are sized against NFR3 (p99 <= 100 ms).
- **Sample PromQL (aggregate):** `histogram_quantile(0.99, sum(rate(olaitan_decision_baseline_evaluation_seconds_bucket[5m])) by (le))`.
- **Sample PromQL (alert):** `histogram_quantile(0.99, sum(rate(olaitan_decision_baseline_evaluation_seconds_bucket[5m])) by (le)) > 0.1` for 5 minutes.

### 1.5 Naming-convention reconciliation

The Story 1.18 acceptance criteria text uses a mix of singular-ring and plural-ring metric names (e.g. AC2 says `olaitan_decision_rule_matches_total` singular; AC3 says `olaitan_decision_baseline_deviations_total{metric, sigma_bucket}` plural). The actual registrations follow `architecture.md:472-475` which mandates the `olaitan_<ring>_<metric>` pattern with the engine subfamily conventionally plural (`rules`, `baseline`) because the engine evaluates a corpus, not a single rule. The AC singular spellings are documentation aliases, not parallel families.

Reconciliation table:

| AC text | Actual registration |
|---|---|
| `olaitan_decision_rule_matches_total{rule_id, severity_bucket, attack_technique}` | `olaitan_decision_rules_matches_by_attribute_total{rule_id, severity_bucket, attack_technique}` (Story 1.18 NEW; label set is the load-bearing requirement) |
| `olaitan_decision_rule_eval_duration_seconds` | `olaitan_decision_rules_evaluation_seconds` (existing Story 1.15 registration) |
| `olaitan_decision_rule_corpus_size` | `olaitan_decision_rules_loaded` (existing Story 1.15 registration) |
| `olaitan_decision_baseline_warmup_active{workload}` | `olaitan_decision_baseline_warmup_active` (no `{workload}` label per BI-2; cardinality envelope) |
| `olaitan_decision_baseline_eval_duration_seconds` | `olaitan_decision_baseline_evaluation_seconds` (existing Story 1.17 registration) |
| `olaitan_correlator_overflow_summarised_total` | matches verbatim (NEW in Story 1.18) |

The `architecture.md:472-475` ring naming convention wins by explicit prior rule whenever the AC text drifts from it.

### 1.6 Traceability matrix sample row

The traceability matrix row corresponding to this section is documented in full at `docs/traceability.md` under the `c3.4-deterministic-detection-observability` claim. Shape:

```
claim_id:       c3.4-deterministic-detection-observability
ch3_section:    §3.4 Deterministic Detection Observability Surface
code_package:   internal/metrics, internal/correlator, internal/decision/rules, internal/decision/baseline, internal/decision/severitybucket, docs/runbook.md
test_files:     internal/metrics/metrics_test.go, internal/correlator/correlator_metrics_test.go,
                internal/decision/rules/engine_metrics_test.go,
                internal/decision/baseline/engine_metrics_test.go,
                internal/decision/baseline/sigma_bucket_test.go,
                internal/decision/severitybucket/severitybucket_test.go
test_ids:       TestRegisterCounterVec_*, TestRegisterHistogramVec_*,
                TestIntegration_CorrelatorMetricsExposeAllThreeFamilies,
                TestBumpMatchesVec_FansOutPerTechnique,
                TestEngine_DeviationsVecLabelledBySigmaBucket,
                TestSigmaBucket_*, TestScore_*, TestBucket_*, TestBucketFromLabel_*
eval_run_ids:   TBD (Epic 5 evaluation harness wires the metric surface into per-scenario package traces)
```

---

## Sections 2 through 10 -- placeholder

Sections 2 (incident triage), 3 (false-positive tuning), 4 (rule corpus management), 5 (baseline reset), 6 (capacity planning), 7 (TLS/auth rotation), 8 (NATS stream recovery), 9 (config rollback), and 10 (post-incident review) are owned by Story 6.8. Story 1.18 deliberately scopes the runbook to the deterministic-detection metric catalogue so the FR50/NFR32/NFR34 surface is documented at the moment it lands, without pre-empting the operational-scenario writing that Story 6.8 conducts against the live cluster.

The placeholder anchors below let dashboards and operator tooling deep-link to specific sections without breaking when Story 6.8 lands.

### 2 Incident triage (Story 6.8)
### 3 False-positive tuning (Story 6.8)
### 4 Rule corpus management (Story 6.8)
### 5 Baseline reset and warm-up override (Story 6.8)
### 6 Capacity planning and scrape budget (Story 6.8)
### 7 TLS and auth rotation (Story 6.8)
### 8 NATS stream recovery (Story 6.8)
### 9 Configuration rollback (Story 6.8)
### 10 Post-incident review (Story 6.8)
