# Olaitan operator runbook

Scope: this runbook is the operator-facing reference for the Olaitan deterministic-detection layer. Story 1.18 lays down **Section 1 only** (the metric catalogue). Sections 2 through 10 cover the ten common operational scenarios from NFR34 (incident triage, false-positive tuning, rule corpus management, baseline reset, etc.) and are filled in by Story 6.8.

Audience: SREs, on-call engineers, and SOC analysts consuming the Prometheus surface at `:9090/metrics`. The runbook assumes familiarity with PromQL, Kubernetes, and the Olaitan three-ring (collector, correlator, decision) architecture documented in the FYP planning artefacts under `_bmad-output/planning-artifacts/` and the per-PR §3.4 chapter under `report/chapter-3-methodology.md`.

References: FR50 (Prometheus surface mandatory), NFR32 (every metric documented with type, unit, label set), NFR34 (operator runbook covers 10 scenarios), NFR42 (traceability matrix update required per PR).

---

## Section 1. Deterministic-detection metric catalogue

This section enumerates every metric registered by the deterministic-detection layer (the collector, correlator, rule engine, and baseline engine rings). Each entry carries six fields: name, type, unit, label set with cardinality envelope, the Help string copied verbatim from the registration, and two sample PromQL queries (one aggregate for normal-operations dashboards, one alerting predicate for the troubleshooting case).

The catalogue is organised by registering ring + story, in commit chronology so the reader can correlate names with the introducing PR.

### 1.1 Collector ring (Stories 1.12, 1.13)

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

#### `olaitan_sensor_circuit_breaker_engaged_total` (Story 1.13)

- **Type:** counter
- **Unit:** count
- **Labels:** `source` (one of `falco`, `audit`, `runtime`, `network`, `applog`; cardinality 5), `node` (the K8S_NODE_NAME of this DaemonSet pod; cardinality 1 per pod, bounded by node count)
- **Help:** Cumulative count of per-source rate-limit circuit-breaker engage transitions on this node (Story 1.13). One increment per CLOSED to OPEN transition; OPEN to CLOSED transitions are not counted.
- **Sample PromQL (aggregate):** `sum(rate(olaitan_sensor_circuit_breaker_engaged_total[1h])) by (source)` (per-source breaker activity).
- **Sample PromQL (alert):** `rate(olaitan_sensor_circuit_breaker_engaged_total[15m]) > 0` for 15 minutes (page on sustained breaker engagement suggesting an over-aggressive upstream or a stuck adapter).

#### `olaitan_sensor_audit_rejected_total` (Story 1.7 / 1.13)

- **Type:** counter
- **Unit:** count
- **Labels:** `source` (constant `audit`), `reason` (one of `method_not_allowed`, `unsupported_media_type`, `payload_too_large`, `decode_error`, `trailing_json`, `translate_failed`; cardinality 6)
- **Help:** Audit-webhook receiver events rejected at HTTP/translate boundary, bucketed by reason (Story 1.7).
- **Sample PromQL (aggregate):** `sum(rate(olaitan_sensor_audit_rejected_total[5m])) by (reason)` (per-reason rejection rate).
- **Sample PromQL (alert):** `rate(olaitan_sensor_audit_rejected_total{reason="decode_error"}[5m]) > 0.1` for 10 minutes (page on sustained decode failures suggesting an API-server payload schema change).

#### `olaitan_sensor_cri_translate_errors_total` and `olaitan_sensor_cri_publish_drops_total` (Story 1.8)

- **Type:** counter (one family each)
- **Unit:** count
- **Labels:** `source` (constant `runtime`)
- **Help (translate):** CRI lifecycle events that failed translation and were log+dropped (Story 1.8).
- **Help (publish):** CRI events whose publish attempt returned a permanent error and were dropped (Story 1.8).
- **Sample PromQL (aggregate):** `rate(olaitan_sensor_cri_translate_errors_total[5m]) + rate(olaitan_sensor_cri_publish_drops_total[5m])` (combined CRI loss rate).
- **Sample PromQL (alert):** `rate(olaitan_sensor_cri_publish_drops_total[15m]) > 0.05` for 15 minutes (page on sustained CRI publish drops; either NATS is degraded or the runtime is producing malformed events).

#### `olaitan_sensor_cni_translate_errors_total`, `olaitan_sensor_cni_publish_drops_total`, and `olaitan_sensor_cni_oversize_dropped_total` (Story 1.10)

- **Type:** counter (three families)
- **Unit:** count
- **Labels:** `source` (constant `network`)
- **Help (translate):** Calico flow records that failed translation and were log+dropped.
- **Help (publish):** Calico events whose publish attempt returned a permanent error and were dropped.
- **Help (oversize):** Calico events rejected at translate time because the marshalled form exceeded MaxEventBytes.
- **Sample PromQL (aggregate):** `sum(rate(olaitan_sensor_cni_translate_errors_total[5m]) + rate(olaitan_sensor_cni_publish_drops_total[5m]) + rate(olaitan_sensor_cni_oversize_dropped_total[5m]))` (combined CNI loss rate).
- **Sample PromQL (alert):** `rate(olaitan_sensor_cni_oversize_dropped_total[15m]) > 0.05` for 15 minutes (page on sustained oversize-flow drops suggesting a misconfigured Goldmane payload shape).

#### `olaitan_sensor_cni_consecutive_eofs` (Story 1.10)

- **Type:** gauge (not counter; resets to 0 on every successful Recv per Copilot CR2 of PR #21)
- **Unit:** count
- **Labels:** `source` (constant `network`)
- **Help:** EOFs from Goldmane stream.Recv since the last successful Recv; resets to 0 on success (Story 1.10).
- **Sample PromQL (aggregate):** `olaitan_sensor_cni_consecutive_eofs` (current EOF streak).
- **Sample PromQL (alert):** `olaitan_sensor_cni_consecutive_eofs > 10` for 5 minutes (page on a stuck stream; Goldmane endpoint likely unreachable).

#### `olaitan_sensor_applog_translate_errors_total`, `olaitan_sensor_applog_publish_drops_total`, `olaitan_sensor_applog_lines_shed_total`, and `olaitan_sensor_applog_lost_on_shutdown_total` (Story 1.9)

- **Type:** counter (four families)
- **Unit:** count
- **Labels:** `source` (constant `applog`)
- **Help (translate):** Applog records that failed translation and were log+dropped.
- **Help (publish):** Applog events whose publish attempt returned a permanent error and were dropped.
- **Help (shed):** LineRecords dropped due to back-pressure shedding under a stalled consumer.
- **Help (lost):** Applog events whose publishWithRetry was cancelled mid-flight by ctx.Done.
- **Sample PromQL (aggregate):** `sum(rate(olaitan_sensor_applog_translate_errors_total[5m]) + rate(olaitan_sensor_applog_publish_drops_total[5m]) + rate(olaitan_sensor_applog_lines_shed_total[5m]) + rate(olaitan_sensor_applog_lost_on_shutdown_total[5m]))` (combined applog loss rate).
- **Sample PromQL (alert):** `rate(olaitan_sensor_applog_lines_shed_total[15m]) > 1` for 15 minutes (page on sustained back-pressure shedding; the sidecar is producing lines faster than the consumer can drain them).

Wiring of the rate-limit counters above is in `cmd/olaitan/metrics.go:140-260` via `registerAdapterCounters`; the per-adapter detail counters (translate / publish / shed / lost / oversize / consecutive-EOFs) are sourced from `internal/collector/<source>/`.

### 1.2 Correlator ring (Story 1.18 NEW)

#### `olaitan_correlator_evidence_packages_total`

- **Type:** counter_vec
- **Unit:** count
- **Labels:** `trigger_type` (one of `multi_signal`, `rule_match`, `baseline_deviation`; cardinality 3)
- **Help:** Cumulative EvidencePackages successfully published to EVIDENCE.packages grouped by trigger type. The counter is bumped only after the JetStream publish returns no error, so the rate reflects published-to-bus packages, not assemble attempts. Label values are the three trigger.TypeMultiSignal/TypeRuleMatch/TypeBaselineDeviation constants (multi_signal, rule_match, baseline_deviation).
- **Sample PromQL (aggregate):** `sum(rate(olaitan_correlator_evidence_packages_total[5m])) by (trigger_type)` (per-trigger-type publish rate).
- **Sample PromQL (alert):** `rate(olaitan_correlator_evidence_packages_total{trigger_type="multi_signal"}[15m]) > 10` for 5 minutes (page on multi-signal storm suggesting a noisy adapter).

#### `olaitan_correlator_window_size_bytes`

- **Type:** histogram
- **Unit:** bytes
- **Labels:** none (buckets `[1024, 4096, 8192, 16384, 32768, 65536, 131072, 262144]`)
- **Help:** On-wire size in bytes of the EvidencePackage at publish time (post-overflow-summarisation). Buckets cover the assembler.DefaultMaxPackageBytes 128 KiB cap; observations above 131072 indicate the cap-enforcement path was bypassed or failed.
- **Sample PromQL (aggregate):** `histogram_quantile(0.99, sum(rate(olaitan_correlator_window_size_bytes_bucket[5m])) by (le))` (p99 publish size).
- **Sample PromQL (alert):** `sum(rate(olaitan_correlator_window_size_bytes_bucket{le="+Inf"}[5m])) - sum(rate(olaitan_correlator_window_size_bytes_bucket{le="131072"}[5m])) > 0` for 5 minutes (count-based cap-bypass detector: any rate of observations strictly above the 128 KiB cap indicates the size-cap enforcement path was bypassed or failed; preferred over a quantile threshold because `histogram_quantile` interpolates within the open-ended top bucket and would false-positive at exactly the documented cap).

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
- **Help:** Per-(rule_id, severity_bucket, attack_technique) rule-match counter (AC2 of Story 1.18). Complements the unlabelled olaitan_decision_rules_matches_total but does NOT reproduce it under aggregation: a rule carrying N MitreTags increments this counter N times (one bump per technique, BI-4) while matches_total increments once per match. Use `sum by (rule_id)(rate(matches_by_attribute_total[5m])) / count(group by (rule_id) (olaitan_decision_rules_matches_by_attribute_total))` for technique-deduplicated comparisons, or rely on matches_total when an exact per-match rate is required. A rule with empty MitreTags emits one bump with `attack_technique="unknown"`.
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
- **Labels:** `metric` (one of the five default extractors: `outbound_unique_dst_ips`, `distinct_exec_paths`, `outbound_bytes`, `audit_events_per_min`, `container_restarts_per_hour`; cardinality 5), `sigma_bucket` (non-overlapping ranges: `3-5`, `5-10`, `10+`; cardinality 3)
- **Help:** Per-(metric, sigma_bucket) baseline-deviation counter. Story 1.17 introduced the unlabelled-per-metric form; Story 1.18 AC3 adds the sigma_bucket label. Labels are non-overlapping ranges so an operator query for any single label returns the observations that genuinely fall in that range, not a superset. Complements per-package evaluations_total{outcome=deviation}.
- **Sample PromQL (aggregate):** `sum(rate(olaitan_decision_baseline_deviations_total[5m])) by (metric, sigma_bucket)`.
- **Sample PromQL (alert):** `rate(olaitan_decision_baseline_deviations_total{sigma_bucket="10+"}[5m]) > 0.05` for 10 minutes (page on sustained 10+ sigma deviation rate suggesting an unusual workload pattern).

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
- **Per-workload telemetry:** the per-workload warm-up detail (which specific workloads are in warm-up at any given moment) is surfaced through the `AUDIT.transitions` subject (shipped in Story 2.8; see "Append-only SIEM audit subjects" below), not through Prometheus. SIEM-side consumers subscribe to the audit subjects when they need pod-level granularity.

#### `olaitan_decision_baseline_evaluation_seconds`

- **Type:** histogram
- **Unit:** seconds
- **Labels:** none (buckets `[0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250]`, NFR3-sized)
- **Help:** Per-package baseline-engine evaluation latency in seconds; histogram buckets are sized against NFR3 (p99 <= 100 ms).
- **Sample PromQL (aggregate):** `histogram_quantile(0.99, sum(rate(olaitan_decision_baseline_evaluation_seconds_bucket[5m])) by (le))`.
- **Sample PromQL (alert):** `histogram_quantile(0.99, sum(rate(olaitan_decision_baseline_evaluation_seconds_bucket[5m])) by (le)) > 0.1` for 5 minutes.

### 1.4a Score calculator ring (Story 2.1 NEW)

#### `olaitan_decision_score_evaluations_total`

- **Type:** counter
- **Unit:** count
- **Labels:** none
- **Help:** Cumulative number of ThreatScore evaluations performed by the deterministic calculator (FR30). Increments once per `Score()` call; the calculator is stateless and pure, so this counter advances even when the input EvidencePackage has no rule matches and no baseline deviations (and the resulting Total is 0).
- **Sample PromQL (aggregate):** `rate(olaitan_decision_score_evaluations_total[5m])`.
- **Sample PromQL (alert):** `rate(olaitan_decision_score_evaluations_total[5m]) == 0 and on() olaitan_correlator_evidence_packages_total > 0` for 10 minutes (page if correlator is producing packages but the score ring stops evaluating; indicates a stuck consumer).

#### `olaitan_decision_score_total`

- **Type:** histogram_vec
- **Unit:** ratio (0-100 contribution space)
- **Labels:** `component_contribution` (one of `rules`, `baseline`, `llm`; cardinality 3), `result_bucket` (one of `low`, `medium`, `high`, `critical` per `severitybucket.Bucket`; cardinality 4). Cartesian envelope 3 x 4 = 12 series, bounded.
- **Help:** Observation of each ThreatScore component contribution (rules, baseline, llm) labelled by the package's result_bucket. Buckets `[0, 25, 50, 75, 100]` cover the 0-100 contribution range. **Story 3.11:** the `llm` component is now live -- `LLMWeight × clamp(llm_capped_confidence, 0, LLMCap)` (FR30). It is `0` whenever the investigation chain is disabled (RS mode / `analyst.provider: none`), the FR19 gate did not trigger, or the chain degraded to `llm_unavailable`; it is bounded above by `LLMWeight × LLMCap = 0.3 × 35 = 10.5` (the Trust-Bound, enforced by the calculator clamp). The chain is run INLINE by the single FSM consumer (`olaitan-response-fsm`); the standalone `olaitan-investigation-chain` consumer was removed in 3.11, so a workload's LLM contribution and its FSM transition are now decided in one place.
- **Sample PromQL (aggregate):** `sum(rate(olaitan_decision_score_total_count[5m])) by (component_contribution, result_bucket)`.
- **Sample PromQL (alert):** `histogram_quantile(0.99, sum(rate(olaitan_decision_score_total_bucket{component_contribution="rules"}[5m])) by (le)) > 20` for 10 minutes (page when the p99 rule contribution sustains above the SUSPICIOUS threshold; suggests a noisy rule or a sustained attack).

#### `olaitan_decision_score_evaluation_seconds`

- **Type:** histogram
- **Unit:** seconds
- **Labels:** none (buckets via `prometheus.ExponentialBucketsRange(1e-6, 100e-3, 10)` aligned to NFR3 100 ms p99 ceiling)
- **Help:** Wall-clock latency of the deterministic ThreatScore evaluation. The algorithm is `O(|RuleMatches| + |BaselineDeviations|)` with a single atomic `mgr.Get()` snapshot read per call and three label-keyed histogram observations; expected p99 well under 100 microseconds (3 orders of magnitude below NFR3).
- **Sample PromQL (aggregate):** `histogram_quantile(0.99, sum(rate(olaitan_decision_score_evaluation_seconds_bucket[5m])) by (le))`.
- **Sample PromQL (alert):** `histogram_quantile(0.99, sum(rate(olaitan_decision_score_evaluation_seconds_bucket[5m])) by (le)) > 0.1` for 5 minutes (page on NFR3 budget breach).

#### Operator scenario: hot-reloading score weights

The FR30 weights and LLM cap are Helm-tunable and hot-reloadable via FR49. To shift the rule-weight from the default 0.4 to 0.5 without a controller restart:

```
helm upgrade olaitan deploy/helm/olaitan --reuse-values \
    --set score.ruleWeight=0.5 --set score.llmWeight=0.2
```

The chart's `templates/configmap.yaml` regex bridge overlays the chart values onto the ConfigMap's `detection.score.*` keys; `internal/config/watcher.go`'s fsnotify listener catches the K8s projected-volume `..data` symlink swap, the 50 ms debounce window expires, and `config.Manager.cur.Store(newCfg)` swaps the atomic pointer. The calculator reads `mgr.Get()` on every `Score()` invocation, so the next EvidencePackage that arrives at the score ring observes the new weights. No `kubectl rollout restart` is required.

The weights validator rejects any operator change that pushes the three weights' sum above 1.0 + 1e-9 (the algebraic trust-bound `max(LLM-only) = LLMWeight × LLMCap` depends on this invariant); a rejected reload leaves the previous snapshot active and the rejection appears in the aggregator's slog output under `config: reload rejected`. Verify the active weights at any time via the startup log line `aggregator: score calculator wired` or by gathering `olaitan_decision_score_*` metrics on `:9090/metrics`.

### 1.4b Response FSM persistence ring (Story 2.3 NEW)

#### `olaitan_response_fsm_state_recovered_total`

- **Type:** counter
- **Unit:** count
- **Labels:** none (per-workload telemetry is forbidden as a Prometheus label per architecture.md:476; per-workload recovery is observable in the startup log line below and in the `fsm:{workload_id}:history` lists).
- **Help:** Cumulative number of workloads whose FSM state was recovered from Redis on controller restart (FR37/NFR24). Incremented once per workload rehydrated by `Machine.Restore` before the FSM consumer starts.
- **Sample PromQL (aggregate):** `olaitan_response_fsm_state_recovered_total`.
- **Sample PromQL (alert):** `increase(olaitan_response_fsm_state_recovered_total[1h]) == 0 and on() olaitan_response_fsm_active_workloads > 0` is NOT an alert (a steady controller never re-recovers); instead watch `changes(process_start_time_seconds[15m]) > 2` for crash-looping, which would re-run recovery repeatedly.

#### Operator scenario: restart recovery and persistence

FSM state is persisted to the durable `fsm:{workload_id}` Redis hash (NO TTL) on every actual transition, with the transition appended to the `fsm:{workload_id}:history` list (capped at the last 1000 entries). On controller restart the aggregator rehydrates the in-memory FSM map from all `fsm:*` keys BEFORE the evidence consumer starts, so a restart never silently de-escalates a workload to CLEAN (NFR24, target within 60 s of pod readiness). Confirm recovery via the startup log line `aggregator: fsm state recovered from redis` (fields `recovered` and `skipped`) and the `olaitan_response_fsm_state_recovered_total` counter.

A restart resets each recovered workload's de-escalation cooldown window (conservative: it can never de-escalate earlier than a fresh cooldown) while preserving dwell progress where the clock is monotonic. During a brief Redis outage, transitions are buffered in memory and replayed on reconnection (idempotent via the compare-and-swap write); a controller crash mid-outage loses only the unflushed buffer, and the prior committed state remains authoritative in Redis.

To disable persistence (sensing-only or a Redis-less deployment), set `detection.fsm.persistence_enabled: false` in the aggregator ConfigMap and `kubectl rollout restart deploy/olaitan-aggregator` (this knob is restart-required: it rewires the FSM sink and the restore hook).

### 1.4c Response NetworkPolicy enforcement ring (Story 2.4 NEW)

#### `olaitan_response_network_policy_apply_seconds`

- **Type:** histogram
- **Unit:** seconds
- **Labels:** none.
- **Help:** End-to-end latency from the FSM RESTRICTED transition timestamp to NetworkPolicy apply completion (NFR6, p99 within 1 s). Observed once per applied/no-op transition.
- **Sample PromQL (p99):** `histogram_quantile(0.99, sum(rate(olaitan_response_network_policy_apply_seconds_bucket[5m])) by (le))`.
- **Sample PromQL (alert):** `histogram_quantile(0.99, sum(rate(olaitan_response_network_policy_apply_seconds_bucket[5m])) by (le)) > 1` breaches the NFR6 budget.

#### `olaitan_response_network_policy_apply_total`

- **Type:** counter
- **Unit:** count
- **Labels:** `result` (one of `applied`, `noop`, `error`, `skipped`, `dropped`, `gc_deleted`, `superseded`, `removed`).
- **Help:** Cumulative NetworkPolicy enforcement actions by result (FR33/FR35). `applied` = a policy created or updated; `noop` = an idempotent re-apply that matched the live object; `skipped` = a workload in an excluded namespace or already deleted; `dropped` = a transition dropped because the apply queue was full; `gc_deleted` = an orphan policy garbage-collected after its workload was removed; `superseded` = an escalation-residue policy removed by the reconcile backstop (a RESTRICTED policy for a workload the FSM now targets at QUARANTINED); `removed` = a de-escalation removal of a workload's managed policies (the SUSPICIOUS/CLEAN inline path, or a reconcile delete driven by the workload's FSM target dropping below the policy's state, Story 2.6). Note the `removed` granularity differs by path: the inline SUSPICIOUS/CLEAN removal counts `removed` once per workload (one handled transition), whereas the reconcile backstop counts `removed` once per policy object deleted, so a workload whose two policies are both reaped by the reconciler increments `removed` twice. Sum `removed` for action volume, not workload count.
- **Sample PromQL (error rate):** `sum(rate(olaitan_response_network_policy_apply_total{result="error"}[5m]))`.
- **Sample PromQL (drops):** `increase(olaitan_response_network_policy_apply_total{result="dropped"}[15m]) > 0` indicates the FSM is producing RESTRICTED transitions faster than the worker can apply them; investigate API-server latency.

#### Operator scenario: graduated isolation (RESTRICTED enforcement)

When a workload's ThreatScore crosses the RESTRICTED band (default 40), the FSM transitions it to RESTRICTED and the NetworkPolicyManager applies a NetworkPolicy named `olaitan-restricted-<hash>` in the workload's namespace. The policy allows egress only to the RFC 1918 private ranges, the configured cluster pod/service CIDRs, and any `extra_allowed_cidrs`, plus an explicit DNS (UDP/TCP 53) rule, and blocks all other (external) egress; ingress is left untouched (the full ingress+egress block is the QUARANTINED state, Story 2.5). Confirm with `kubectl get networkpolicy -n <namespace> -l app.kubernetes.io/managed-by=olaitan` and inspect the `olaitan.io/fsm-state` and `olaitan.io/package-id` annotations to trace the policy back to the triggering evidence package.

Enforcement is OFF by default. To enable it, set `response.network_policy.enabled: true` in the aggregator ConfigMap and, critically, set `response.network_policy.cluster_cidrs` to your cluster's own pod and service CIDRs (the defaults `10.244.0.0/16` and `10.96.0.0/12` match the kind/Calico evaluation cluster). If the service CIDR is omitted, in-cluster DNS resolution to CoreDNS can break under RESTRICTED. Then `kubectl rollout restart deploy/olaitan-aggregator`.

Two real-world limitations apply. First, enforcement depends on a NetworkPolicy-compliant CNI (Calico, Cilium, Antrea); under a CNI that does not enforce NetworkPolicy (for example Flannel) the policy object is created but has no effect. Second, Kubernetes NetworkPolicies are additive: if a pre-existing permissive egress policy also selects the workload's pods, it unions with the Olaitan RESTRICTED policy and the egress block is not fully effective. The RESTRICTED egress block is fully effective only where no conflicting allow-policy selects the workload.

Orphan policies (a workload deleted while RESTRICTED) are garbage-collected within 60 s by a periodic reconcile (default 30 s, tunable via `response.network_policy.reconcile_interval_seconds`) that deletes managed policies whose owner no longer exists.

A RESTRICTED transition is enforced per emission, not per desired state. If a transition is dropped because the apply queue was full (`result="dropped"`) or its owner-selector resolution hit a transient API error (`result="error"`), that specific RESTRICTED transition is not enforced until the FSM re-emits it for the same workload; the manager does not retry the dropped or errored transition on its own. There is no continuous desired-state re-reconciliation that would re-apply a missing RESTRICTED policy independently of a fresh FSM emission, so a sustained `result="dropped"` or `result="error"` rate means some workloads may sit in RESTRICTED without an enforcing policy until the next transition. Full desired-state re-reconciliation is deferred (see Open Assumption 5 in the Story 2.4 specification). Treat a non-zero `dropped`/`error` rate as an enforcement-coverage gap, not merely a latency blip.

#### Operator scenario: full isolation (QUARANTINED enforcement, Story 2.5)

When a workload's ThreatScore crosses the QUARANTINED band, the FSM transitions it from RESTRICTED to QUARANTINED and the NetworkPolicyManager applies a deny-all NetworkPolicy named `olaitan-quarantined-<hash>` in the workload's namespace. Unlike the RESTRICTED egress allow-list, the quarantine policy blocks ALL ingress and ALL egress for the workload's pods: it carries `policyTypes: [Ingress, Egress]` with no ingress and no egress rules at all (in additive `networking.k8s.io/v1` semantics, a selected pod with a policy type but no rules of that type is fully denied for that direction). There is deliberately NO DNS carve-out under QUARANTINED, so in-pod name resolution is also cut off; this is intentional total isolation of a confirmed-malicious workload (the DFIR agent does not rely on in-pod DNS). Confirm with `kubectl get networkpolicy -n <namespace> -l app.kubernetes.io/managed-by=olaitan` and inspect the `olaitan.io/fsm-state: QUARANTINED` annotation. The quarantine policy carries the same management labels as the RESTRICTED policy.

The replacement of the RESTRICTED policy by the QUARANTINED policy is monotonically tightening from the workload's perspective: there is never a window with no policy at all, and never a window less protected than RESTRICTED. The manager uses apply-before-delete with distinct deterministic names. It FIRST applies the `olaitan-quarantined-<hash>` deny-all policy (via the same idempotent get-then-create-or-update path RESTRICTED uses) and, ONLY after that apply returns success, best-effort deletes the `olaitan-restricted-<hash>` policy for the same workload. Kubernetes NetworkPolicies are additive allow-lists: while both policies select the pod, ingress is denied immediately (only the quarantine policy declares the Ingress policyType, with no allow rules), and egress remains the UNION of both policies' allows, which is still the RESTRICTED allow-list (RFC 1918, cluster CIDRs, DNS). The deny-all does NOT subtract or override those egress allows; egress only tightens to deny-all once the restricted policy is removed. The manager never deletes the old policy before the new one is confirmed, so protection only ever increases.

The supersession delete of the RESTRICTED policy is best-effort inline. A failed inline delete does NOT fail the QUARANTINED enforcement, but it does leave the workload not yet fully isolated: ingress is already denied, yet a lingering RESTRICTED policy keeps egress at the allow-list level (RFC 1918 + cluster + DNS), so egress is not yet deny-all. A transient inline delete failure is logged at WARN and is then reconciled by the periodic reconcile backstop (see below). The same two real-world limitations as RESTRICTED apply: enforcement depends on a NetworkPolicy-compliant CNI, and a pre-existing permissive third-party policy selecting the same pod can union to permit traffic the quarantine intends to block.

If the inline supersession delete fails (or a controller shutdown is timed precisely between a successful quarantine apply and the supersession delete), the superseded `olaitan-restricted-<hash>` policy is removed by the periodic reconcile, which is the supersession backstop. Each reconcile cycle (default 30 s) lists managed policies, identifies workloads that currently have a QUARANTINED policy (by the `olaitan.io/fsm-state: QUARANTINED` annotation), and deletes any RESTRICTED policy for those workloads regardless of whether the owner still exists. This converges egress to deny-all within one reconcile interval and is counted under `result="superseded"`. Note that orphan GC alone would NOT remove the lingering restricted policy while the owner still exists (it only deletes on owner deletion); the supersession backstop is what makes the eventual full isolation guarantee hold. No operator action is required beyond awaiting the reconcile cycle.

#### Operator scenario: de-escalation policy removal (Story 2.6, FR35)

When a workload's threat indicators decay, the FSM de-escalates it one step at a time (QUARANTINED -> RESTRICTED -> SUSPICIOUS -> CLEAN), each step cooldown-gated. The NetworkPolicyManager removes or relaxes the managed policies in lock-step so a workload that is no longer suspect recovers normal connectivity automatically, without a stale deny-all or egress-block stranding it. Each FSM target DEFINES the workload's desired managed-policy set, and both the inline path and the reconcile backstop converge to it:

- **QUARANTINED -> RESTRICTED (relaxation, the mirror of escalation):** the manager FIRST applies the `olaitan-restricted-<hash>` egress-only policy, then best-effort deletes the superseded `olaitan-quarantined-<hash>` deny-all. Apply-before-delete is load-bearing here for the opposite reason to escalation: deleting the deny-all before the restricted apply would momentarily revert the workload to fully open egress (no Olaitan restriction at all). During the brief overlap the workload is selected by both policies, so egress is already at the relaxed allow-list (the deny-all contributes no egress allows) while ingress stays denied until the deny-all is gone; the overlap is therefore, if anything, STRICTER than the final RESTRICTED state and never policy-less. The restricted apply counts `applied`/`noop`; the inline quarantine delete is silent best-effort. Confirm with `kubectl get networkpolicy -n <namespace> -l app.kubernetes.io/managed-by=olaitan`: you should see the `olaitan-restricted-<hash>` policy (annotation `olaitan.io/fsm-state: RESTRICTED`) and NO `olaitan-quarantined-<hash>`.

- **RESTRICTED -> SUSPICIOUS and -> CLEAN (full removal):** SUSPICIOUS is a sensing-only state with no NetworkPolicy isolation and CLEAN is fully recovered, so both have an EMPTY desired set: the manager deletes BOTH `olaitan-restricted-<hash>` and `olaitan-quarantined-<hash>` for the workload (`IsNotFound` on either is success). Removal runs WITHOUT resolving a podSelector, so a de-escalating workload whose owner is being torn down still has its policies cleared. CLEAN additionally VERIFIES absence via a follow-up read of each name and re-deletes a stray survivor once. A successful removal counts `removed`; a removal-with-nothing-to-remove (a workload that was never isolated, or whose policies an intermediate step already cleared) is a successful no-op also counted `removed`, NEVER `error`. Do not read a `removed` with no policies present as a fault.

The reconcile backstop is now FSM-target-aware (Story 2.6). Each reconcile cycle (default 30 s) the manager queries the FSM for each managed policy's workload and converges the policy set to the workload's CURRENT target's desired set: target QUARANTINED deletes a stale RESTRICTED policy (`result="superseded"`, the escalation residue, unchanged from Story 2.5); target RESTRICTED deletes a stale QUARANTINED policy (`result="removed"`, the de-escalation residue) WITHOUT touching the freshly-applied restricted policy; target SUSPICIOUS/CLEAN with the owner still present deletes BOTH (`result="removed"`). This is what guarantees a failed inline relaxation or removal self-heals within one reconcile interval, and what prevents a reconcile tick during the QUARANTINED->RESTRICTED overlap from re-deleting the freshly-applied restricted policy (the old "quarantine object wins" heuristic would have resolved that overlap backwards). The FSM target is read through a one-method `StateOracle` seam wired from the in-process `fsm.Machine`.

When the FSM has no opinion on a workload (the oracle returns not-ok, e.g. transiently before the FSM map is populated, or after an FSM restart that did not restore the workload), the desired-state backstop deliberately does NOT delete the policy: the orphan-GC pass (owner NotFound -> `gc_deleted`) is the sole authority for such workloads. This is conservative by design, so an FSM state loss never strips protection from a still-running workload; the policy is reaped only if its owner is genuinely gone, otherwise it is retained until the FSM next evaluates the workload and the backstop regains an opinion. The orphan-GC behaviour is unchanged for all policies.

Scope boundary: Story 2.6 handles ONLY automated, ThreatScore-driven de-escalation transitions. Operator-override state pins (`olaitan.io/state-override`, FR38/FR39) and their TTL release are Story 2.7; an override that drives the FSM into a lower state will flow through this same removal path once it lands, but the override controller, the annotation watch, and the `override_rejected` metric are not part of Story 2.6.

#### Operator scenario: pinning a workload's state with an annotation (Story 2.7, FR38/FR39)

When you have manually investigated an alert and want Olaitan to stand a workload down or escalate it for a fixed window, annotate the workload's pod OR its owner (Deployment/StatefulSet/DaemonSet/ReplicaSet/Job/CronJob) with the override pair and let the override controller pick it up. The controller is OFF by default; enable it with `response.override.enabled: true`.

- `olaitan.io/state-override: <STATE>` where `<STATE>` is one of `CLEAN`, `SUSPICIOUS`, `RESTRICTED`, `QUARANTINED`. This pins the FSM to that state and DEFERS all subsequent ThreatScore-driven transitions until the override is released (FR38).
- `olaitan.io/state-override-ttl: <duration>` (optional) is a Go duration such as `30m` or `2h`. When absent (or unparseable, or non-positive) the controller DEFAULTS to `1h` and logs a WARN; a bad TTL is NOT a rejection of the override.
- `olaitan.io/state-override-by: <operator-id>` (optional) records who applied the override. When present it is carried on the `OVERRIDES.applied` event, the `override:{workload_id}` Redis record, and the FSM pin transition's `operator_id` for the audit trail. When absent the operator id is empty (acceptable). An operator-id change ALONE does NOT re-pin or re-arm the TTL (the TTL hard deadline is keyed on state + duration only).

**Observation is a poll, not a watch.** The controller LISTs pods on a ticker (`response.override.poll_interval_seconds`, default 15 s) and reconciles. The aggregator deliberately holds no `watch` RBAC; observation is on-demand polling, so an override applied while the controller is briefly down is picked up on the next tick. **Release latency is therefore one poll interval**: the Redis key's TTL is exact, but the FSM's resumption is detected on the first poll AFTER the override ends (Open Assumption 1). Lower `poll_interval_seconds` for tighter release latency.

**Native Redis TTL is a HARD DEADLINE, not a refreshing lease.** Each applied override writes `override:{workload_id}` (the canonical `namespace/owner-kind/owner-name` form) with a NATIVE Redis TTL equal to the requested duration. Inspect it with `redis-cli TTL override:default/Deployment/web`; the TTL should match the requested duration when the override was first applied (AC3). The reconcile is EDGE-TRIGGERED: the TTL is measured from FIRST application and is NEVER refreshed while the annotation merely remains present, so the override AUTO-RELEASES when the TTL elapses EVEN IF the annotation is still on the pod or owner (this honours AC2/FR39: "when the TTL elapses, the override is released, the FSM resumes"). To extend or change an override, the operator must CHANGE the annotation (a different state or a different `-ttl`) or REMOVE and RE-APPLY it; an unchanged annotation does not re-arm the deadline. This is the deliberate divergence from the no-TTL `fsm:` family: the override's lifetime is wall-clock, so it is reaped by Redis exactly on expiry. The pin's in-memory flag is NOT persisted in the `fsm:` hash; on restart the FSM rehydrates the pinned state from `fsm:` and the first post-restart poll re-establishes the in-memory pin from the surviving `override:` key (Open Assumption 3). If the controller is down longer than the TTL, Redis drops the key during the outage and the first post-restart poll sees no key and releases.

**Restart re-arm caveat (hard-deadline model).** The "already-expired" suppression that stops a still-present annotation from re-pinning after its hard deadline is held IN MEMORY on the controller (a per-workload consumed-signature set). After a controller restart, that in-memory set is empty, so a still-present annotation whose hard deadline already elapsed RE-PINS ONCE (re-arm) with a fresh native TTL on the first post-restart poll. This is acceptable: the operator who wanted the override gone should remove the annotation, and the durable `override:` key drives correctness across the restart for the common case.

**Release triggers (all detected by the same poll).** (1) Hard-deadline TTL expiry: the native Redis TTL elapses, Redis drops the `override:` key, and the poll detects the expiry AUTHORITATIVELY: a workload that is CURRENTLY PINNED in the FSM, is STILL desired (its annotation is present), and has NO active `override:` key this tick has reached its hard deadline (the missing key IS the deadline signal; the FSM pin set is the authority for "we believe this is pinned"). It calls `ReleasePin` and marks the workload "consumed" so the still-present annotation does NOT immediately re-pin. This absolute-deadline detection does NOT depend on observing the key present on a previous tick, so it is correct even when the TTL is SHORTER than the poll interval (the key is written and expires inside one poll gap) and when a SCAN/GET race transiently drops the key from one poll's active set. (2) Manual removal before expiry: you delete the annotation, the poll sees the workload no longer in the desired set (with the key possibly still present), CONFIRMS the annotation is genuinely gone with a direct read of the owner object (see below), then calls `ReleasePin` AND deletes the Redis key immediately (AC4), and clears the consumed marker so a later re-add re-pins. On release the FSM resumes score-driven control from the released state, re-evaluated against the CURRENT ThreatScore; the dwell/cooldown anchors are reset to a fresh window. The released workload reports the pinned state until its next ThreatScore arrives, then converges (Open Assumption 2): there is no synthetic re-score.

**Manual-removal confirmation by a direct owner read.** Before a pinned/active workload that is not in this tick's desired set is released as a "manual removal", the controller CONFIRMS the annotation is genuinely gone by reading the workload's owner object directly (parse the `workload_id` into `namespace/Kind/name`, GET that owner via the typed client, and check it does NOT carry `olaitan.io/state-override`). This closes the owner-scaled-to-zero / rollout-churn false positive: a workload whose owner annotation pins it but which has ZERO live pods this tick produces a successful-but-EMPTY pod list, which is NOT a removal. Outcomes: owner NotFound (genuinely gone) => confirmed removal => release; owner present WITHOUT the annotation => confirmed removal => release; owner present WITH the annotation => the pods are merely absent (e.g. scaled to zero, mid-rollout) => NOT a removal => the pin is RETAINED; owner GET errors (non-NotFound) => indeterminate => retained. A pod-sourced override whose pod could not be resolved this tick (a transient owner-walk error) is likewise retained, since the owner object carries no pod-level annotation to confirm against.

**Transient-error safety.** A pinned workload is NEVER released on an UNPROVEN absence. If a transient (non-NotFound) Kubernetes API error prevents the poll from positively determining a workload's desired state this tick (an owner-annotation read error, or a workload-id resolve error), the controller marks THAT SPECIFIC workload INDETERMINATE and SKIPS releasing it; a positively-resolved, confirmed-absent workload elsewhere is still releasable the same tick (the protection is per-workload, not a tick-wide veto). The override is retained until a clean poll positively confirms the annotation is gone. This prevents a transient API blip from spuriously un-isolating a pinned QUARANTINED workload.

**Enforcement reuses Stories 2.4-2.6 with no new code (BI-7).** A pin is a `StateTransition` routed through the same FSM sink the automated path uses. A pin to RESTRICTED/QUARANTINED therefore drives the Story 2.4/2.5 NetworkPolicy apply, and a pin to CLEAN/SUSPICIOUS drives the Story 2.6 removal. The override is a NEW WAY TO PRODUCE a transition, not a new enforcement path.

**Precedence and conflicts (BI-9, Open Assumption 4).** A pod-level annotation wins over the same annotation on the owner; both key on the canonical owner-resolved `workload_id`, so an owner-level annotation pins the whole workload (the common "stand this Deployment down" case). Conflicting per-pod annotations of the SAME owner (pod A says RESTRICTED, pod B says QUARANTINED) resolve to the HIGHEST requested state (most-isolating wins, the safe security default) with a WARN log naming the conflict. Annotate the owner for a whole-workload override and avoid conflicting per-pod annotations.

**Rejected overrides.** A typo'd or non-enum state value is refused: no pin, no Redis key, an `OVERRIDES.applied` event with `rejected: true, reason: invalid_state`, and the metric below increments with `reason="invalid_state"`, so you can tell "you mistyped the state" from a legal pin. **Story 4.1 update:** `PRESERVED_KILLED` is now a LEGAL override target (it is no longer refused with `state_unavailable`); see the PRESERVED_KILLED section below. An operator may pin `olaitan.io/state-override: PRESERVED+KILLED` (the plus-form is accepted and normalised to the underscore code token), but ONLY when the workload is currently QUARANTINED: a pin attempt from any lower state is rejected inside the FSM (no pin, no Redis key) to close the skip-into hole.

The `OVERRIDES.applied` NATS subject (365-day JetStream retention) carries one event per applied AND per rejected override; its append-only `AUDIT.overrides` SIEM mirror ships in Story 2.8 (see "Append-only SIEM audit subjects" below).

### PRESERVED_KILLED, the fifth FSM state (Story 4.1, FR31)

`PRESERVED_KILLED` is the fifth and terminal FSM state, one step above QUARANTINED on the `CLEAN -> SUSPICIOUS -> RESTRICTED -> QUARANTINED -> PRESERVED_KILLED` chain. There are exactly TWO legal ways in, BOTH only from QUARANTINED:

- **Automated kill condition (default).** A QUARANTINED workload escalates to PRESERVED_KILLED when the Helm-tunable kill condition is met: the ThreatScore has been continuously at or above `kill_threat_score` (default 90) for at least `kill_sustain_seconds` (default 300 s), AND the workload has been QUARANTINED for at least that long. A freshly-spiking score does NOT kill immediately: both the at-or-above-90 window and the dwell-since-QUARANTINED clock must elapse, and any dip below 90 resets the at-or-above window. The transition publishes to `AUDIT.transitions` with `reason=kill_condition_met`, `trigger_type=automated`.
- **Operator override.** An operator may pin `olaitan.io/state-override: PRESERVED+KILLED` (plus-form accepted; normalised to the underscore code token), but ONLY when the workload is currently QUARANTINED. A pin attempt from any lower state is rejected inside the FSM (no skip-into). The transition carries `trigger_type=override`, `reason=operator_override`, `operator_id` set.

**Kill tunables (hot-reloadable, FR47/FR49).** `kill_threat_score` and `kill_sustain_seconds` live in the `detection.fsm` block of `config/olaitan.yaml`; in Helm they are `fsm.killThreatScore` / `fsm.killSustainSeconds` (empty -> config defaults 90 / 300). `kill_threat_score` must be in `[0,100]` and strictly above the QUARANTINED band (70); `kill_sustain_seconds` must be `>= 0`.

**Scope (Story 4.1 only transitions state).** The QUARANTINED NetworkPolicy STAYS in place on a kill (the workload remains isolated): the inline path applies/removes nothing, and the reconcile backstop retains the QUARANTINED deny-all. Story 4.1 does NOT delete the pod, does NOT run CRIU/forensic capture, and does NOT invoke the DFIR agent; those are Stories 4.2/4.3/4.4. A workload in PRESERVED_KILLED is visible in `olaitan_response_fsm_active_workloads{state="PRESERVED_KILLED"}`.

### Forensic capture controller (Story 4.2, FR36)

When a workload reaches `PRESERVED_KILLED`, the forensic capture controller (`internal/response/forensics/`) preserves a forensic record of the doomed pod(s) to S3 BEFORE deleting them. It is a non-blocking FSM `MultiSink` member: `Publish` filters to the kill transition and enqueues, and a background worker runs capture -> upload -> delete off the FSM hot path. It is OFF by default; enable with `response.forensics.enabled=true`.

**Chosen path: documented fallback (Path A), not CRIU.** Per ADR-2026-05-02-01, CRIU is infeasible on the pinned containerd 1.7 substrate (no `CheckpointContainer` CRI RPC) and the kernel substrate (CRIU vDSO init failure), so Story 4.2 ships `kubectl_fallback.go`: per-container logs (current and the terminated container's `--previous`), the pod spec/status, and recent events, assembled into a content-addressed `forensic-bundle.tar.gz`. CRIU (`criu.go`) is a dormant, rejected alternative and is never wired live.

**Capture-before-delete with S3-ack gating (the load-bearing invariant).** The pod is deleted ONLY after the object store acknowledges a durable, SSE-KMS-encrypted PUT of the bundle under `forensic-bundles/<sha256>/forensic-bundle.tar.gz`. If the upload fails after the in-line retry, the pod is NOT deleted (forensic preservation has priority over the kill), `olaitan_forensic_writes_deferred_total` increments, and the pod stays network-isolated by virtue of the retained QUARANTINED deny-all (Story 4.1). The deferred-write retry queue is Story 4.7; Story 4.2 only signals the deferral.

**Configuration.** `response.forensics` in `config/olaitan.yaml` (Helm: `response.forensics.*`): `s3_endpoint`, `s3_bucket`, `s3_region`, `s3_use_ssl` (default true; set false for a plaintext local MinIO), `kms_key_alias` (SSE-KMS key; empty leaves bucket-default SSE). The S3 access and secret keys are NFR8 secrets read from the `S3_ACCESS_KEY` / `S3_SECRET_KEY` environment variables (Helm: `secrets.s3AccessKey` / `secrets.s3SecretKey`), never YAML. Enabling forensics grants the aggregator ServiceAccount `pods` `delete` and `pods/log` `get` (in addition to the default patch/get/list); these are gated on `forensics.enabled` so a deployment that never kills pods keeps the narrower posture.

**Metrics (FR36/NFR7/NFR28).**
- `olaitan_forensic_capture_seconds` (histogram): capture-to-S3-to-delete latency, observed only on full success; NFR7 budget is `histogram_quantile(0.99, ...) <= 10`.
- `olaitan_forensic_capture_total{result}`: `captured` (full success), `deferred` (S3 failed after retry, pod retained), `skipped` (excluded namespace / no pods / no longer PRESERVED_KILLED), `error` (capture or delete failure), `dropped` (Publish queue full).
- `olaitan_forensic_writes_deferred_total`: deferred forensic writes; a non-zero rate means S3 is unreachable and evidence-bearing pods are accumulating undeleted-but-isolated. Alert on it.

**Operator actions on a deferred write.** A rising `olaitan_forensic_writes_deferred_total` indicates S3/MinIO is unreachable or misconfigured. The pods are safe (still QUARANTINED, deny-all). Restore S3 reachability and KMS-key validity; until Story 4.7's retry queue lands, a re-kill is not re-triggered automatically, so verify the bundle landed in the bucket and manually delete the pod only after confirming a durable upload, OR leave the pod isolated pending the Story 4.7 drain.

**Captured logs are KMS-encrypted but UNREDACTED (Story 4.5 follow-up).** The fallback uploads container logs encrypted at rest via SSE-KMS, but Story 4.2 deliberately introduces NO text-redaction code path (that is Story 4.5's `ForensicReport` redaction on the Ring-5 report path). The forensic bundle is a secret-tier artefact relying on KMS + bucket access control until Story 4.5 layers redaction onto the report path.

### Append-only SIEM audit subjects (Story 2.8, FR40/NFR16)

When `response.audit.enabled=true` (off by default; one flag gates all three), the agent publishes three append-only NATS audit subjects for SIEM consumption (Splunk / Elastic / Datadog). Each rides a dedicated `LimitsPolicy` JetStream stream (append-only by retention: NFR16 means consumers cannot delete events) with Helm-tunable per-subject retention:

| Subject | Stream | Default retention | Records |
|---|---|---|---|
| `AUDIT.transitions` | `AUDIT_TRANSITIONS` | 90 d (`response.audit.retention_transitions_days`) | every actual FSM state change (`before_state`/`after_state`/`triggering_threat_score`/...), automated AND operator-pin (including the Story 4.1 QUARANTINED -> PRESERVED_KILLED kill, `reason=kill_condition_met`) |
| `AUDIT.overrides` | `AUDIT_OVERRIDES` | 365 d (`response.audit.retention_overrides_days`) | every override application AND rejection, with full FR40 attribution |
| `AUDIT.policies` | `AUDIT_POLICIES` | 365 d (`response.audit.retention_policies_days`) | every real NetworkPolicy mutation (apply/supersede_delete/deescalation_remove/gc_delete) |

Inspect with `nats sub AUDIT.transitions --raw` (or `.overrides` / `.policies`): each is structured JSON with documented field names (no NL parsing). Committed schemas live at `docs/schemas/audit/*.json` (authoritative) with `*.yaml` documentation mirrors.

### AUDIT.redactions, the fifth SIEM audit subject (Story 3.1, FR41/FR44/NFR15/NFR18)

`AUDIT.redactions` is the fifth and final SIEM audit subject, completing the architecture's five-subject surface. It joins the other four above and is inspected the same way: `nats sub AUDIT.redactions --raw`. It carries one structured-JSON event per redacted field, validated against `docs/schemas/audit/redactions.json` (authoritative, with the `redactions.yaml` mirror).

| Subject | Stream | Default retention | Records |
|---|---|---|---|
| `AUDIT.redactions` | `AUDIT_REDACTIONS` | 365 d (`report.redact.retention_redactions_days`) | one event per redacted field: `field_path` + `reason` (`secret_pattern`/`jwt_body`/`raw_payload`/`file_contents`) + `package_id` |

Operational notes:
- **Redaction is ALWAYS on; only the SIEM emission is config-gated, off by default (BI-7).** The `Redact()` pipeline strips secrets/JWTs/raw-payloads/file-contents at EVERY LLM and persistence boundary regardless of config (turning it off would violate NFR15 and is forbidden). The `report.redact.audit_enabled` flag (default `false`) gates ONLY whether the `AUDIT.redactions` SIEM events are published. An operator without a SIEM leaves it `false` and pays no NATS-publish cost while STILL getting full redaction.
- **No secret value on the wire (NFR18, BI-5.3).** The event records WHERE (`field_path`) and WHY (`reason`) a redaction happened, NEVER the secret that was redacted: there is no value/before field. `nats sub AUDIT.redactions --raw` is therefore safe to ship to a SIEM. `redacted_at` (the redaction decision time) is distinct from `published_at` (the audit-emit time).
- **Append-only via LimitsPolicy (NFR16), 365 d default.** The `AUDIT_REDACTIONS` stream is `LimitsPolicy` (consumers cannot delete events), Helm-tunable via `report.redact.retention_redactions_days`. Unlike transitions' 90 d, no AC carves out a shorter window for redactions, so it takes the architecture's generalised "AUDIT.* 365 d" default.
- **Best-effort, never blocks or fails the redaction (BI-6.2).** A NATS outage drops redaction-audit events (with a warn + a dropped counter on the buffered sink) rather than adding latency to or failing the redaction / LLM call. The redaction is the security guarantee; the audit line is observability.

### AUDIT.assessments, the LLM-verdict SIEM subject (Story 3.14, FR41/NFR15/NFR18)

`AUDIT.assessments` is the append-only SIEM copy of every investigation-chain run. Inspect it the same way: `nats sub AUDIT.assessments --raw`. Each event is structured JSON validated against `docs/schemas/audit/assessments.json` (authoritative, with the `assessments.yaml` mirror).

| Subject | Stream | Default retention | Records |
|---|---|---|---|
| `AUDIT.assessments` | `AUDIT_ASSESSMENTS` | 365 d (`response.audit.retention_assessments_days`) | one event per chain run: per-role prompt versions/providers/models, the L1/L2/Senior verdicts, the **redacted** evidence, raw + capped confidences, `redaction_applied` |

Operational notes:
- **Full chain trail, keyed on `package_id`.** The event carries `prompt_versions{l1,l2,senior}` (the Story 3.13 content hashes — so a verdict is reproducible to an exact prompt revision), `providers`/`models` per role, the `l1_hypothesis`/`l2_verification`/`threat_assessment`, and `raw_confidence`/`llm_capped_confidence`. An ablation mode (`l1_only`/`l1_l2`) omits the roles it did not run. The msgID is `package_id`, so a chain re-run of the same package is server-side deduplicated within the stream's dedup window.
- **Redaction at the audit boundary (NFR15/NFR18).** `redacted_evidence` is the EvidencePackage AFTER `redact.Redact` — the exact bytes the LLM saw, with secret env values, JWT bodies, and raw payloads stripped. The raw package is NEVER serialised into the event, so `AUDIT.assessments` is safe to ship to a SIEM. `redaction_applied` is `true` on every production path; a `false` is a CI-enforced violation (a property test asserts no production call builds an assessment with redaction skipped, and an adversarial secret-bearing package proves no secret reaches the payload).
- **Append-only via LimitsPolicy (NFR16), 365 d default.** The `AUDIT_ASSESSMENTS` stream is `LimitsPolicy` (consumers cannot delete events), Helm-tunable via `response.audit.retention_assessments_days`. The operational `ASSESSMENTS.completed` 30-day read-model named in the architecture is deferred until a query consumer needs it (no Epic-3 consumer reads it; the SIEM copy here is the load-bearing audit trail).
- **Schema is v2, additive over the Story 3.8 v1 (NFR29).** Older consumers ignore the new fields. `decided_at` (chain decision) equals `published_at` in the synchronous publish path.

Operational notes:
- **Two events per applied override, by design (BI-10):** an applied operator override emits one `AUDIT.transitions` (the state change, `trigger_type=override`) AND one `AUDIT.overrides` (the application, with TTL/source/attribution); a rejected override emits only `AUDIT.overrides`. They are complementary, correlated on `workload_id` + time. Do NOT "deduplicate" them.
- **Mutations only, not heartbeats (BI-9, Open Assumption 2):** an idempotent NetworkPolicy noop, a NotFound delete, and a no-op FSM evaluation produce NO audit event. Audit-stream volume tracks real activity, not reconcile cadence. For reconcile-cadence telemetry use the Story 2.9 Prometheus metrics.
- **Transitions retention is 90 d (BI-7):** this reconciles architecture.md:239's generalised "AUDIT.* 365 d" with the AC's specific 90 d for transitions (matching `STATE_TRANSITIONS.applied`); overrides/policies stay 365 d.
- **Best-effort, never blocks enforcement (BI-5):** a NATS outage drops audit events (with a warn + a dropped counter on the buffered transitions/policy paths) rather than stalling the FSM goroutine, the override poll, or the netpol apply worker. A missed audit line is an observability gap, not a control-plane failure.

#### `olaitan_response_override_rejected_total` (Story 2.7, FR38/FR39)

- **Type:** Counter vector, labelled `reason`.
- **Labels:** `reason` is `invalid_state` (an unknown/typo'd state value) or `state_unavailable` (retained for series stability). Both label series are pre-initialised to 0 at startup so alert PromQL has a stable zero baseline.
- **Meaning:** cumulative count of operator-override requests the controller refused. **Story 4.1 update:** `state_unavailable` no longer increments. It used to count `PRESERVED_KILLED` override attempts (rejected as not-yet-implemented); Story 4.1 admits `PRESERVED_KILLED` as a legal override target (its only-from-QUARANTINED legality is enforced inside the FSM, not as a pre-filter rejection), so the label stays flat at 0. A rising `invalid_state` indicates operators are mistyping the annotation value. (A `PRESERVED_KILLED` pin from a non-QUARANTINED workload is rejected inside the FSM and logged, but does NOT increment this counter.)
- **Counting semantics (one per DISTINCT rejection, not per poll).** A standing invalid annotation is counted ONCE, not once per poll. The controller tracks the last-rejected signature (`reason|requested-value`) per workload and increments the counter (and emits the `OVERRIDES.applied` rejection event) only on a NEW or CHANGED rejection for that workload, so the counter stays consistent with the server-side-deduped NATS event (one event, one increment). If the operator edits the annotation to a DIFFERENT still-invalid value the counter ticks once more (a new distinct rejection); when the workload stops being rejected (the value is corrected, or the annotation is removed) the marker is cleared, so a later regression to the same bad value re-counts. Read a flat `invalid_state` as "one standing misconfiguration", and a STEP increase as "a new or changed bad annotation", rather than as a per-scrape rate.
- **No `workload_id` label** (forbidden as a Prometheus label per architecture.md:472-476); the rejected workload is in the `OVERRIDES.applied` event and the controller WARN log.

#### Graduated-isolation observability surface (Story 2.9, NFR32)

Story 2.9 completes the Epic 2 Prometheus surface. The FSM metrics
(`olaitan_response_fsm_transitions_total{from_state,to_state,reason}`,
`olaitan_response_fsm_dwell_seconds{state}`,
`olaitan_response_fsm_active_workloads{state}`) shipped in Story 2.2. Story 2.9
adds:

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `olaitan_response_override_applied_total` | counter | `state` | applied operator overrides per requested target state |
| `olaitan_response_override_active` | gauge | `state` | workloads with an ACTIVE operator pin, by state (refreshed each reconcile from the FSM pin set) |
| `olaitan_response_network_policy_active` | gauge | `state` | Olaitan-managed NetworkPolicies per kind (`restricted`/`quarantined`), refreshed each reconcile from the managed-policy list |
| `olaitan_response_audit_transitions_dropped_total` | counter | (none) | AUDIT.transitions events dropped on buffer overflow during a NATS outage |
| `olaitan_response_audit_policies_dropped_total` | counter | (none) | AUDIT.policies events dropped on buffer overflow |

**Metric-name reconciliation (Story 2.9 BI-2).** epics.md Story 2.9 spells the
NetworkPolicy metrics `olaitan_response_networkpolicy_apply_duration_seconds`
etc.; the SHIPPED family (Story 2.4) is `olaitan_response_network_policy_apply_seconds`
and `_apply_total{result}`. The shipped `network_policy` names are authoritative
(renaming would break Story 2.4 tests + operator dashboards for a cosmetic
spelling); the new `network_policy_active` gauge follows that shipped family.

Sample PromQL (scaffolding; finalised in Epic 6):
- Runaway escalation: `sum(rate(olaitan_response_fsm_transitions_total{to_state="QUARANTINED"}[5m]))`
- Override misuse: `sum(rate(olaitan_response_override_applied_total[1h]))` and `olaitan_response_override_active`
- Stale policies: `olaitan_response_network_policy_active` vs `olaitan_response_fsm_active_workloads{state=~"RESTRICTED|QUARANTINED"}`
- Apply latency SLO (NFR6): `histogram_quantile(0.99, sum by (le) (rate(olaitan_response_network_policy_apply_seconds_bucket[5m])))`
- Audit loss: `increase(olaitan_response_audit_transitions_dropped_total[5m]) > 0`

#### Enabling graduated isolation via Helm (Story 2.10, FR47/FR49)

`helm upgrade olaitan deploy/helm/olaitan/` from an Epic 1 sensing-only
deployment adds the Epic 2 surface without disrupting in-flight evidence
packages (AC1). Isolation defaults OFF; enable it explicitly (it is NOT
auto-enabled by the RS evaluation arm). All knobs are surfaced in values.yaml
and overlaid onto the running config via the ConfigMap watcher (hot-reloadable
except where a per-knob comment marks it restart-required):

```
--set response.networkPolicy.enabled=true \
--set response.networkPolicy.clusterCidrs='{10.244.0.0/16,10.96.0.0/12}' \
--set response.override.enabled=true \
--set response.audit.enabled=true \
--set fsm.thresholds.suspicious=20 --set fsm.thresholds.restricted=40 --set fsm.thresholds.quarantined=70 \
--set fsm.dwellSeconds.restricted=120 --set fsm.deescalationCooldownSeconds=600 \
--set response.audit.retentionTransitionsDays=90
```

Operators MUST set `response.networkPolicy.clusterCidrs` to their cluster's
real pod/service CIDRs so in-cluster traffic and DNS survive the RESTRICTED
egress block. A values key left at its default leaves the baked
config/olaitan.yaml default untouched (the overlay only fires when the value is
set), so the chart and config defaults cannot diverge.

### LLM transport tier (Story 3.2, NFR4/NFR5/NFR18/NFR23/NFR27)

Story 3.2 lands the shared LLM provider interface (`internal/agent/provider/`)
and the Claude implementation (`internal/agent/provider/claude/`) over the
official `anthropic-sdk-go`. This resolves the architecture.md:308 deferral
(official SDK chosen over a raw HTTPS client: stable, typed error classes for
the retry predicate, custom base URL for the integration boundary, structured
output support). The package layout follows architecture.md:292 --
`internal/agent/provider/`, NOT `internal/decision/analyst/`, which
hosts the Story 3.5-3.7 agent code (the L1 runner landed in Story 3.5).

**Metric: `olaitan_llm_calls_total`** (counter, unitless).
Labels: `{provider, role, status}`; `provider` in `{claude, openai,
ollama}` (Stories 3.2-3.4), `role` in `{l1, l2, senior, dfir}`, `status`
in `{success, transient_failure, permanent_failure, timeout}`. Bounded
48-series family today (3 providers x 4 x 4); no per-workload label, per
the metrics.go:357-362 cardinality rule. Registration is SHARED and
idempotent (`provider.RegisterCallsMetric`, Story 3.3): every provider
increments the same family, so a dual-provider process (the Story 3.8
routing future) cannot hit a duplicate-registration error. The status is
the FINAL outcome of the whole retried call, incremented exactly once per
`Analyse` invocation:

| status | Meaning |
|---|---|
| `success` | The call returned a decoded response (possibly after retries). |
| `transient_failure` | Retries exhausted on 429/500/529/transport errors, or the parent context was cancelled (process shutdown). |
| `permanent_failure` | A non-retryable client error (400/401/403/404/413) aborted the call on the first attempt. |
| `timeout` | The per-role deadline itself expired (parent context still live). |

Sample PromQL -- dashboard rate:
`sum by (role, status) (rate(olaitan_llm_calls_total[5m]))`;
alerting predicate (sustained transport failure):
`sum(rate(olaitan_llm_calls_total{status=~"transient_failure|timeout"}[10m])) > 0.1`.

**Metric: `olaitan_decision_llm_calls_total`** (counter, unitless).
Labels: `{provider, role, status}`; `role` in `{l1, l2, senior}` (the
emitting chain roles; the DFIR agent reports through the transport family
only), `status` is the architecture B7 `llm_status` enum. One increment
per PROVIDER-REACHING runner `Run` (Story 3.5; a package with no citable
event ids fails fast with ErrNoCitableEvents before the provider call and
records nothing): this is the DECISION-level outcome after
response validation, complementing the transport-level
`olaitan_llm_calls_total` (one `Run` maps to exactly one `Analyse` call,
which may itself have retried internally). Bounded envelope 3 providers
x 3 roles x 4 statuses = 36 series. The l1 (Story 3.5) and l2 (Story
3.6) and senior (Story 3.7) runners increment the family; registration
happens in the runner constructors, so before the Story 3.8 trigger
wires the chain into the production binary the family is neither
registered nor populated there. The full 36-series envelope is live
code as of Story 3.7 (the analyst.Chain orchestrator sequences all
three roles). Registration is SHARED and idempotent
(`analyst.RegisterDecisionCallsMetric`), so the Story 3.6/3.7 runners
join the same family.

| status | Meaning |
|---|---|
| `success` | The reply parsed, validated against its role schema (`l1_hypothesis.v1` / `l2_verification.v1`) and passed the referential checks. |
| `unavailable` | `Provider.Analyse` failed (transport failure, exhausted retries, the per-role timeout, or caller-context cancellation), or the reply was truncated by the output-token ceiling (stop reason `max_tokens`/`length`). |
| `schema_violation` | The reply failed its role schema contract: empty body, undecodable JSON, JSON-Schema failure (incl. the size bounds), whitespace-only hypothesis/finding text, a duplicated narrative `event_id` (L2), or a referenced `event_id` absent from the input package. |
| `success_low_confidence` | RESERVED for Story 3.11 (a validated assessment below the acting threshold; the threshold lives with the score fold, so the reservation moved from 3.7 to 3.11); never emitted before then. |

Sample PromQL -- schema-violation rate per provider (feeds the Story
3.10 three-strike policy dashboards):
`sum by (provider) (rate(olaitan_decision_llm_calls_total{status="schema_violation"}[10m]))`.

**Metric: `olaitan_decision_llm_l2_skipped_total`** (counter, unitless).
Labels: `{reason}`, bounded set: `l1_unavailable` (the L1 stage failed
with provider unavailability, so the chain short-circuits to
Senior-on-evidence-only mode; Story 3.10 may extend the set). One
increment per investigation chain that skips L2, recorded by the Story
3.7 orchestrator at the `analyst.ShouldSkipL2` gate (Story 3.6 BI-6).
A schema violation does NOT skip L2 before Story 3.10's three-strike
escalation. The bounded reason set as of Story 3.7: `l1_unavailable` and
`l1_schema_violation` (the single pre-3.10 L1 attempt returned a schema
violation, so there is no hypothesis to verify; Story 3.10's
three-strike policy re-routes this class). NOTE the `l1_unavailable` reason inherits the full
`unavailable` status semantics of the decision family: transport
failure, exhausted retries, the per-role timeout, output-token-ceiling
truncation, and caller-context cancellation all qualify, so the label
measures chain short-circuits, not provider outages specifically
(Story 3.10 may split the reason set). Increment via
`analyst.RecordL2Skip` (refuses the empty no-skip reason). Registration
is shared and idempotent (`analyst.RegisterL2SkippedMetric`). Alerting
sketch, effective once Story 3.8 wires the chain trigger -- sustained
L1 failure starving the verification stage:
`sum(rate(olaitan_decision_llm_l2_skipped_total{reason="l1_unavailable"}[10m])) > 0.05`.

**Metric: `olaitan_llm_cap_violation_total`** (counter, no labels; renamed
from `olaitan_decision_llm_cap_violation_total` to the FR50 canonical name in
Story 3.15).
Refused attempts to write an `llm_capped_confidence` above the Senior
provider's score cap: the Trust-Bounded LLM Integration code guard
(Story 3.7 AC3, `analyst.GuardCappedConfidence`). ZERO in healthy
operation -- the orchestrator caps by construction via
`min(raw_confidence, ScoreCap)`, so any increment means a code path
bypassed the cap arithmetic; alert on ANY increment:
`increase(olaitan_llm_cap_violation_total[5m]) > 0`. The Story
3.11 FSM-feeding path MUST route through the same guard. Both
`raw_confidence` and `llm_capped_confidence` are recorded on the
assessment for audit traceability (AC2); the architecture bound
max(LLM-only ThreatScore) = 0.3 x 35 = 10.5 is pinned by
TestCapBoundProperty against the score package constants.

**Metric: `olaitan_investigation_chain_runs_total`** (counter, labels
`mode`, `outcome`). One increment per `EvidencePackage` for which the chain
is invoked. **Story 3.11:** the standalone `olaitan-investigation-chain`
consumer was REMOVED and the chain is now run INLINE by the single
deterministic FSM consumer (`olaitan-response-fsm`) -- it runs the chain on
the FR19 trigger, folds the capped LLM confidence into the ThreatScore, and
drives the FSM once, so a workload's LLM contribution and its FSM transition
are decided in one place (and an inline-chain panic is recovered to a
deterministic-only score, never crashing the FSM). `mode` is the configured chain
boundary: `full` (L1->L2->Senior), `l1_l2` (Senior ablated off), or
`l1_only` (L2 + Senior ablated off). `outcome` is `not_triggered` (the
FR19 gate declined: no rule severity >= 50 and no baseline sigma >= 3.0),
`assessed` (the chain PRODUCED an assessment; the `AUDIT.assessments`
publish is best-effort and a publish failure is logged separately, so the
metric does not over-claim persistence), `no_citable` (the chain aborted
on empty citable
evidence -- the Story 3.6 chain-level concern, no retry; Story 3.10 owns
retries), or `error`. A high `not_triggered` ratio is expected and
healthy (the gate controls LLM cost). A sustained `error` rate is a
provider/transport problem:
`sum(rate(olaitan_investigation_chain_runs_total{outcome="error"}[10m]))`.

**Investigation chain (Story 3.8, FR19/FR25/FR27/FR53).** The chain is
TRIGGERED only on qualifying packages (FR19 gate above) and routes each
role to its own provider+model via the Helm values
`analyst.{l1,l2,senior}_{provider,model}` (FR25; per-role provider is a
concrete family claude/openai/ollama or "" to inherit the top-level
`analyst.provider` mapping api->claude / local->ollama). Per-provider
trust caps are enforced in code (claude 35 / openai 30 / ollama 25); an
openai-routed role caps at 30, never the claude-tier 35, with a tighter
global `analyst.score_cap` acting as an operator ceiling. **Ablation
(FR53):** `analyst.l2_enabled: false` runs L1-only (Senior also off);
`analyst.senior_enabled: false` runs L1+L2; the assessment records which
roles ran via `agents_available`. **Bypass (FR27/NFR27):**
`analyst.provider: none` builds no chain -- `EvidencePackage` objects are
still consumed and scored by the FSM on rules-and-baselines-only
ThreatScores, and the rules-only mode is disclosed once at startup. NOTE
the chain produces and audits assessments but does NOT yet move the FSM
ThreatScore: the LLM score fold is Story 3.11 (`score.go` LLM term stays
0 until then).

**Audit subject `AUDIT.assessments`** (`audit.assessments.v1`, Story 3.8
AC4). One event per investigation-chain run, carrying `mode` and
`agents_available` so the ablation boundary is auditable, plus
`raw_confidence`/`llm_capped_confidence` for trust-bound traceability.
Published synchronously by the chain consumer (`WithMsgID` = package_id).
Story 3.14 owns the broader audit pipeline and may extend the payload.

**Investigation checkpoints `INVESTIGATIONS.{package_id}.{l1,l2}`** (Story
3.9, FR29). The chain checkpoints each completed L1/L2 output to a dedicated
`INVESTIGATIONS` JetStream stream (LimitsPolicy, FileStorage, 6h default
retention, Helm-tunable via `analyst.checkpoint_retention`) so a controller
restart resumes from the last completed step rather than re-spawning it. The
checkpoint store publishes with `WithMsgID = package_id + step` (idempotent
re-publish within the dedup window) and resumes by reading the last message
per subject. The stream is capped at `MaxMsgsPerSubject: 1`, so even a
re-publish after the dedup window expires cannot accumulate stale duplicates —
the resume read is the canonical last value for the full retention. **Resume is
structural:** the chain consumer acks the `EvidencePackage` only AFTER the
chain completes, so a crash mid-chain leaves it un-acked; JetStream
redelivers it and the chain re-checks the checkpoints, re-running only the
un-checkpointed steps (the Senior is never checkpointed, so a post-L2 restart
re-runs only the Senior). Checkpointing is best-effort durability: a publish
or read failure logs and the step re-runs, never aborting the chain. A
6h-stale checkpoint simply means the chain re-runs from scratch (the retention
floor). Operational note: the INVESTIGATIONS stream is NOT a SIEM audit
subject (it is short-lived resume data); do not point SIEM ingest at it.

**LLM-tier circuit breaker** (Story 3.12, FR51/NFR23). A global breaker counts
LLM-eligible packages (those past the FR19 trigger gate) over a sliding
1-minute window; above `analyst.circuit_breaker.rate_per_min` (default 10)/min
it ENGAGES and the chain is bypassed (deterministic-only score, no LLM call)
until the rate stays at/below threshold for `cooling_seconds` (default 60s) --
so an attacker spraying triggering events cannot amplify LLM cost. Signals:
`olaitan_llm_circuit_breaker_engaged_total` increments once per engage edge,
`olaitan_investigation_chain_runs_total{outcome="breaker_bypassed"}` counts the
bypassed packages, and one structured log line is emitted per engage/disengage
(NOT per package). Both thresholds are Helm-tunable
(`analyst.circuit_breaker.{rate_per_min,cooling_seconds}`) and hot-reloaded.
Alert on a sustained `rate(olaitan_llm_circuit_breaker_engaged_total[10m]) > 0`:
either a real burst or a too-low threshold. Set
`analyst.circuit_breaker.enabled: false` (config-file) to disable.

**LLM retry, Ollama fallback, and `llm_unavailable`** (Story 3.10, FR26/FR28).
Each role's provider call runs under a 3-strike retry (exponential base delays
1s then 4s, capped at 16s, plus jitter; with 3 strikes only the 1s and 4s
back-offs are slept): a schema violation or a non-timeout transient provider
error is retried, while a per-call timeout yields immediately to the fallback
rather than retry-and-wait; a
deterministic precondition (no citable events / no hypothesis) fails fast and
is never retried. On primary exhaustion the chain falls through to the
configured Ollama endpoint (`analyst.local`) for that single role call — not
the rest of the chain — under the same 3-strike retry, and increments
`olaitan_llm_fallback_total{from_provider, to_provider, role}` once at the
fall-through (regardless of whether Ollama then succeeds). A role with no
fallback (already on Ollama, or `analyst.local` unset) skips the fall-through.
When BOTH primary and fallback exhaust, the role is marked unavailable: L1 ->
skip L2 and run the Senior on evidence only; L2 -> run the Senior on the
hypothesis only; **Senior -> a degraded assessment marked `llm_unavailable`
with `llm_capped_confidence: 0`, so the workload is decided on the deterministic
ThreatScore alone** (the chain does NOT abort — rules-and-baselines-only is
always available, NFR27). Expected signals: a sustained
`rate(olaitan_llm_fallback_total[10m]) > 0` means the primary provider is
flaky and Ollama is absorbing the load; a rising
`olaitan_decision_llm_calls_total{status="unavailable"}` with fall-throughs
also failing means both tiers are down and assessments are degrading to
deterministic-only. The fallback retries multiply provider-reaching attempts,
so `olaitan_decision_llm_calls_total` increments once per attempt (up to 3 per
provider per role), not once per chain.

**Per-role timeout table (total budget across ALL retry attempts):**

| role | budget |
|---|---|
| `l1` | 30s |
| `l2` | 30s |
| `senior` | 60s |
| `dfir` (reserved, Epic 4) | 120s |

The role timeout is the TOTAL budget for the attempt loop including backoff
(worst case 1s+4s of sleep across 3 attempts), not per-attempt. Story 3.8
makes these config-routable.

**Retry ownership.** The SDK's built-in auto-retry is DISABLED
(`option.WithMaxRetries(0)`); `internal/retry` owns all retries with
`Strategy{Min:1s, Max:16s, Multiplier:4, Jitter:1, MaxAttempts:3}` so the
attempt count and backoff stay observable and single-source-of-truth, and the
metric above cannot be corrupted by hidden SDK attempts. Error classification
is by the SDK's typed `*anthropic.Error` status code, never substring
matching: 400/401/403/404/413 abort immediately; 429/500/529 and transport
errors retry.

**API key wiring and the NFR18 guarantee.** `analyst.api.api_key_secret`
NAMES the environment variable the Kubernetes Secret is projected into (the
config loader never reads the value); `cmd/olaitan` reads that env var once
at startup and passes the value into the provider constructor. The key is
never logged, never a metric or audit label, and never embedded in an error;
the construction log records the BOOLEAN `api_key_set` only. The Helm wiring
that projects the Secret lands in Story 3.16.

### Agent prompt tuning and versioning (Story 3.13, NFR41/FR49 prompt half)

The per-role L1/L2/Senior system prompts (and an Epic-4 DFIR placeholder)
live as files: `internal/agent/prompts/defaults/<role>.txt` in the repo, and
at runtime in the `{release}-prompts` ConfigMap mounted read-only at
`analyst.prompts.mountPath` (default `/etc/olaitan/prompts/`; the rendered
config's `analyst.prompts_dir` tracks it). A role whose `<role>.txt` is absent
from the mount falls back to the controller's binary-embedded default, so an
operator may override a subset of roles.

**Hot-reload (no restart).** Edit the ConfigMap (`kubectl edit configmap
{release}-prompts`, or `helm upgrade` with a values override). The prompts
watcher — a dedicated fsnotify listener on the mount directory, mirroring the
rules-corpus loader — catches the K8s projected-volume `..data` symlink swap,
debounces 50 ms, content-hashes the new prompts, and atomically swaps the
prompt on every chain runner (primary L1/L2/Senior plus their Ollama-fallback
twins). The change is picked up on the **next** investigation call; no
`kubectl rollout restart`. Each role whose content hash moved emits one
`prompt_version_changed{role,old_hash,new_hash}` log line. A reload that fails
to parse (oversized or unreadable file) is logged `prompts: reload rejected`
and the prior prompts are retained — the pod stays Ready.

**Versioning and audit (NFR41).** The prompt-content hash (lowercase hex
SHA-256 of the newline-trimmed text) is the prompt version recorded with every
assessment on `AUDIT.assessments` (Story 3.14), so each verdict is traceable to
an exact prompt revision — essential for evaluation reproducibility. Any change
to a `defaults/*.txt` file MUST be recorded in `docs/prompt-changelog.md` with
the new hash in the same PR; the `prompt-changelog` CI job
(`hack/check-prompt-changelog.sh`) fails the PR otherwise. To compute a hash
locally: `printf '%s' "$(cat internal/agent/prompts/defaults/l1.txt)" |
sha256sum`.

**Disabling the ConfigMap.** Set `analyst.prompts.enabled: false` to drop the
ConfigMap and its mount; the controller then runs on the image-baked embedded
defaults for every role (operators lose hot-reload and per-role override).

**Clean degradation (no key).** When `analyst.provider` is not the API path
or the projected env var is empty, the Claude provider is simply not
constructed: the controller starts normally and runs rules-only (RS mode);
the deterministic ThreatScore path is unaffected. The rules-only fallback
POLICY for mid-flight LLM failures is Story 3.10 scope.

**Request surface (Opus 4.8).** Analyst calls are non-streaming with
thinking explicitly disabled and a bounded `max_tokens` (default 4096); no
sampling parameter (`temperature`/`top_p`/`top_k`) and no `budget_tokens` is
ever sent (removed on Opus 4.8; they return HTTP 400). Default model
`claude-opus-4-8`, operator-pinnable via `analyst.api.model` (exact model ids
only, never a date suffix). Evidence is redacted via the Story 3.1 pipeline
BEFORE the wire payload is built; the captured-request-body integration test
is the proof.

**OpenAI-compatible provider (Story 3.3).** A second `Provider`
implementation at `internal/agent/provider/openai_compat/` speaks the
lowest-common-denominator Chat Completions shape over a hand-rolled stdlib
client (no SDK dependency): `POST {base}/chat/completions`, `max_tokens`
(never `max_completion_tokens`), `Authorization: Bearer`, no sampling
params, `stream: false`. `Name()` is `openai` -- the family identity for
the metric label and the Story 3.8 routing key; the BaseURL selects the
vendor (default `https://api.openai.com/v1`; Together
`https://api.together.xyz/v1`; Groq `https://api.groq.com/openai/v1`; any
LiteLLM/vLLM proxy). The BaseURL must be an absolute http(s) URL without
userinfo credentials; anything else fails construction with
`ErrBadBaseURL` (fail-fast: a bad endpoint would otherwise retry forever
as transient, and userinfo would leak into the construction log). The
model id is REQUIRED (no cross-vendor default
exists; the constructor returns `ErrNoModel`), and the context window is
the `MaxContextTokens` config knob (default 128000) because compatible
vendors are unenumerable. The client never follows redirects: a 3xx from
a misconfigured endpoint surfaces as a typed transient error instead of
converting the POST to a GET and re-sending the bearer token to the
redirect target. Upstream error bodies are bounded (4 KiB read, 256 B
kept) and laundered (key scrub, control-character flattening) before any
error string or log line is built, because some vendors echo key material
in 401 bodies. Retry, per-role timeouts, redaction-before-send,
key hygiene, the outcome metric, and the degenerate-200 guards (null body,
empty choices) behave identically to the Claude provider; the shared
helpers in `internal/agent/provider/` enforce the parity. The provider is
NOT yet wired in cmd/olaitan: no config discriminator exists between the
Claude and OpenAI paths under `analyst.provider: api`; Story 3.8 owns the
per-role routing that makes it reachable.

**Known limitations (tracked, not blocking).**
(a) An explicit `analyst.score_cap: 0` is currently indistinguishable from
an omitted field (Go zero value) and is coerced to the default 35; an
operator intending "LLM contributes nothing" should use
`analyst.provider: none` until Story 3.11 (which owns cap enforcement)
introduces the unset-vs-zero distinction.
(b) The provider's `max_tokens` ceiling is programmatically tunable
(`claude.Config.MaxTokens` / `openaicompat.Config.MaxTokens`) but has no
`analyst.*` config field yet; the operator-facing knob lands with the
Story 3.16 Helm wiring. Until then the default 4096 applies.
(c) A well-formed 200 reply with an empty message object (Claude), an
empty `choices[0].message.content` (OpenAI-compatible), or an empty
`message.content` (Ollama) yields `Response.Raw == ""` recorded as
`success`; callers (Stories 3.5-3.7) must treat an empty `Raw` as a
failed verdict.

**Air-gapped / data-residency mode (Story 3.4, FR48).** When
`analyst.provider` is `api`, evidence packages cross the cluster
boundary into a third-party LLM provider. Operators under
data-residency constraints run the LLM tier fully in-cluster instead
via the Ollama provider at `internal/agent/provider/ollama/`, which
speaks the NATIVE `/api/chat` endpoint over a hand-rolled stdlib
client (no SDK, no external egress).

- **Provider selector.** The config value is `local`
  (`analyst.provider: local` plus `analyst.local.{endpoint, model}`);
  the PRD-level spelling `analyst.provider: ollama` arrives as a Helm
  alias with Story 3.16's evaluation-mode wiring. Provider changes are
  restart-required (`kubectl rollout restart deploy/olaitan-aggregator`).
- **No credential exists.** There is no API key, no Authorization
  header, and no `api_key_set` construction-log field for this
  provider: the chart-rendered NetworkPolicy is the auth boundary
  (ingress to the Ollama pod only from the aggregator pod selector on
  11434; egress declared and EMPTY; the release policy excludes the
  ollama component so the NetworkPolicy union cannot re-grant what the
  ollama policy denies). PRECONDITION: NetworkPolicy isolation requires
  an enforcing CNI (the project's Calico deployment enforces; a
  non-enforcing CNI such as bare flannel leaves the credential-free
  Ollama pod reachable cluster-wide). The endpoint must be an absolute
  http(s) URL without userinfo, query, or fragment; anything else
  fails construction with `ErrBadEndpoint`.
- **Trust cap ladder.** The Ollama tier contributes at most
  `score_cap` 25 of 100 to the ThreatScore (versus 35 Claude-tier, 30
  OpenAI-class) -- a smaller local model earns less algebraic trust.
  The 25 default ships in the package; the FILE-SIDE config default is
  the Claude-tier 35, so set `analyst.score_cap: 25` (Helm-bridged;
  values-airgapped.yaml does this) for the local tier -- the aggregator
  logs a loud warning at startup when the configured cap exceeds 25 on
  the local path. Enforcement on assessments is Story 3.7 scope.
- **Model provisioning is operator-owned.** The chart deploys the
  server only (`ollama.enabled: true` renders the Deployment, Service,
  and NetworkPolicy; default false). Bake the model into the image or
  pre-populate a volume (`ollama.persistence.existingClaim`); in a true
  air-gapped cluster `ollama pull` has nowhere to pull from.
  `analyst.local.model` must name a model that is actually present: an
  empty model degrades to rules-only at startup, and a wrong name
  surfaces as a PERMANENT 404 on every call (a 404 from Ollama means
  "model not provisioned", not a transient outage).
- **Context-window pairing.** The provider never sends
  `options.num_ctx`; the EFFECTIVE context window is the server-side
  `num_ctx` (small by default regardless of model capability). The
  provider's `MaxContextTokens` knob defaults to a conservative 4096 to
  match; an operator who raises `num_ctx` (Modelfile, or
  `OLLAMA_CONTEXT_LENGTH` via the chart's `ollama.extraEnv`) should
  raise the knob to the same value so the Story 3.5-3.7 prompt
  budgeter neither lies nor starves.
- **Cold-load and Health.** First use loads the model into memory; a
  cold 70b-class load takes minutes, during which the provider's
  1-token Health probe honestly reports unhealthy. Warm the model after
  deploy (one throwaway chat request, or a server-side `keep_alive`
  policy) before relying on Health-gated automation.
- **Reference overlay.** `deploy/helm/olaitan/values-airgapped.yaml`
  is the documented FR48 reference: in-cluster Ollama enabled,
  `analyst.provider: local` with a pinned model and `score_cap: 25`,
  and `networkPolicy.extraEgress` left empty (the point). The
  `analyst.local.*` and `analyst.score_cap` values are bridged into
  the rendered olaitan.yaml by the chart (the same overlay mechanism
  as `analyst.provider`), so a Helm-set value is never a silent no-op;
  when `ollama.enabled` is on and no endpoint is set, the chart
  DERIVES the rendered Service DNS for the actual release and
  namespace, so the overlay works under any install name.

### 1.4d LLM observability surface (Story 3.15, FR50/NFR32)

The complete FR50 LLM-tier metric set. Each carries a documented type, unit,
and bounded label set (NFR32). The five Epic-6 Grafana panels ("LLM provider
health", "Per-role latency", "Cap-violation alerts", "Circuit breaker
engagement", "Prompt version history") derive from exactly these.

| Metric | Type | Unit | Labels | Story |
|---|---|---|---|---|
| `olaitan_llm_calls_total` | counter | calls | `provider`, `role`, `status` | 3.2 |
| `olaitan_llm_call_duration_seconds` | histogram | seconds | `provider`, `role` | 3.15 NEW |
| `olaitan_llm_fallback_total` | counter | fall-throughs | `from_provider`, `to_provider`, `role` | 3.10 |
| `olaitan_llm_cap_violation_total` | counter | violations | (none) | 3.7 (renamed 3.15) |
| `olaitan_llm_circuit_breaker_engaged_total` | counter | engagements | (none) | 3.12 |
| `olaitan_llm_prompt_version` | gauge (info) | 1 | `role`, `hash` | 3.15 NEW |

Sample PromQL (one per panel):
- **Provider error rate:** `sum by (provider) (rate(olaitan_llm_calls_total{status!="success"}[5m])) / sum by (provider) (rate(olaitan_llm_calls_total[5m]))`.
- **Per-role p99 latency:** `histogram_quantile(0.99, sum by (le,role) (rate(olaitan_llm_call_duration_seconds_bucket[5m])))` — alert when the L1/L2 series exceeds the 30 s budget or Senior the 60 s budget (NFR4/NFR5).
- **Fallback rate (primary flaky):** `sum by (role) (rate(olaitan_llm_fallback_total[10m])) > 0` sustained means the primary provider is failing and Ollama is absorbing.
- **Cap-violation alert (trust-bound breach):** `increase(olaitan_llm_cap_violation_total[5m]) > 0` — page on ANY increment; a healthy system caps by construction.
- **Circuit-breaker engagement:** `increase(olaitan_llm_circuit_breaker_engaged_total[10m]) > 0` — an attack-driven cost burst or a too-low `rate_per_min`.
- **Prompt-version history (drift):** `olaitan_llm_prompt_version` — exactly one series per role reads 1; `count by (role) (olaitan_llm_prompt_version) > 1` should never fire, and a `changes()` over the `{role,hash}` series timeline shows when a prompt was tuned (correlate with the `prompt_version_changed` log and the `AUDIT.assessments` prompt hashes).

Note: `olaitan_decision_llm_calls_total{provider,role,status}` (the analyst DECISION-outcome counter) and `olaitan_decision_llm_l2_skipped_total` are additional internal metrics distinct from the FR50 transport surface above; they keep their `decision_` names.

### 1.4e Evaluation-matrix arms and LLM chain shape (Story 3.16, FR53)

The chart selects a canonical Epic-5 evaluation arm with the single switch
`evaluation.config`. Each arm overlays the effective `rules.enabled`,
`baselines.enabled`, `analyst.provider`, `analyst.l2_enabled`, and
`analyst.senior_enabled` values (computed by the `olaitan.evaluation.effective*`
templates in `_helpers.tpl:181-289`), so an operator cannot silently invalidate
the across-arm comparison by setting the individual knobs. `evaluation.config`
is restart-required; roll the aggregator after a change.

| Arm | rules | baselines | provider | l2 | senior | Effective analyst chain |
|---|---|---|---|---|---|---|
| `F` | false | false | none | n/a | n/a | Falco-only; no deterministic layer, LLM tier bypassed |
| `RS` | true | true | none | n/a | n/a | Rules + statistics; LLM tier bypassed |
| `RSL` | true | true | api | false | true | Single-LLM analyst, L1 only (`senior` precedence collapses to L1-as-senior) |
| `RSLT-full` (alias `RSLT`) | true | true | api | true | true | Full chain L1 -> L2 -> Senior |
| `RSLT-L1-only` | true | true | api | false | true | L1-only ablation (L2 off => Senior off by Go-side `SeniorEnabledOrDefault` precedence) |
| `RSLT-L1+L2` | true | true | api | true | false | L1 + L2 ablation; no Senior |
| `""` | operator | operator | operator | operator | operator | No overlay; operator-supplied knobs flow through verbatim |

`olaitan.evaluation.validate` (`_helpers.tpl:153-160`) fails render with a clear
enum message when `evaluation.config` is outside this set. **Trust-bound holds in
every arm:** enabling more analyst stages never lets the LLM escalate the FSM past
SUSPICIOUS; the LLM contribution stays capped (`0.3 x 35 = 10.5 < 20`), enforced
at the provider cap, the `GuardCappedConfidence` chokepoint, and the `score.go`
re-clamp regardless of which arm is deployed.

**Upgrading an Epic-2 RS-with-isolation deployment to LLM-enriched verdicts.** An
existing RS (rules + graduated-isolation, no LLM) install gains the multi-agent
analyst by switching to an LLM-bearing arm and supplying the API-key Secret the
provider dials:

```bash
helm upgrade olaitan deploy/helm/olaitan \
  --reuse-values \
  --set evaluation.config=RSLT-full \
  --set analyst.api.endpoint=https://<vendor-or-gateway>/v1 \
  --set analyst.api.apiKeySecret=olaitan-llm-api-key
kubectl rollout restart deploy/olaitan-aggregator
```

The `analyst.api.apiKeySecret` Secret is projected into the aggregator env by
`deployment.yaml:124-134`; without it the provider degrades to rules-only with an
`api_key_set=false` log (NFR18), so the chart never silently dials a public
endpoint with no key. The graduated-isolation response layer from Epic 2 is
unaffected; the LLM only enriches the verdict the FSM already bounds.

**Air-gapped routing (Ollama, FR48).** To run an LLM-bearing arm without egress to
a public vendor, route the analyst to the in-cluster Ollama instead of the `api`
provider: set `analyst.provider=local` and `ollama.enabled=true` (or apply the
`values-airgapped.yaml` overlay). That renders the `ollama` Deployment/Service plus
its NetworkPolicy (egress declared-empty, ingress only from the aggregator
selector), and the provider dials `http://ollama.olaitan.svc.cluster.local:11434`.
The NetworkPolicy **is** the authentication boundary here: the Ollama provider
takes no API key (`analyst.local.{endpoint,model}` is its only config). The local
ScoreCap defaults to 25, so the trust-bound is, if anything, tighter on the
air-gapped path.

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
