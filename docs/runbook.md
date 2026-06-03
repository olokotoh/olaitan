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
- **Per-workload telemetry:** the per-workload warm-up detail (which specific workloads are in warm-up at any given moment) is surfaced through the `AUDIT.transitions` subject documented in `architecture.md:380`, not through Prometheus. SIEM-side consumers subscribe to the audit subjects when they need pod-level granularity.

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
- **Help:** Observation of each ThreatScore component contribution (rules, baseline, llm) labelled by the package's result_bucket. Buckets `[0, 25, 50, 75, 100]` cover the 0-100 contribution range; the `llm` component is identically zero in Epic 2 (the slot is wired for Epic 3 to populate).
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
- **Labels:** `result` (one of `applied`, `noop`, `error`, `skipped`, `dropped`, `gc_deleted`).
- **Help:** Cumulative NetworkPolicy enforcement actions by result (FR33). `applied` = a policy created or updated; `noop` = an idempotent re-apply that matched the live object; `skipped` = a workload in an excluded namespace or already deleted; `dropped` = a transition dropped because the apply queue was full; `gc_deleted` = an orphan policy garbage-collected after its workload was removed.
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

The replacement of the RESTRICTED policy by the QUARANTINED policy is atomic from the workload's perspective: there is never a window with no policy at all. The manager uses apply-before-delete with distinct deterministic names. It FIRST applies the `olaitan-quarantined-<hash>` deny-all policy (via the same idempotent get-then-create-or-update path RESTRICTED uses) and, ONLY after that apply returns success, best-effort deletes the `olaitan-restricted-<hash>` policy for the same workload. During the brief overlap both policies select the pod, and their union is strictly more blocked, never less: NetworkPolicies are additive and restrictive, so the deny-all quarantine policy can only remove permission the restricted policy granted, and ingress is denied outright by the quarantine policy regardless of the restricted policy's silence on ingress. The manager never deletes the old policy before the new one is confirmed.

The supersession delete of the RESTRICTED policy is best-effort and silent by default. A failed delete does NOT fail the QUARANTINED enforcement: the workload is already fully blocked by the quarantine policy, and the stale restricted policy is benign (it only ever adds egress permission the quarantine policy overrides). A transient delete failure is logged at WARN and is reconciled by the next QUARANTINED re-emit or by the orphan GC when the owner is deleted; it is not counted under a separate metric result. The same two real-world limitations as RESTRICTED apply: enforcement depends on a NetworkPolicy-compliant CNI, and a pre-existing permissive third-party policy selecting the same pod can union to permit traffic the quarantine intends to block.

A controller shutdown timed precisely between a successful quarantine apply and the supersession delete can leave the superseded `olaitan-restricted-<hash>` policy in place until the next orphan-GC cycle removes it (once its owner is deleted). This does NOT reduce protection: the deny-all `olaitan-quarantined-<hash>` policy is already active and is strictly stricter than the restricted policy, so the stale restricted policy only adds egress permission the deny-all overrides. The two policies select the same pod and their union is the deny-all. The leftover restricted object is therefore benign and self-healing; no operator action is required beyond awaiting the GC cycle.

De-escalation removal is out of scope here. Story 2.5 handles only escalation INTO QUARANTINED; it does not remove the quarantine policy on QUARANTINED->RESTRICTED, nor restore the egress-only policy, nor handle ->SUSPICIOUS/->CLEAN removal. Those lock-step removals are Story 2.6. A quarantine policy that is never removed except by orphan GC is therefore expected until Story 2.6 lands; the distinct `olaitan-restricted-<hash>` vs `olaitan-quarantined-<hash>` names are what let Story 2.6 remove the quarantine object and restore the restricted object independently.

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
