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

**Rejected overrides.** An override into `PRESERVED_KILLED` (Epic 4, not yet implemented) is REFUSED: no pin, no Redis key, an `OVERRIDES.applied` event with `rejected: true, reason: state_unavailable`, and the metric below increments with `reason="state_unavailable"`. A typo'd or non-enum state value is refused the same way with `reason="invalid_state"` so you can tell "you asked for a real-but-not-yet-implemented state" from "you mistyped the state".

The `OVERRIDES.applied` NATS subject (365-day JetStream retention) carries one event per applied AND per rejected override; its append-only `AUDIT.overrides` SIEM mirror ships in Story 2.8 (see "Append-only SIEM audit subjects" below).

### Append-only SIEM audit subjects (Story 2.8, FR40/NFR16)

When `response.audit.enabled=true` (off by default; one flag gates all three), the agent publishes three append-only NATS audit subjects for SIEM consumption (Splunk / Elastic / Datadog). Each rides a dedicated `LimitsPolicy` JetStream stream (append-only by retention: NFR16 means consumers cannot delete events) with Helm-tunable per-subject retention:

| Subject | Stream | Default retention | Records |
|---|---|---|---|
| `AUDIT.transitions` | `AUDIT_TRANSITIONS` | 90 d (`response.audit.retention_transitions_days`) | every actual FSM state change (`before_state`/`after_state`/`triggering_threat_score`/...), automated AND operator-pin |
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

Operational notes:
- **Two events per applied override, by design (BI-10):** an applied operator override emits one `AUDIT.transitions` (the state change, `trigger_type=override`) AND one `AUDIT.overrides` (the application, with TTL/source/attribution); a rejected override emits only `AUDIT.overrides`. They are complementary, correlated on `workload_id` + time. Do NOT "deduplicate" them.
- **Mutations only, not heartbeats (BI-9, Open Assumption 2):** an idempotent NetworkPolicy noop, a NotFound delete, and a no-op FSM evaluation produce NO audit event. Audit-stream volume tracks real activity, not reconcile cadence. For reconcile-cadence telemetry use the Story 2.9 Prometheus metrics.
- **Transitions retention is 90 d (BI-7):** this reconciles architecture.md:239's generalised "AUDIT.* 365 d" with the AC's specific 90 d for transitions (matching `STATE_TRANSITIONS.applied`); overrides/policies stay 365 d.
- **Best-effort, never blocks enforcement (BI-5):** a NATS outage drops audit events (with a warn + a dropped counter on the buffered transitions/policy paths) rather than stalling the FSM goroutine, the override poll, or the netpol apply worker. A missed audit line is an observability gap, not a control-plane failure.

#### `olaitan_response_override_rejected_total` (Story 2.7, FR38/FR39)

- **Type:** Counter vector, labelled `reason`.
- **Labels:** `reason` is `state_unavailable` (a real-but-unimplemented target such as `PRESERVED_KILLED`) or `invalid_state` (an unknown/typo'd state value). Both label series are pre-initialised to 0 at startup so alert PromQL has a stable zero baseline.
- **Meaning:** cumulative count of operator-override requests the controller refused. A non-zero `state_unavailable` is expected if operators try to pin `PRESERVED_KILLED` before Epic 4; a rising `invalid_state` indicates operators are mistyping the annotation value.
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
`internal/agent/provider/`, NOT the empty `internal/decision/analyst/`
placeholder, which is reserved for the Story 3.5-3.7 agent code.

**Metric: `olaitan_llm_calls_total`** (counter, unitless).
Labels: `{provider, role, status}`; `provider` in `{claude, openai}` (Story
3.3; Story 3.4 adds `ollama`), `role` in `{l1, l2, senior, dfir}`, `status`
in `{success, transient_failure, permanent_failure, timeout}`. Bounded
32-series family today (2 providers x 4 x 4); no per-workload label, per
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
(c) A well-formed 200 reply with an empty message object (Claude) or an
empty `choices[0].message.content` (OpenAI-compatible) yields
`Response.Raw == ""` recorded as `success`; callers (Stories 3.5-3.7) must
treat an empty `Raw` as a failed verdict.

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
