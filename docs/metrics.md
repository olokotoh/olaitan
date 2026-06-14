# Forensic-tier metric reference (Epic 4)

Scope: this is the canonical reference for the **forensic-reporting (Epic 4) Prometheus metric set** exposed by the DFIR agent, the durable S3 report writer, the deferred-report queue, and the optional notification webhook. It records, per metric, the four NFR32 fields: Prometheus **type**, **unit**, **label set**, and one sample **PromQL** query.

This is a structured REFERENCE table, not operator narrative. The FULL operator runbook for the forensic tier (alert design, SLO narrative, dashboards, escalation playbook) is **Epic 6** (Story 4.9 AC4 reads "the runbook is updated (Epic 6)"); Story 4.9 delivers the canonical metric NAMES, LABEL SETS, and TYPES plus this reference so that runbook is writable. The deterministic-detection metric catalogue (collector / correlator / decision rings) lives in `docs/runbook.md` Section 1.

Audience: SREs consuming the Prometheus surface at `:9090/metrics`. FR50 (Prometheus surface mandatory), NFR32 (every metric documented with type, unit, label set, sample PromQL).

## Provenance (Story 4.9 reconciliation)

Story 4.9 reconciled the Epic-4 forensic metric names to their canonical forms. The two DFIR generation metrics were RENAMED from their unreleased Story-4.4 ad-hoc names (safe: Epic 4 is `epic-4-staging`-only, never promoted to `main`, so no dashboard depends on them yet); the DFIR call counter gained a `provider` label (mirroring the Epic-3 `olaitan_llm_calls_total{provider,role,status}` precedent); a NEW settling-window gauge and a NEW deferred-drained counter were added; and the Story-4.7 `result="drained"` value was RETIRED from the shared writes counter in favour of the dedicated drained counter (one source of truth, no double-count).

| Old name (epic-4-staging) | Canonical name | Action |
|---|---|---|
| `olaitan_dfir_reports_total{status}` | `olaitan_report_dfir_calls_total{provider,status}` | RENAME + add `provider` label |
| `olaitan_dfir_report_generation_seconds` | `olaitan_report_dfir_duration_seconds` | RENAME |
| (none) | `olaitan_report_settling_window_active{state}` | NEW gauge |
| `olaitan_report_writes_total{result="drained"}` | `olaitan_report_writes_deferred_drained_total` | RECONCILE: add counter, retire the `drained` value |

## DFIR agent (AC1)

### `olaitan_report_dfir_calls_total`

- **Type:** counter
- **Unit:** count (one increment per forensic-report generation attempt)
- **Label set:** `{provider, status}` — `provider` is the DFIR provider `Name()` (e.g. `claude`, `ollama`, `openai_compat`; the literal `unknown` when the provider name is empty); `status` in `{success, unavailable, schema_violation}`. Statically bounded (`{providers} x 3 statuses`).
- **Sample PromQL (generation-failure rate over 5m):**
  ```promql
  sum(rate(olaitan_report_dfir_calls_total{status!="success"}[5m]))
    / sum(rate(olaitan_report_dfir_calls_total[5m]))
  ```

### `olaitan_report_dfir_duration_seconds`

- **Type:** histogram
- **Unit:** seconds (agent invocation to rendered report)
- **Label set:** (none)
- **Sample PromQL (p99 generation latency against the NFR7 10s budget):**
  ```promql
  histogram_quantile(0.99, sum(rate(olaitan_report_dfir_duration_seconds_bucket[5m])) by (le))
  ```

### `olaitan_report_settling_window_active`

- **Type:** gauge
- **Unit:** active-windows (the number of currently-armed settling windows, by candidate final state)
- **Label set:** `{state}` — the candidate `final_state` FSM string (`SUSPICIOUS`, `RESTRICTED`, `QUARANTINED`, `PRESERVED_KILLED`). Incremented on the first arm of a window for a workload in a non-CLEAN state, decremented on finalisation or a CLEAN cancel; a re-arm that changes the candidate state moves the count from the old state series to the new (no double-count for the same active window). Statically bounded (4 non-CLEAN states).
- **Sample PromQL (settling windows currently armed, by state):**
  ```promql
  sum(olaitan_report_settling_window_active) by (state)
  ```

## S3 report writer + deferred queue (AC2)

### `olaitan_report_writes_total`

- **Type:** counter
- **Unit:** count (one increment per durable-write outcome)
- **Label set:** `{result}` — `result` in `{success, deduped, error, retried, deferred}`. (The `drained` value is RETIRED as of Story 4.9; a successful drain is counted on `olaitan_report_writes_deferred_drained_total` instead.) Statically bounded.
- **Sample PromQL (durable-write error rate over 5m):**
  ```promql
  sum(rate(olaitan_report_writes_total{result="error"}[5m]))
  ```

### `olaitan_report_write_duration_seconds`

- **Type:** histogram
- **Unit:** seconds (PUT start to confirmed durable write)
- **Label set:** (none)
- **Sample PromQL (p99 write-tail latency):**
  ```promql
  histogram_quantile(0.99, sum(rate(olaitan_report_write_duration_seconds_bucket[5m])) by (le))
  ```

### `olaitan_report_writes_deferred_count`

- **Type:** gauge
- **Unit:** count (live depth of the Redis-backed `reports:deferred` queue)
- **Label set:** (none)
- **Sample PromQL (alert: a non-zero deferred backlog means S3 is down):**
  ```promql
  olaitan_report_writes_deferred_count > 0
  ```

### `olaitan_report_writes_deferred_drained_total`

- **Type:** counter
- **Unit:** count (one increment per deferred report successfully re-PUT to the durable archive when S3 recovered)
- **Label set:** (none). This is the SINGLE source of truth for drains (Story 4.9 BI-5); a HEAD-deduped drain stays `result="deduped"` on `olaitan_report_writes_total` and is not counted here.
- **Sample PromQL (drain throughput during a recovery):**
  ```promql
  sum(rate(olaitan_report_writes_deferred_drained_total[5m]))
  ```

## Optional notification webhook (AC3)

### `olaitan_notification_webhook_delivered_total`

- **Type:** counter
- **Unit:** count (one increment per webhook delivery outcome)
- **Label set:** `{result}` — `result` in `{delivered, failed}`. This series exists ONLY when the off-by-default notification webhook is enabled (the Story 4.8 gate); a deployment without the webhook exposes no series.
- **Sample PromQL (webhook delivery-failure rate over 5m):**
  ```promql
  sum(rate(olaitan_notification_webhook_delivered_total{result="failed"}[5m]))
    / sum(rate(olaitan_notification_webhook_delivered_total[5m]))
  ```
