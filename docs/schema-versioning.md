# Schema Versioning

This document records additive, semver-bounded changes to the canonical
event and posture schemas in `internal/schema/`. Architecture reference:
architecture.md:130 (schema versioning policy).

The Olaitan project follows semver for the on-the-wire schema:

- **MAJOR** bumps require a coordinated stream-cutover and break the
  EVENTS.raw consumer contract.
- **MINOR** bumps add fields that existing consumers may safely ignore
  (json `omitempty` so the pre-bump wire form remains byte-identical
  for the steady-state case).
- **PATCH** bumps adjust documentation, comments, or examples and do
  not touch the marshalled bytes.

| Date | Story | Version | Change | Field(s) | Backwards compatible? |
|---|---|---|---|---|---|
| 2026-05-15 | 1.13 | MINOR | Added per-event sampling annotation for the per-source rate-limit circuit breaker. | `Event.Sampled` (`bool`, `json:"sampled,omitempty"`); `Event.SamplingRate` (`float64`, `json:"sampling_rate,omitempty"`) | Yes. `omitempty` keeps unsampled events bit-identical to the pre-1.13 wire form; the EVENTS.raw `MaxMsgSize` budget is unaffected. |
| 2026-05-29 | 2.2 | MINOR | Extended `StateTransition` with the FSM provenance fields (BI-2). The on-wire shape is mirrored in `docs/schemas/state_transition.yaml` (`state_transition.v2`). | `StateTransition.WorkloadID` (`string`, `json:"workload_id,omitempty"`); `StateTransition.PackageID` (`string`, `json:"package_id,omitempty"`); `StateTransition.Reason` (`string`, `json:"reason,omitempty"`) | Yes. All three are `omitempty`, so the pre-2.2 wire form (the Story 1.x `schema.Incident.Transitions` slice) stays byte-identical for the zero value. No existing field was renamed or removed. |
| 2026-05-31 | 2.3 | NEW (storage) | New durable Redis storage format for FSM state persistence (FR37). A Redis hash format defined in `internal/response/fsm/store.go` (`SchemaVersionFSMState = "fsm_state.v1"`), mirrored in `docs/schemas/fsm_state.yaml`. NOT an EVENTS.raw wire type; the field set is the persisted projection of the in-memory FSM `workloadState`. | `fsm:{workload_id}` hash fields: `schema_version`, `current_state`, `state_entered_at_ns`, `cooldown_anchor_ns`, `updated_at_ns` | Yes. First version of this format; no prior persisted state to migrate. An unknown `schema_version` is skipped on load rather than crashing recovery. |
| 2026-06-03 | 2.7 | NEW (storage) | New durable Redis storage format for operator overrides (FR39). A Redis hash defined in `internal/response/override/store.go` (`SchemaVersionOverride = "override.v1"`). Unlike the no-TTL `fsm:` family, the `override:{workload_id}` key carries a NATIVE Redis TTL equal to the requested override duration: the native TTL IS the FR39 release mechanism and is a HARD DEADLINE measured from first application. The reconcile is edge-triggered, so the controller writes the key only on a NEW override or an operator EDIT (a change of `requested_state` or `ttl_seconds`); it does NOT refresh the TTL while an unchanged annotation merely remains present, so the override auto-releases when the TTL elapses even with the annotation still on the workload (AC2). `operator_id` is populated from the optional `olaitan.io/state-override-by` annotation (empty when absent) and is NOT part of the hard-deadline signature (an operator-id change alone does not re-arm the TTL). NOT an EVENTS.raw wire type; the field set is the durable record of an active operator pin. | `override:{workload_id}` hash fields: `schema_version`, `requested_state`, `ttl_seconds`, `operator_id`, `applied_at_ns`, `source` | Yes. First version of this format; no prior persisted state to migrate. An unknown `schema_version` is skipped on `ListActive` rather than aborting the scan. |
| 2026-06-03 | 2.7 | NEW (wire) | New published NATS subject `OVERRIDES.applied` (BI-10, 365-day JetStream retention) carrying one event per applied AND per rejected operator override (FR38/FR39). Event type `override.OverrideApplied` (`schema_version = "override.v1"`), published via `PublishJS` with a `WithMsgID` dedup key. This is the inverse of the Stories 2.4-2.6 "schema-versioning untouched" note: Story 2.7 DOES introduce a new persisted family AND a new wire subject. The append-only `AUDIT.overrides` SIEM mirror is Story 2.8, not here. | `OverrideApplied` fields: `schema_version`, `workload_id`, `requested_state`, `before_state`, `ttl_seconds`, `operator_id`, `source`, `rejected`, `reason`, `published_at`, `applied_at_ns` | Yes. First version of this subject; no prior consumers. Rejection events carry `rejected:true` + a `reason` (`state_unavailable`/`invalid_state`); applied events carry `rejected:false` and an empty `reason`. |

## How to add a row

1. Edit `internal/schema/event.go` (or the relevant sub-type).
2. Add the field with a `json:"...,omitempty"` tag so consumers
   unaware of the new field marshal a byte-identical wire form for
   the zero value.
3. Add round-trip tests in `internal/schema/schema_test.go` proving
   the new field omits at zero and renders when set.
4. Append a row above with the date, story ID, version bump category,
   one-line description, exact field declaration, and a yes/no on
   backwards compatibility.
5. Note any downstream consumer that should pick the field up in the
   relevant story's Dev Notes hand-off section.
