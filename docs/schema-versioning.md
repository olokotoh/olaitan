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
