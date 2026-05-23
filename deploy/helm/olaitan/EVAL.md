# Evaluation Matrix Configuration

Olaitan ships with a single chart-level switch (`evaluation.config`)
that selects between the canonical evaluation arms of the Epic 5
four-way comparison (FR53). Setting one value places the chart into a
known-good configuration; the alternative is to fiddle with three
independent knobs (`rules.enabled`, `baselines.enabled`,
`analyst.provider`) and accept that an operator deviation invalidates
the across-arm comparison.

## Canonical arms

| Arm    | `rules.enabled` | `baselines.enabled` | `analyst.provider` | Purpose                                                                                       |
| ------ | --------------- | ------------------- | ------------------ | --------------------------------------------------------------------------------------------- |
| `F`    | false           | false               | none               | Falco-only baseline. Measures Falco alone, with no deterministic detection layer above it.    |
| `RS`   | true            | true                | none               | Rules + Statistics. Deterministic detection runs end-to-end; LLM tier bypassed.                |
| `RSL`  | true            | true                | api                | RS plus single-LLM analyst. Reserved for Epic 3 Story 3.x; equivalent to RS until then.       |
| `RSLT` | true            | true                | api                | RS plus full multi-agent chain. Reserved for Epic 3 Story 3.x; chain shape via `analyst.chain.enabled`. |
| `""`   | operator        | operator            | operator           | No overlay; the operator-supplied per-knob values flow through verbatim.                       |

The chart's `_helpers.tpl` defines four named templates that compute
the effective per-arm values:

- `olaitan.evaluation.validate` -- fails render with a clear message
  when `evaluation.config` or `analyst.provider` is outside its
  permitted enum.
- `olaitan.evaluation.effectiveRulesEnabled`
- `olaitan.evaluation.effectiveBaselinesEnabled`
- `olaitan.evaluation.effectiveAnalystProvider`

The configmap.yaml bridge invokes the validator at the top of the
rendered `olaitan.yaml` block and then overlays the three effective
values onto `detection.rules.enabled`,
`detection.baselines.enabled`, and `analyst.provider`.

## Operator override semantics

When `evaluation.config` is non-empty, the per-arm canonical values
clobber the operator-supplied individual knobs. This is the correct
semantic for the Epic 5 evaluation flow: an operator deviation under a
named arm would invalidate the across-arm comparison. If you need to
deviate from the canonical arms (e.g. a one-off experiment), leave
`evaluation.config` empty and set the three individual knobs directly.

## Install recipes

The Bitnami Redis subchart requires an explicit password
(`secrets.redisPassword`); set it on every install.

```bash
# F arm: Falco-only baseline.
helm install olaitan deploy/helm/olaitan \
  --set secrets.redisPassword=<password> \
  --set evaluation.config=F

# RS arm: Olaitan rules + statistics, no LLM. Epic 1 closure target.
helm install olaitan deploy/helm/olaitan \
  --set secrets.redisPassword=<password> \
  --set evaluation.config=RS

# Default (sensing) install with explicit no-LLM. Equivalent to RS but
# leaves the rules/baselines knobs at the values.yaml defaults so an
# operator can flip them individually without re-installing.
helm install olaitan deploy/helm/olaitan \
  --set secrets.redisPassword=<password> \
  --set analyst.provider=none
```

## Restart semantics

`evaluation.config` is restart-required. Setting it drives changes to
three downstream knobs (`rules.enabled`, `baselines.enabled`,
`analyst.provider`) which are all individually restart-required per
their per-block documentation in `values.yaml`. The chart-side overlay
does not magically make the change hot-reloadable: roll the
aggregator pod after a `helm upgrade`.

```bash
helm upgrade olaitan deploy/helm/olaitan \
  --reuse-values \
  --set evaluation.config=RS
kubectl rollout restart deploy/olaitan-aggregator
```

## What this surface does not cover

- The `RSL` and `RSLT` arms are wired in the chart today but the LLM
  driver does not yet exist (Epic 3 Story 3.x lands `analyst.provider=api`
  end-to-end). Setting `evaluation.config=RSL` today renders the
  effective `api` provider on the rendered `analyst.provider` line, but
  the analyst ring is not constructed because the driver code is
  absent.
- Per-arm cluster-side smoke testing on `kind` is covered by Story
  1.19's `tests/e2e/rs_smoke_test.go` (RS arm only). Full per-arm
  end-to-end is the Epic 5 evaluation harness (Stories 5.1-5.5).
