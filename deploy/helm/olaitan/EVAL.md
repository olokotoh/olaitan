# Evaluation Matrix Configuration

Olaitan ships with a single chart-level switch (`evaluation.config`)
that selects between the canonical evaluation arms of the Epic 5
four-way comparison (FR53). Setting one value places the chart into a
known-good configuration; the alternative is to fiddle with three
independent knobs (`rules.enabled`, `baselines.enabled`,
`analyst.provider`) and accept that an operator deviation invalidates
the across-arm comparison.

## Canonical arms

| Arm            | `rules` | `baselines` | `provider` | `l2` | `senior` | Purpose                                                                                       |
| -------------- | ------- | ----------- | ---------- | ---- | -------- | --------------------------------------------------------------------------------------------- |
| `F`            | false   | false       | none       | n/a  | n/a      | Falco-only baseline. Measures Falco alone, with no deterministic detection layer above it.    |
| `RS`           | true    | true        | none       | n/a  | n/a      | Rules + Statistics. Deterministic detection runs end-to-end; LLM tier bypassed.                |
| `RSL`          | true    | true        | api        | false| true     | RS plus single-LLM analyst (L1 only; senior precedence collapses to L1-as-senior).            |
| `RSLT-full`    | true    | true        | api        | true | true     | RS plus the full multi-agent chain L1 -> L2 -> Senior. `RSLT` is a legacy alias for this arm. |
| `RSLT-L1-only` | true    | true        | api        | false| true     | RSLT ablation: L1 only (L2 off => Senior off by Go-side precedence).                          |
| `RSLT-L1+L2`   | true    | true        | api        | true | false    | RSLT ablation: L1 + L2, no Senior.                                                            |
| `""`           | operator| operator    | operator   | op.  | op.      | No overlay; the operator-supplied per-knob values flow through verbatim.                       |

The chart's `_helpers.tpl` defines the named templates that compute
the effective per-arm values:

- `olaitan.evaluation.validate` -- fails render with a clear message
  when `evaluation.config` or `analyst.provider` is outside its
  permitted enum (`"" F RS RSL RSLT RSLT-full RSLT-L1-only RSLT-L1+L2`).
- `olaitan.evaluation.effectiveRulesEnabled`
- `olaitan.evaluation.effectiveBaselinesEnabled`
- `olaitan.evaluation.effectiveAnalystProvider`
- `olaitan.evaluation.effectiveL2Enabled` / `effectiveSeniorEnabled`
  (Story 3.16) -- drive the analyst chain-ablation shape per arm.

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

- The LLM driver landed across Epic 3 (Stories 3.2-3.8 build the
  provider abstraction, the L1/L2/Senior chain, and the per-arm wiring;
  Story 3.16 wired the RSL/RSLT arms end-to-end). Setting
  `evaluation.config=RSLT-full` now constructs the full analyst ring and
  produces a (trust-bound-capped) LLM verdict, provided an
  `analyst.api.apiKeySecret` is supplied; without a key the provider
  degrades to rules-only with an `api_key_set=false` log, so the chart
  never silently dials a public endpoint.
- The full RSLT-full per-arm cluster e2e (`tests/e2e/rslt_smoke_test.go`,
  `make e2e-local-rslt`) ships compile-clean but is `OLT_E2E_RSLT`-gated
  and the cluster RUN is deferred to before Epic 5 (retro Epic-3 action
  A1); the default CI e2e job still exercises the RS arm only
  (`tests/e2e/rs_smoke_test.go`). Full per-arm end-to-end is the Epic 5
  evaluation harness (Stories 5.1-5.5).
