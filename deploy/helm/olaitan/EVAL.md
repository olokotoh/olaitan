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

## Evaluation overlays (Story 5.3, FR53)

For the Epic 5 evaluation harness, the six arms are committed as THIN Helm
values overlays alongside this chart, so a run applies an arm via
`helm upgrade --values <overlay>` with no `--set` fiddling and no code
change:

| Overlay file | `evaluation.config` | Arm |
| --- | --- | --- |
| `values-eval-f.yaml` | `F` | Falco-only baseline |
| `values-eval-rs.yaml` | `RS` | Rules + Statistics (no LLM) |
| `values-eval-rsl.yaml` | `RSL` | RS + single-LLM Standard mode |
| `values-eval-rslt-full.yaml` | `RSLT-full` | RS + full L1 -> L2 -> Senior chain |
| `values-eval-rslt-l1-only.yaml` | `RSLT-L1-only` | RSLT ablation: L1 only |
| `values-eval-rslt-l1-l2.yaml` | `RSLT-L1+L2` | RSLT ablation: L1 + L2, no Senior |

Each overlay is THIN: it sets ONLY `evaluation.config` (the per-arm
rules/baselines/provider/l2/senior values are COMPUTED by the chart from
that one knob, per the canonical-arms table above) plus, for the LLM arms,
the reproducibility model pin `analyst.api.model: claude-opus-4-8`
(mirroring `eval/manifest.yaml`'s `llm_model_version`, NFR37). The overlays
do NOT restate the per-arm knobs (the chart clobbers them under a named arm
anyway; restating them is dead weight that risks drift).

Apply an arm:

```bash
helm upgrade --install olaitan deploy/helm/olaitan \
  --set secrets.redisPassword=<password> \
  -f deploy/helm/olaitan/values-eval-rs.yaml
```

Filename note (BI-1): the canonical chart enum for the last arm is
`RSLT-L1+L2`; the `+` is normalised to `-` in the FILENAME
(`values-eval-rslt-l1-l2.yaml`) while the IN-FILE `evaluation.config` stays
the canonical `RSLT-L1+L2` so the chart validator and helpers fire
unchanged. RSL and RSLT-L1-only render the same analyst shape (api / l2 off
/ senior on) and so render byte-identical; both overlays are kept for
matrix clarity (the arm distinction lives in the harness `--config` name +
the run id, not the rendered config).

LLM-arm install-time pointers: the LLM-arm overlays keep
`analyst.api.endpoint` empty (the vendor default) and
`analyst.api.apiKeySecret` at the chart default (`olaitan-llm`). Supply the
key via `secrets.llmApiKey` at install; for an in-cluster fake-LLM run set
`--set analyst.api.endpoint=http://fake-llm:8080/v1` (the
`make e2e-local-rslt` pattern).

The `olaitan-eval` harness (`cmd/olaitan-eval/`) applies these overlays
behind the `ConfigOverlay` seam: `--config <name>` resolves to the matching
`values-eval-<name>.yaml`, runs `helm upgrade --install --reuse-values
--values <overlay> --wait`, then an explicit `kubectl rollout status
deploy/<fullname>-aggregator` Ready gate before the scenario fires
(fail-closed). See `cmd/olaitan-eval/README.md`.

The rollout-status target is `deploy/<fullname>-aggregator`, where
`<fullname>` is the chart's `olaitan.fullname` helper, which DEDUPS the
chart name: the canonical `--release olaitan` collapses
`olaitan-olaitan-aggregator` to `olaitan-aggregator`, while a custom
release (e.g. `--release myrel`) that does not already contain the chart
name expands to `myrel-olaitan-aggregator`. The harness's
`aggregatorDeployName` mirrors this dedup so the Ready gate names the
deployment the chart actually renders. This assumes NO
`fullnameOverride`/`nameOverride` is set at install: `aggregatorDeployName`
mirrors only the dedup branch of `olaitan.fullname`, so a custom name
override would make the rollout-status target diverge from the rendered
deployment name.

Arm switching and `--reuse-values` (BI-8): the harness reuses the
install-time values via `--reuse-values`, which is SAFE to do in place
across arms because ALL arm-distinguishing knobs
(`rules`/`baselines`/`provider`/`l2`/`senior`) are DERIVED by the chart from
the single `evaluation.config` value the overlay sets (the canonical-arms
table above) -- the overlay layers `evaluation.config` (and, for the LLM
arms, the inert model pin) on top of the install-time values, and the chart
recomputes every per-arm knob, so switching from one arm to another by
re-applying its overlay produces the correct derived configuration. For the
`F` / `RS` arms the lingering `analyst.api.model` string carried over from a
prior LLM-arm install is INERT (the derived `provider=none` means the model
is never read). If you want a clean-slate switch with no carried-over
install-time values, `helm uninstall` first (or omit `--reuse-values`). The
exercised path is option (a): a pre-install (via `make eval-smoke`)
followed by the harness's idempotent re-apply of the same/another arm's
overlay; the first-install-VIA-the-harness path (option (b)) is supported by
helm's `--reuse-values` no-op-on-fresh-install semantics but is NOT a tested
path here.

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
