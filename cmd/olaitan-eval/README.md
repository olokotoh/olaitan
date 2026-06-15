# olaitan-eval

The Olaitan evaluation harness binary (FR53-FR54). It orchestrates a single
reproducible evaluation run from one `eval/manifest.yaml` reproducibility
envelope (NFR37), so any run is fully reproducible from one file and the
manifest hash is recorded in every result row.

Story 5.1 ships the FOUNDATION: the harness skeleton, the manifest
reader/validator, the canonical manifest hash, the fail-closed
digest-verification gate, the minimal per-run `metadata.yaml`, the
`runs/<run_id>/` layout, the CLI, and the N-trial loop. Stories 5.2-5.5
fill in the rich behaviour BEHIND the frozen seams (see below) without
reshaping the harness.

## Usage

```
olaitan-eval --manifest eval/manifest.yaml --scenario s1 --config rs --runs 1
```

| Flag | Default | Meaning |
|---|---|---|
| `--manifest` | `eval/manifest.yaml` | path to the reproducibility-envelope manifest |
| `--scenario` | (required) | scenario id to run; one of `s1`..`s5` (an unknown id is rejected) |
| `--config` | (required) | evaluation arm; one of `f`, `rs`, `rsl`, `rslt`, `rslt-full`, `rslt-l1-only`, `rslt-l1-l2` (an unknown arm is rejected; Story 5.3 tightened this to the six arms that have a committed overlay) |
| `--runs` | `1` | number of trials to run |
| `--out` | `runs` | output directory for `runs/<run_id>/` |
| `--allow-unverified` | (empty) | artefact names to skip in the digest gate; comma-separated or the flag repeated |
| `--chart-root` | `deploy/helm/olaitan` | path to the Helm chart the `ConfigOverlay` upgrades |
| `--release` | `olaitan` | Helm release name the `ConfigOverlay` upgrades |
| `--namespace` | `olaitan` | Kubernetes namespace the `ConfigOverlay` upgrades into |
| `--overlays-dir` | `deploy/helm/olaitan` | directory holding the `values-eval-<name>.yaml` configuration overlays |
| `--overlay-timeout` | `5m` | budget for the `helm --wait` + the aggregator `rollout status` Ready gate |

The harness, in order: loads + validates the manifest, computes its SHA256
over the committed file bytes, runs the digest-verification gate ONCE
before the first trial, generates a `run_id`, creates `runs/<run_id>/`,
runs `--runs` trials through the five-phase `Runner` loop, and writes the
per-run `metadata.yaml`.

## The manifest contract

`eval/manifest.yaml` pins the eight NFR37 fields (image digests,
Kubernetes patch version, Falco rule corpus tag, Sigma corpus git SHA, LLM
model version `claude-opus-4-8`, random seed, sysctl snapshot, cluster
bootstrap script git SHA). The parser fails fast on any missing or empty
required field. See `eval/README.md` for the field reference.

The manifest hash is `sha256` of the COMMITTED file bytes, re-derivable
with:

```
sha256sum eval/manifest.yaml
```

This hash is recorded as `manifest_sha256` in every run's `metadata.yaml`.
Hashing the raw bytes (not a re-marshalled struct) means YAML key-order /
comment / whitespace drift never silently changes the hash.

## The `runs/<run_id>/` layout

```
runs/
  <run_id>/                  # <UTC-compact-timestamp-with-millis>-<scenario>-<config>-<short-hash>
    metadata.yaml            # minimal schema; manifest_sha256 carrier (extended by Story 5.5)
    trial-1/
      CAPTURE_PLACEHOLDER.md # Story 5.1 placeholder; the six-file rich set is Story 5.4
    trial-2/
    ...
```

`runs/` is git-ignored except for a committed `runs/example/` skeleton.

## The digest-verification gate + the `--allow-unverified` escape hatch

Before the first trial the harness verifies each pinned artefact's actual
digest against the manifest pin. The gate is FAIL-CLOSED: a mismatch OR an
artefact whose actual digest cannot be resolved is a REFUSE (non-zero exit,
a clear expected-vs-actual error), not a skip.

The ONLY way to proceed past an unverifiable or mismatched artefact is the
documented escape hatch:

```
olaitan-eval --allow-unverified=aggregator ...
```

`--allow-unverified` is off by default. It VOIDS the reproducibility
guarantee for each named artefact and exists only as a research escape
hatch. The Story 5.1 minimal gate verifies the container image digest(s);
the Falco-corpus-tag, Sigma-corpus-SHA, and bootstrap-SHA verifications
carry `// Story 5.x:` TODOs and are allow-listed by default until the
corpora become harness-reachable.

## The five frozen seams (filled by Stories 5.2-5.5)

The `Runner` holds five interfaces and drives them in the
architecture-mandated order (architecture.md:712):

```
Reset -> Warm -> ConfigOverlay.Apply -> Scenario.Run -> Capturer.Capture -> Cleanup
```

`Cleanup` is deferred so it runs even when an earlier phase errors.

| Seam | Owner story | Story 5.1 minimal impl |
|---|---|---|
| `ClusterController` (`Reset`/`Warm`/`Cleanup`) | 5.1 | reuses the rs_smoke kind bring-up; no-op phases at the foundation layer |
| `ConfigOverlay` (`Apply`) | Story 5.3 | FILLED: `helmOverlay` (overlay.go) resolves `--config <name>` to its committed `deploy/helm/olaitan/values-eval-<name>.yaml` overlay, runs `helm upgrade --install --reuse-values --values <overlay> --wait --timeout <budget>`, then an explicit `kubectl rollout status deploy/<fullname>-aggregator` Ready gate (fail-closed). `<fullname>` is the chart's `olaitan.fullname` helper, which DEDUPS the chart name when the release already contains it (the canonical `olaitan` release collapses `olaitan-olaitan-aggregator` to `olaitan-aggregator`; a custom `myrel` release expands to `myrel-olaitan-aggregator`), mirrored by `aggregatorDeployName`. The six arms (F / RS / RSL / RSLT-full / RSLT-L1-only / RSLT-L1+L2) each select the already-shipped chart matrix; the LLM arms pin `analyst.api.model` |
| `Scenario` (`Run`) | Story 5.2 | FILLED: `scenarioHarness` (scenario.go) resolves `--scenario sN` to the `deploy/demo/scenarios/sN-<slug>/` harness + its `target.yaml`; the synthetic-event injection lives in `tests/e2e/scenarios_smoke_test.go` on kind (BI-3) |
| `Capturer` (`Capture`) | Story 5.4 | `metadataOnlyCapturer` writes the placeholder marker only |
| `DigestVerifier` (`Verify`) | 5.1 | `imageDigestVerifier` checks the image digest; corpus/SHA checks deferred |

Story 5.2-5.5 supply rich implementations behind these interfaces without
changing the `Runner` loop or the signatures.

## The configuration-matrix overlays (Story 5.3, FR53)

The `ConfigOverlay` seam selects an evaluation arm by applying its committed
THIN Helm values overlay. Each overlay sets ONLY `evaluation.config` (the
already-shipped chart matrix knob computes the per-arm
rules/baselines/provider/l2/senior values) plus, for the LLM arms, the
reproducibility model pin `analyst.api.model: claude-opus-4-8` (mirroring
`eval/manifest.yaml`'s `llm_model_version`, NFR37).

| `--config` | Overlay file | Arm |
|---|---|---|
| `f` | `values-eval-f.yaml` | Falco-only baseline |
| `rs` | `values-eval-rs.yaml` | Rules + Statistics (no LLM; the default CI e2e arm) |
| `rsl` | `values-eval-rsl.yaml` | RS + single-LLM Standard mode |
| `rslt` / `rslt-full` | `values-eval-rslt-full.yaml` | RS + full L1 -> L2 -> Senior chain |
| `rslt-l1-only` | `values-eval-rslt-l1-only.yaml` | RSLT ablation: L1 only |
| `rslt-l1-l2` | `values-eval-rslt-l1-l2.yaml` | RSLT ablation: L1 + L2, no Senior |

Filename note (BI-1): the canonical chart enum for the last arm is
`RSLT-L1+L2`; the `+` is normalised to `-` in the FILENAME
(`values-eval-rslt-l1-l2.yaml`), but the IN-FILE `evaluation.config` stays
the canonical `RSLT-L1+L2` so the chart validator and effective-value
helpers fire unchanged. The `--config rslt-l1-l2` arm resolves to that file.

The LLM-arm overlays keep `analyst.api.endpoint` empty (the vendor default)
and `analyst.api.apiKeySecret` at the chart default (`olaitan-llm`): supply
the API key via `secrets.llmApiKey` at install, and optionally point
`analyst.api.endpoint` at an in-cluster fake-LLM for a cluster run.
