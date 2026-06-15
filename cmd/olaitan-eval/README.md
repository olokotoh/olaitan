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
| `--config` | (required) | evaluation arm; one of `f`, `rs`, `rsl`, `rslt`, `rslt-full`, or an `rslt-<ablation>` (an unknown arm is rejected) |
| `--runs` | `1` | number of trials to run |
| `--out` | `runs` | output directory for `runs/<run_id>/` |
| `--allow-unverified` | (empty) | artefact names to skip in the digest gate; comma-separated or the flag repeated |

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
| `ConfigOverlay` (`Apply`) | Story 5.3 | `rsOverlay` reuses `evaluation.config=RS` |
| `Scenario` (`Run`) | Story 5.2 | `rsScenario` reuses the rs_smoke synthetic S1 container-escape event |
| `Capturer` (`Capture`) | Story 5.4 | `metadataOnlyCapturer` writes the placeholder marker only |
| `DigestVerifier` (`Verify`) | 5.1 | `imageDigestVerifier` checks the image digest; corpus/SHA checks deferred |

Story 5.2-5.5 supply rich implementations behind these interfaces without
changing the `Runner` loop or the signatures.
