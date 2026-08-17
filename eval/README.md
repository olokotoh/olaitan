# Evaluation reproducibility envelope

`eval/manifest.yaml` is the single NFR37 reproducibility envelope. It pins
every input that makes an Olaitan evaluation run reproducible. The
`olaitan-eval` harness loads it, computes its SHA256 over the committed
file bytes, runs a fail-closed digest-verification gate over the pinned
artefacts, and records the manifest hash in every run's `metadata.yaml`.

The manifest hash is re-derivable by any reader:

```
sha256sum eval/manifest.yaml
```

The hash is over the COMMITTED file bytes, so YAML key-order / comment /
whitespace drift never silently changes it. Edit `eval/manifest.yaml` as
the human-editable contract; the `Manifest` struct in
`cmd/olaitan-eval/manifest.go` mirrors these keys verbatim and fails fast
on any missing or empty required field.

## The eight NFR37 fields

| Field (YAML key) | Meaning | How to regenerate |
|---|---|---|
| `images` | map of logical name to a `repo@sha256:<digest>` reference (the aggregator image plus any fixture/sidecar images the run installs). Verified by the digest gate. | `docker buildx imagetools inspect <repo>:<tag> --format '{{.Manifest.Digest}}'` |
| `kubernetes_patch_version` | the cluster patch level (architecture.md:79); matches the Makefile `ENVTEST_K8S_VERSION`. | match the kind node image / `ENVTEST_K8S_VERSION` |
| `falco_rule_corpus_tag` | the Falco rule corpus tag (pinned to the Falco subchart version in `deploy/helm/olaitan/Chart.yaml`). | `grep -A1 'name: falco' deploy/helm/olaitan/Chart.yaml` |
| `sigma_corpus_git_sha` | the commit of the `rules/` OLT Sigma corpus. | `git log -1 --format=%H -- rules/` |
| `llm_model_version` | the analyst model actually run. Currently `deepseek-chat` (OpenAI-compatible provider), the disclosed substitution for the originally pinned `claude-opus-4-8` (ADR-2026-08-17-01). | the current analyst model |
| `random_seed` | the deterministic seed threaded to harness-side randomness. `0` is a valid, fully-deterministic choice. | a fixed integer |
| `sysctl_snapshot` | the host sysctl values the run assumes, inline; or a single `path: <file>` entry for the captured-file form. | `sysctl -a` (selected keys) |
| `cluster_bootstrap_script_git_sha` | the commit of `deploy/demo/setup.sh`. | `git log -1 --format=%H -- deploy/demo/setup.sh` |

## The digest gate and the escape hatch

Before the first trial the harness REFUSES to start on any pinned-artefact
digest mismatch OR any artefact whose actual digest cannot be resolved
(fail-closed). To proceed past an unverifiable or mismatched artefact, pass
`--allow-unverified=<name>` (off by default). This VOIDS the
reproducibility guarantee for that artefact and is a research escape hatch
only.

The Story 5.1 minimal gate verifies the container image digest(s). The
Falco-corpus-tag, Sigma-corpus-SHA, and bootstrap-SHA verifications are
filled in by later Epic-5 stories (each carries a `// Story 5.x:` TODO in
`cmd/olaitan-eval/runner.go`) and are allow-listed by default until the
corpora become harness-reachable.

## Per-run artefacts (Story 5.4, FR54)

Every run captures a UNIFORM six-artefact set into `runs/<run_id>/`:
`events.jsonl` (`olaitan.events.raw.>`), `evidence.jsonl`
(`olaitan.evidence.packages`), `assessments.jsonl` (`AUDIT.assessments`),
`fsm.jsonl` (`AUDIT.transitions`), `report.md` (`REPORTS.generated` + an honest
no-report note when no S3 / no report), and `metadata.yaml`. Each `.jsonl` line
is a self-describing envelope `{schema_version, published_at, subject, payload}`
wrapping the verbatim source payload. `metadata.yaml` keeps the Story-5.1 keys
and adds `success_criterion_met` / `measured_time_to_detect` /
`measured_final_fsm_state` / `fsm_state_source` (measured against the scenario's
`target.yaml`), `resource_usage`, `size_bytes`, and `size_cap_exceeded`. Pass
`--nats-url` to drain a live run's subjects; `--max-run-size-bytes` is the
fail-LOUD size cap (default 500 MiB, artefacts retained, not deleted).

## Note on the committed pins

The `images.aggregator` pin in the committed `eval/manifest.yaml` is a
PLACEHOLDER digest: the published image is not yet digest-pinned in the
chart. Story 5.3 wires `analyst.model` and a real published-image pin.
Until then, the AC5 smoke run allow-lists the `aggregator` artefact.
