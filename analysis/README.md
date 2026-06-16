# analysis/

This directory holds the Olaitan evaluation analysis plan (`preregistration.md`)
and the analysis pipeline (`analyse.py` + `lib/`, landed in Story 5.5).

## Canonical analysis plan

`preregistration.md` is the canonical analysis plan for the Olaitan evaluation.
It is the pre-registered, frozen-before-runs plan that states the per-RQ
hypotheses (RQ1-RQ5), the primary outcome metrics, the per-test statistical
procedures, the pre-specified significance levels and Bonferroni correction
structure, the sample sizes, the stopping rule, and the confirmatory test
registry. Every number in it is derived from the PRD and epics and cited inline.

The pre-registration soft-freeze date is **2026-08-15** (prd.md:319). On or
before that date the statistical tests are committed to Chapter 3 and the
analysis pipeline is committed here. Evaluation runs commence after the plan is
locked.

## The post-freeze exploratory-label rule (binding)

Any analysis added after 2026-08-15 that is not in `preregistration.md` (that is,
any test whose `test_id` is not in the confirmatory test registry in
`preregistration.md` section 8a) MUST be labelled "exploratory analysis" in
Chapter 4 and reported in a section distinct from the confirmatory findings. This
mirrors the PRD rule that tests added after the pre-registration date are
disclosed as exploratory and reported separately from the pre-registered findings
(prd.md:319). The rule is binding: confirmatory and exploratory results are never
mixed in the same reporting section.

## The analysis pipeline (Story 5.5)

`analyse.py` has landed (Story 5.5). It is the FIRST Python in this otherwise-Go
repo: a pure-Python, NO-CLUSTER, OFFLINE pipeline that CONSUMES the merged
Story-5.4 per-run artefacts under `runs/<run_id>/` (read-only) and produces, per
`(config, scenario)` cell, Detection Rate, MTTD, and FPR, plus ATT&CK Cohen's
kappa pooled across scenarios per config (so the ground-truth technique label
varies across S1-S5 rather than being constant within a single-scenario cell)
(AC1), runs the pre-registered inferential tests READ FROM `preregistration.md`
section 8a (McNemar + Bonferroni, Kruskal-Wallis + Dunn's-with-Holm, Wilcoxon
signed-rank, ICC(2,k), and the one-sided Poisson FPR equivalence test, AC2/AC3),
attaches the `manifest_sha256` + sample-size + test provenance triad to every
output row (AC4), and stamps any test whose `test_id` is not in the registry
`exploratory: true` in a separate output section (the contract written here,
enforced there).

Layout:

- `analyse.py`: the CLI entrypoint + `main()`.
- `lib/`: the typed helper modules (`io`, `metrics`, `fsm`, `tests`,
  `ablation`, `provenance`, `prereg`), one concern each.
- `tests/`: the pytest suite (one known-answer test per helper) plus
  `test_smoke.py`, a byte-deterministic full-pipeline smoke test.
- `fixtures/`: committed deterministic synthetic run dirs + the smoke-test
  golden; `generate.py` re-derives the run dirs.
- `output/`: the generated `summary.csv` + `summary.md` (gitignored; the smoke
  golden lives under `fixtures/golden/`).
- `requirements.txt` / `requirements-dev.txt`: the pinned dependency set.
- `pyproject.toml`: the `mypy --strict` + pytest config.

Run it:

```bash
pip install -r analysis/requirements.txt -r analysis/requirements-dev.txt
python analysis/analyse.py --runs runs/ --output analysis/output/
# or: make analysis        (run the pipeline)
#     make analysis-test    (mypy --strict + pytest, mirrors the CI job)
```

The pipeline DEGRADES HONESTLY (BI-7): the real 400-run thesis numbers land
later on the cluster (Story 5.9). It ships the pipeline + the committed
synthetic fixtures + the tests; it reports `n` per cell, emits `n/a`/NaN (never
a fabricated number) when `n == 0`, flags `underpowered: true` below the
pre-registered N (15 main / 10 ablation), and SKIPS a test (with `status:
skipped (insufficient data, n=...)`, never a crash or a fabricated p-value) when
its preconditions are unmet. Fixture runs are labelled `fixture: true` and are
NEVER thesis-final.
