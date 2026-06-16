# analysis/

This directory holds the Olaitan evaluation analysis plan and (from Story 5.5
onward) the analysis pipeline.

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

## What lands here later

`analysis/analyse.py` (Story 5.5) lands in this directory later. It consumes the
confirmatory test registry in `preregistration.md` section 8a and stamps any
test or metric not in the registry as `exploratory: true` in a separate output
section. It also records, alongside every number, the `manifest_sha256`, the
sample size, and the statistical test used (epics.md:2206-2208). This
pre-registration writes the contract; Story 5.5 implements the enforcement.
