# DFIR rubric study: definition, rater recruitment, and ethics (Story 5.7, RQ5)

This document is the committed source artefact for the thesis Chapter 3 §3.9.7
rubric-study section. It defines the Likert rubric, the five canonical
dimensions, the rater-recruitment criteria, the blinding protocol, and an
IRB/ethics declaration template appropriate for a Miva University final-year
project (FYP).

It is the DEFINITION only. The ACTUAL administration of the study (the real
N>=3 raters x N=10 cluster-captured incidents per scenario) and the full
Chapter 3 prose are a DEFERRED carry-forward (Stories 5.9-5.10), NOT part of
Story 5.7's done-ness. Story 5.7 ships the harness, the two report-variant
generators, the seeded blind-randomised pairing, the rubric-scores artefact
format, the static-file rater workflow, this definition document, and an OFFLINE
single-synthetic-incident proof. The offline fixture scores are LABELLED
synthetic and are NEVER a thesis-final RQ5 number.

## Research question (RQ5)

Do Olaitan's DFIR LLM-generated forensic reports (variant a) improve analyst
comprehension, ATT&CK coverage, and kill-chain reconstruction over a no-LLM
templated baseline (variant b), as judged by a structured rubric rather than
informal opinion?

The two report variants are produced over the SAME incident evidence:

- **Variant (a), the Olaitan DFIR LLM report:** the Story-4.4
  `dfir.ForensicReport.Render` renderer, reused read-only (the deterministic
  factual sections plus the model's interpretive analyst narrative).
- **Variant (b), the templated baseline:** a fixed Markdown template over the
  same evidence with no language-model interpretation (the analyst narrative is
  replaced by a fixed templated stub).

The (a)-vs-(b) contrast isolates the LLM-sourced analyst interpretation; the
factual sections (kill-chain timeline, containment actions, MITRE ATT&CK
annotations, contributing posture findings) are rendered identically by both
variants.

## The Likert scale

Each rubric dimension is scored on a documented five-point Likert scale:

| score | anchor |
|---|---|
| 1 | very poor: the dimension is absent or actively misleading. |
| 2 | poor: the dimension is partially present but with material gaps or errors. |
| 3 | adequate: the dimension is present and usable, with minor gaps. |
| 4 | good: the dimension is clear, accurate, and largely complete. |
| 5 | excellent: the dimension is exemplary, complete, and immediately actionable. |

## The five canonical dimensions (the confirmatory family)

The confirmatory rubric family is the FIVE canonical PRD dimensions, fixed by
the pre-registration (`analysis/preregistration.md` Section 8a). They are keyed
EXACTLY as the Story-5.5 `build_rubric_rows` registry and the Story-5.7 Go
emitter, so the scores artefact and the analysis cannot drift. The
pre-registration governs over the epic's four-item prose (clarity and
completeness are split out from "analyst comprehension"; "overall usefulness" is
explicitly NOT a confirmatory dimension).

| key | dimension | scoring guide |
|---|---|---|
| `clarity` | Clarity | Is the report readable and unambiguous to an analyst under time pressure? |
| `completeness` | Completeness | Does the report cover the incident's material facts without important omissions? |
| `attack-coverage` | ATT&CK coverage | Are the relevant MITRE ATT&CK for Containers techniques correctly identified and annotated? |
| `killchain` | Kill-chain reconstruction accuracy | Is the kill-chain (the ordered state escalation and its triggers) reconstructed accurately? |
| `actionability` | Actionability | Could an analyst act on the report (containment, next steps) without further investigation? |

The confirmatory analysis runs a two-sided Wilcoxon signed-rank test PER
dimension (family of 5, Bonferroni-corrected alpha 0.05/5 = 0.01, prereg ids
`RQ5-RUBRIC-WILCOXON-{CLARITY,COMPLETENESS,ATTACK-COVERAGE,KILLCHAIN,ACTIONABILITY}`)
comparing the LLM vs templated scores paired per incident, plus ICC(2,k)
inter-rater reliability (`RQ5-ICC`, threshold ICC >= 0.70). The RQ5 success
metric is >= 3 of 5 dimensions with Wilcoxon p < 0.05 AND ICC(2,k) >= 0.70.

### Exploratory-only: overall usefulness

An "overall usefulness" impression MAY be collected for context, but it is
EXPLORATORY only: it is NOT a sixth member of the confirmatory family (adding it
would break the family=5 Bonferroni correction). If it is collected and emitted,
it must be stamped exploratory via the Story-5.8 registry mechanism, never added
to the Wilcoxon family.

## Rater-recruitment criteria

- **Number of raters:** at least N>=3 (the pre-registered rater minimum,
  `analysis/preregistration.md`), so ICC(2,k) inter-rater reliability is
  well-defined.
- **Qualification:** each rater is a security analyst or DFIR practitioner (or a
  final-year cyber-security student under supervision) able to read a Markdown
  forensic report and judge the five dimensions on the documented anchors.
- **Blinding protocol:** each incident's two variants are presented in a SEEDED
  random slot order (`report-a`, `report-b`). The rater-facing report files
  carry a NORMALISED, variant-agnostic front-matter header (a neutral
  `schema_version: "rubric.blinded.v1"` plus the shared `incident_id` only): the
  variant-identifying provenance metadata is STRIPPED from the rater-facing file
  (the LLM variant's `report.v1`/`prompt_hash`/`dfir_provider`/`dfir_model` and
  the templated baseline's `rubric.templated.v1`/`report_kind`), so neither the
  variant label nor an asymmetric header reveals which report is
  machine-generated. The report PROSE legitimately differs between the variants
  (that quality difference is exactly what the rater scores); only the
  identifying metadata header is normalised. The harness retains the full
  per-variant provenance ONLY in the off-disk un-blinding key (slot -> variant),
  used at scoring time, never in the rater-facing files.
- **Conflict-of-interest exclusion:** a rater who contributed to Olaitan's
  development (including the author) is EXCLUDED from scoring, so the comparison
  is not self-graded.

## The static-file rater workflow

The harness writes, per incident: the two blinded report files
(`report-a.md`, `report-b.md`) and a per-rater scoring-sheet template
(`scoring-sheet-<rater>.md`) carrying the five dimensions and the Likert scale
for each slot. The rater fills in the sheet and returns it; the filled scores
are parsed back into the `rubric.score.v1` artefact and un-blinded via the slot
key. There is no live web UI or server (a static-file workflow has no runtime
dependency and parses cleanly).

## The scores artefact (`rubric.score.v1`)

The collected scores land under the reserved `runs/rubric/<run-dir>/` sub-tree
(kept out of the main 4x5 evaluation grid so the analysis pipeline does not
orphan it). One JSONL record per `(incident_id, variant, rater, dimension)`
Likert score, plus a sibling `metadata.yaml` carrying the join/provenance keys
(`scenario`, `manifest_sha256`, `n_incidents`, `n_raters`, `synthetic`). The
offline synthetic set carries `synthetic: true` and `rater: synthetic-*` on
every record, so a placeholder score is never mistaken for a real rater score.

## IRB / ethics declaration template (Miva University FYP)

The study collects subjective rubric judgements about machine-generated text; it
collects NO personal or sensitive data about the raters and poses no more than
minimal risk. The following declaration template would be filed with the Miva
University FYP supervisor / ethics review before administration:

> **Study title:** Structured rubric comparison of LLM-generated versus
> templated DFIR forensic reports (Olaitan, RQ5).
>
> **Principal investigator (student):** _[name, matriculation number]_.
> **Supervisor:** _[name]_.
>
> **Participants:** N>=3 voluntary security-analyst raters. Participation is
> voluntary and may be withdrawn at any time without consequence.
>
> **Data collected:** rubric Likert scores (1-5) on five dimensions per blinded
> report. NO personally identifying information (PII) is collected; raters are
> identified only by an anonymous rater id (e.g. `rater-1`).
>
> **Risk:** minimal. The task is reading two short forensic reports and scoring
> them on a documented rubric. No deception beyond the blinding of the variant
> label (disclosed to raters in the consent text).
>
> **Consent:** raters are given this declaration and consent before scoring.
>
> **Data handling:** scores are stored as anonymised `rubric.score.v1` records;
> no rater identity is linkable to a score; the data is retained only for the
> duration of the FYP assessment and is not shared outside the supervisory team.
>
> **Conflict of interest:** raters who contributed to Olaitan's development
> (including the author) are excluded.

## Deferred carry-forward (BI-2)

The REAL rater study (N>=3 human raters x N=10 cluster-captured incidents per
scenario) needs real raters and cluster-captured incidents and is a DEFERRED
carry-forward (Stories 5.9-5.10), tracked here so it is not forgotten. Story 5.7
ships the harness plus the OFFLINE single-synthetic-S1-incident proof; the real
N>=3 x N=10 study lands later and replaces the synthetic placeholder scores with
real rater scores under the same `runs/rubric/` artefact shape, which
`build_rubric_rows` reads unchanged.
