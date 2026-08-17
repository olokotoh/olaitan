# Olaitan pre-registered analysis plan

This document is the canonical, frozen-before-runs analysis plan for the Olaitan
evaluation. It is committed before the main evaluation runs begin so that the
four-way comparison, the RSLT internal ablation, the adversarial-LLM bound test,
and the DFIR rubric study are confirmatory rather than exploratory. Every
hypothesis, effect-size threshold, statistical test, per-test significance
level, sample size, and stopping rule below is derived from the project PRD and
epics (cited inline); none is invented at analysis time.

Source documents (read-only references): the PRD Technical-Success and
Measurable-Outcomes tables (prd.md:104-126), the PRD Validation Approach
(prd.md:317-324), the PRD MVP scope (prd.md:149), the FR55 trust-bound
(prd.md:110,544), and Story 5.5's analysis pipeline acceptance criteria
(epics.md:2198-2212). The statistical tests named here align exactly with the
tests Story 5.5's `analysis/analyse.py` implements (epics.md:2200).

## 1. Pre-registration metadata

- **Title:** Olaitan pre-registered analysis plan (Epic 5, Reproducible Evaluation).
- **soft_freeze_date: 2026-08-15.** This is the pre-registration soft-freeze date
  (the PRD "Pre-registration date: 2026-08-15", prd.md:319). On or before this
  date the statistical tests are committed to Chapter 3 and the analysis pipeline
  (`analysis/analyse.py`, Story 5.5) is committed to the repository. Evaluation
  runs commence after pre-registration is locked. Any test added after this date
  that is not in this plan is disclosed as exploratory in Chapter 4 and reported
  separately from the pre-registered findings (prd.md:319). This document is
  committed before the freeze date (the plan is registered now, the freeze is the
  future point past which deviations become exploratory); the introducing commit
  records the freeze date in its message.
- **Pinned LLM model:** `claude-opus-4-8`. This is the real current analyst model
  pinned in the reproducibility envelope (eval/manifest.yaml:43,
  `llm_model_version: claude-opus-4-8`). The epic's earlier placeholder
  `claude-opus-4-7-2026-MM-DD` never shipped and is stale; this plan records the
  pinned model, not the placeholder.
- **Manifest-hash discipline:** every reported number carries, alongside it, the
  `manifest_sha256` of `eval/manifest.yaml` under which its run set executed, plus
  the sample size and the statistical test used, so each number in the thesis is
  traceable to its run set (epics.md:2206-2208). `manifest_sha256` is the SHA-256
  over the committed bytes of `eval/manifest.yaml`, re-derivable via
  `sha256sum eval/manifest.yaml` (eval/manifest.yaml:1-9).
- **Canonical-plan declaration:** this file is the canonical analysis plan for the
  Olaitan evaluation. `analysis/README.md` declares this status and the binding
  post-freeze exploratory-label rule. Confirmatory tests are enumerated in the
  registry in Section 8; any test not in that registry is exploratory.

## 2. Research questions

The five research questions (RQ1-RQ5) frame the validation. The PRD enumerates a
Validation Approach but labels only RQ5 inline (prd.md:126,324); RQ1-RQ4 are
reconstructed from the PRD's four validation bullets (prd.md:321-324), the two
named contributions (prd.md:102), and the success-metric table (prd.md:117-126),
mapped to the five named outcomes. The exact RQ wording below is a pre-registered
choice (open question OQ3 in the source story, recommended resolution taken).

- **RQ1 (detection efficacy across the four-way matrix).** Does the full
  multi-agent variant RSLT-full detect more attacks than the Falco-only baseline
  F (and than RS and RSL) across the five MITRE ATT&CK for Containers scenarios
  S1-S5? Primary metrics: Detection Rate and ATT&CK technique-annotation accuracy
  (Cohen's kappa). [Source: prd.md:102,106,108,119,121,321-322]
- **RQ2 (mean time to detect).** Does RSLT-full detect within the per-scenario
  success windows, and how does Mean Time To Detect (MTTD) distribute across the
  configurations? Primary metric: MTTD (seconds). [Source: prd.md:109,122,322]
- **RQ3 (false positive rate).** Do the LLM tiers inflate the false positive rate?
  Primary metric: unsolicited state escalations per hour on the 24-hour benign
  calibration sweep, per configuration. [Source: prd.md:107,120]
- **RQ4 (marginal LLM-tier contribution and the trust-bound).** What is the
  marginal contribution of the L2 verification tier and the Senior challenge tier
  (the RSLT internal ablation: L1-only vs L1+L2 vs full), and is the trust-bound
  empirically held under adversarial prompting (the FR55 experiment)? Primary
  metrics: Detection Rate (ablation contributions); the FSM final state and the
  ThreatScore bound (adversarial trial). [Source: prd.md:110,111,124,125,321-322;
  epics.md:2238,2246]
- **RQ5 (DFIR rubric study).** Do LLM-generated DFIR reports score higher than
  rule-templated baseline reports across the five rubric dimensions, with adequate
  inter-rater reliability? Primary metrics: the five Likert rubric dimensions and
  ICC(2,k). RQ5 is the only RQ the PRD labels inline. [Source: prd.md:112,126,324]

## 3. Per-RQ hypotheses

Each RQ carries a null hypothesis (H0) and an alternative (H1) with the PRD
effect-size threshold. Every threshold is transcribed from the PRD, not chosen
here. The alternatives are directional (superiority) except RQ3, which is a
false-positive **non-inferiority / equivalence** question and is therefore framed
as an equivalence test against a fixed tolerance bound rather than a directional
superiority test (a "the LLM tiers do not make things worse" claim is an
equivalence claim, not a directional alternative to an equality null). The RQ3
framing below states H0/H1 in equivalence form accordingly.

- **RQ1.** H0: RSLT-full Detection Rate equals F Detection Rate (no gain). H1:
  RSLT-full Detection Rate is greater than F Detection Rate. Effect-size threshold:
  an average Detection-Rate gap of at least 15 percentage points (RSLT-full minus
  F) across S1-S5; and ATT&CK Cohen's kappa at least 0.75 for the LLM-augmented
  configurations RSL and RSLT-full versus expert annotation. [Source:
  prd.md:106,108,119,121]
- **RQ2.** H0: the MTTD distributions are equal across configurations. H1:
  RSLT-full MTTD is lower (detects within the per-scenario window more often).
  Effect-size threshold: within-window detection in at least 80 percent of runs
  per cell, with the windows S1 30s, S2 60s, S3 90s, S4 300s, S5 120s. [Source:
  prd.md:109,122]
- **RQ3 (equivalence framing).** Tolerance bound: 2 unsolicited state escalations
  per hour on the 24-hour benign-corpus sweep, per configuration (the PRD FPR
  acceptance threshold). H0: an LLM-bearing configuration's FPR is at or above the
  2-per-hour tolerance bound (the LLM tiers inflate the false positive rate beyond
  tolerance). H1: an LLM-bearing configuration's FPR is below the 2-per-hour bound
  (the LLM tiers do not inflate the false positive rate beyond tolerance). The
  confirmatory test is a one-sided Poisson rate test of each LLM-bearing
  configuration (RSL, RSLT-full) against the bound (a TOST-style non-inferiority
  check against the tolerance, not an omnibus equality test across configurations);
  the non-LLM references F and RS are reported descriptively. Effect-size
  threshold: fewer than 2 unsolicited state escalations per hour, per
  configuration. [Source: prd.md:107,120]
- **RQ4 (ablation).** H0: the L2 verification tier and the Senior challenge tier add
  no Detection-Rate contribution. H1: L2 adds at least 10 percent relative
  Detection-Rate improvement over L1-only, and Senior adds at least 5 percent
  relative Detection-Rate improvement over L1+L2. [Source: prd.md:111,124,125]
- **RQ4 (trust-bound, FR55).** H0: the LLM can push a workload past the SUSPICIOUS
  state under adversarial prompting on a benign package. H1: the trust-bound holds:
  no workload transitions past SUSPICIOUS. Effect-size threshold: 0 of 100
  adversarial trials transition past SUSPICIOUS, and the maximum observed
  ThreatScore stays at or below 10.5 for the Claude provider (and at or below 7.5
  for the Ollama provider). [Source: prd.md:110; epics.md:2238,2246]
- **RQ5.** H0: the LLM-generated report scores equal the templated-report scores
  per rubric dimension. H1: the LLM-generated report scores higher. Effect-size
  threshold: at least 3 of the 5 rubric dimensions reach Wilcoxon signed-rank
  p < 0.05, with inter-rater reliability ICC(2,k) at least 0.70. [Source:
  prd.md:112,126,324]

## 4. Primary outcome metrics

- **Detection Rate (DR).** The proportion of scenario runs in which the attack is
  detected, per configuration cell. Feeds RQ1 and the RQ4 ablation. [Source:
  prd.md:106,119]
- **Mean Time To Detect (MTTD).** Seconds from attack injection to detection
  signal, compared against the per-scenario windows. Feeds RQ2. [Source:
  prd.md:109,122]
- **False Positive Rate (FPR).** Unsolicited state escalations per hour on the
  24-hour benign-corpus sweep, per configuration. Feeds RQ3. [Source:
  prd.md:107,120]
- **ATT&CK technique-annotation accuracy (Cohen's kappa).** Agreement of the
  LLM-augmented configurations RSL and RSLT-full with expert annotation. Feeds
  RQ1. [Source: prd.md:108,121]
- **DFIR rubric Likert dimensions.** The five rubric dimensions Clarity,
  Completeness, ATT&CK coverage, Kill-chain reconstruction accuracy, and
  Actionability, each scored on a documented Likert scale; plus ICC(2,k) for
  inter-rater reliability. Feeds RQ5. [Source: prd.md:112,324]

The five canonical PRD rubric dimensions (prd.md:112,324) are pre-registered over
Story 5.7's four-item prose framing. This reconciliation is a pre-registered
choice (open question OQ2 in the source story, recommended resolution taken): the
more specific PRD success-metric statement governs.

## 5. Statistical procedures, alpha, and Bonferroni structure

The tests below are fixed by Story 5.5's acceptance criteria (epics.md:2200) and
the PRD measurable-outcomes table (prd.md:119-126); they are not chosen here.
Story 5.5's `analysis/analyse.py` implements exactly these tests so the plan and
the code agree.

**Pre-specified significance level.** Alpha = 0.05 for every hypothesis test
below: two-sided for the directional superiority tests (RQ1, RQ2, RQ4 ablation,
RQ5), and one-sided for the RQ3 FPR equivalence (non-inferiority) test, where a
one-sided test against the tolerance bound is the correct form for an
equivalence/non-inferiority question. The PRD names the tests and the corrections
but does not state a literal numeric alpha; 0.05 is the field-standard default and
is recorded here as a pre-specified choice, not a PRD-stated value (open question
OQ1 in the source story, recommended resolution taken). [Source: field-standard
default; the PRD names tests + corrections, prd.md:119-126]

**Correction structure.** The word "structure" is load-bearing: the plan states
which family of comparisons is corrected together, not merely that Bonferroni is
used. The families are pre-committed below. The detection-rate four-way family and
the ablation family are corrected as separate families (open question OQ4 in the
source story, recommended resolution taken: separate families).

| Test family | Test | Applies to | Pre-specified alpha | Correction family | Family size | Corrected alpha | Source |
|---|---|---|---|---|---|---|---|
| Detection-rate (four-way) | McNemar's paired | RSLT-full vs F (and vs RS, vs RSL) per scenario | 0.05 two-sided | Bonferroni across the 5 per-scenario comparisons within a config-pair contrast | 5 | 0.05 / 5 = 0.01 | prd.md:119; epics.md:2200 |
| Detection-rate (ablation) | McNemar's paired | L2 over L1-only; Senior over L1+L2 | 0.05 two-sided | Bonferroni across the 2 ablation contrasts times 5 scenarios (a separate family from the four-way family) | 2 x 5 = 10 | 0.05 / 10 = 0.005 | prd.md:124,125 |
| MTTD | Kruskal-Wallis omnibus plus Dunn's post-hoc with Holm correction | MTTD across configurations per scenario | 0.05 two-sided | Holm on the Dunn pairwise comparisons (the post-hoc carries the multiplicity control); the Kruskal-Wallis omnibus is per-scenario and uncorrected | per-scenario pairwise set | Holm-adjusted | prd.md:122; epics.md:2200 |
| DFIR rubric | Wilcoxon signed-rank | LLM-generated vs templated per rubric dimension | 0.05 two-sided | Bonferroni across the 5 rubric dimensions | 5 | 0.05 / 5 = 0.01 | prd.md:112,126 |
| Inter-rater | ICC(2,k) | rater agreement on the rubric | report point estimate plus 95 percent confidence interval; threshold ICC at least 0.70 (a reliability estimate, not a hypothesis test) | not applicable (reliability estimate, not a multiplicity family) | not applicable | prd.md:112,126 |
| ATT&CK accuracy | Cohen's kappa | RSL and RSLT-full vs expert annotation | report point estimate; threshold kappa at least 0.75 (an agreement estimate, not a hypothesis test) | not applicable (agreement estimate) | not applicable | prd.md:108,121 |
| FPR (equivalence) | One-sided Poisson rate test (TOST-style non-inferiority against the 2 escalations/hour tolerance bound) | each LLM-bearing configuration (RSL, RSLT-full) vs the 2/hour bound on the benign sweep | 0.05 one-sided | Bonferroni across the 2 LLM-bearing configurations tested against the bound (F and RS are reported descriptively and are not in the test family) | 2 | 0.05 / 2 = 0.025 | prd.md:120 |

The MTTD post-hoc is pre-registered as Dunn's-with-Holm. Story 5.5's acceptance
criteria say "Kruskal-Wallis with Dunn's post-hoc" (epics.md:2200) while the PRD
measurable-outcomes table says "Kruskal-Wallis with Dunn's + Holm post-hoc"
(prd.md:122). The more specific PRD statement governs: Holm is the multiplicity
control on the Dunn pairwise comparisons and is fully consistent with "Dunn's
post-hoc". This reconciliation is the pre-registered choice (open question OQ2 in
the source story); Story 5.5's `analysis/analyse.py` implements Dunn's-with-Holm
to match.

## 6. Sample sizes

Each sample size is stated against its specific RQ and test, not aggregated. The
main four-way runs and the ablation runs size the detection (DR) and MTTD matrix;
the FPR benign sweep, the FR55 trials, and the RQ5 rubric study each have their
own, separate sizing.

| Sample | Size | Scope | Note | Source |
|---|---|---|---|---|
| Main four-way runs | N=15 per cell | 4 configurations times 5 scenarios | feeds RQ1, RQ2 | prd.md:149 |
| Benign calibration sweep | one 24-hour benign-corpus run per configuration (4 runs) | 4 configurations | feeds RQ3; FPR = escalations/hour measured over the 24-hour window, a distinct sampling unit from the N=15 attack matrix (it is not folded into the main four-way runs) | prd.md:107,120 |
| Ablation runs | N=10 per cell | 2 ablation arms (L1-only, L1+L2) times 5 scenarios | feeds RQ4 ablation | prd.md:149 |
| Total main plus ablation | 400 runs | (4 x 5 x 15) plus (2 x 5 x 10) = 300 plus 100 = 400 | reconciles to the PRD's stated 400-run total | prd.md:149 |
| FR55 adversarial trials | 100 per LLM configuration (RSL, RSLT-full) | a separate experiment; not folded into N=15 | benign-forced input; the trust-bound test | prd.md:110,544; epics.md:2232 |
| RQ5 incidents | N=10 per scenario | representative incidents captured during the main four-way runs | the rubric study unit | epics.md:2258 |
| RQ5 raters | N >= 3 | blind-randomised variant pairs | inter-rater reliability via ICC(2,k) | epics.md:2264 |

N=15 (main) and N=10 (ablation) are per cell, reconciling to the 400-run total
above (open question OQ5 in the source story, recommended resolution taken). The
FR55 100 trials per LLM configuration are a separate count from the 400 main and
ablation runs; they are not folded into N=15 (the recommended OQ5 resolution).
[Source: prd.md:149 for the per-cell-to-400 reconciliation; prd.md:110 and
epics.md:2232 for the separate FR55 count]

## 7. Stopping rule

The data-collection stopping rule is fixed-N with no optional stopping. The full
pre-specified N is collected for every cell (N=15 main per cell, N=10 ablation per
cell, 100 FR55 trials per LLM configuration, N=10 RQ5 incidents per scenario).
There is no interim peeking that alters the decision to continue, and no early
termination on an observed significant interim result. Data collection commences
after the 2026-08-15 soft freeze locks this plan and stops at the pre-specified N.
This fixed-N, no-peeking rule is the analytic-flexibility defence that this
pre-registration exists to provide. [Source: prd.md:317-319 (runs commence after
pre-registration is locked); prd.md:149 (the pre-specified N)]

## 8. Confirmatory-vs-exploratory contract and traceability contract

### 8a. Confirmatory test registry

The registry below is the canonical machine-readable list of every pre-registered
(confirmatory) test, keyed by a stable `test_id` (open question OQ7 in the source
story, recommended resolution taken: the Markdown table keyed by `test_id` is the
canonical form Story 5.5 consumes). Each `test_id` begins with its `RQ<n>-` prefix
followed by a stable, opaque suffix naming the metric and test (with a
per-dimension suffix for the rubric tests). Registry membership is determined by
exact-string match on the whole `test_id`, never by field-parsing the suffix into
fixed positions: two ids (`RQ4-FR55-BOUND`, `RQ5-ICC`) intentionally do not split
into separate metric and test fields. The id set is stable and documented here.
Each row carries an explicit HTML anchor (`<a id="<lowercased test_id>">`)
immediately before its `test_id`, so a Chapter 3 or Chapter 4 claim can cite
`analysis/preregistration.md#<lowercased test_id>` (for example
`analysis/preregistration.md#rq1-dr-mcnemar`) and have the fragment resolve to the
registry row, alongside its eval run ids. Each row also carries its Bonferroni
correction family and corrected alpha so Story 5.5 reads the family membership
from the registry, not only from the Section 5 prose table.

| test_id | RQ | Test | Comparison | Correction family / corrected alpha | Pre-registered | Source |
|---|---|---|---|---|---|---|
| <a id="rq1-dr-mcnemar"></a>`RQ1-DR-MCNEMAR` | RQ1 | McNemar's paired | RSLT-full vs F (and vs RS, vs RSL) per scenario | four-way detection-rate family, 0.05 / 5 = 0.01 | yes | prd.md:119 |
| <a id="rq1-attack-kappa"></a>`RQ1-ATTACK-KAPPA` | RQ1 | Cohen's kappa | RSL and RSLT-full vs expert annotation | not applicable (agreement estimate; threshold kappa at least 0.75) | yes | prd.md:121 |
| <a id="rq2-mttd-kw-dunn-holm"></a>`RQ2-MTTD-KW-DUNN-HOLM` | RQ2 | Kruskal-Wallis omnibus plus Dunn's post-hoc with Holm | MTTD across configurations per scenario | Holm on the Dunn pairwise comparisons (post-hoc carries the multiplicity control) | yes | prd.md:122 |
| <a id="rq3-fpr-poisson"></a>`RQ3-FPR-POISSON` | RQ3 | One-sided Poisson rate test (TOST-style non-inferiority vs the 2/hour bound) | each LLM-bearing configuration (RSL, RSLT-full) vs the 2 escalations/hour tolerance bound | LLM-config equivalence family, 0.05 / 2 = 0.025 | yes | prd.md:120 |
| <a id="rq4-abl-l2-mcnemar"></a>`RQ4-ABL-L2-MCNEMAR` | RQ4 | McNemar's paired | L2 over L1-only | ablation family, 0.05 / 10 = 0.005 | yes | prd.md:124 |
| <a id="rq4-abl-senior-mcnemar"></a>`RQ4-ABL-SENIOR-MCNEMAR` | RQ4 | McNemar's paired | Senior over L1+L2 | ablation family, 0.05 / 10 = 0.005 | yes | prd.md:125 |
| <a id="rq4-fr55-bound"></a>`RQ4-FR55-BOUND` | RQ4 | empirical count | 0 of 100 trials past SUSPICIOUS; maximum ThreatScore at or below 10.5 (Claude) / 7.5 (Ollama) | not applicable (empirical bound check, not an NHST multiplicity family) | yes | prd.md:110; epics.md:2238 |
| <a id="rq5-rubric-wilcoxon-clarity"></a>`RQ5-RUBRIC-WILCOXON-CLARITY` | RQ5 | Wilcoxon signed-rank | LLM vs templated, Clarity dimension | rubric family, 0.05 / 5 = 0.01 | yes | prd.md:126 |
| <a id="rq5-rubric-wilcoxon-completeness"></a>`RQ5-RUBRIC-WILCOXON-COMPLETENESS` | RQ5 | Wilcoxon signed-rank | LLM vs templated, Completeness dimension | rubric family, 0.05 / 5 = 0.01 | yes | prd.md:126 |
| <a id="rq5-rubric-wilcoxon-attack-coverage"></a>`RQ5-RUBRIC-WILCOXON-ATTACK-COVERAGE` | RQ5 | Wilcoxon signed-rank | LLM vs templated, ATT&CK coverage dimension | rubric family, 0.05 / 5 = 0.01 | yes | prd.md:126 |
| <a id="rq5-rubric-wilcoxon-killchain"></a>`RQ5-RUBRIC-WILCOXON-KILLCHAIN` | RQ5 | Wilcoxon signed-rank | LLM vs templated, Kill-chain reconstruction accuracy dimension | rubric family, 0.05 / 5 = 0.01 | yes | prd.md:126 |
| <a id="rq5-rubric-wilcoxon-actionability"></a>`RQ5-RUBRIC-WILCOXON-ACTIONABILITY` | RQ5 | Wilcoxon signed-rank | LLM vs templated, Actionability dimension | rubric family, 0.05 / 5 = 0.01 | yes | prd.md:126 |
| <a id="rq5-icc"></a>`RQ5-ICC` | RQ5 | ICC(2,k) | inter-rater reliability on the rubric | not applicable (reliability estimate; threshold ICC at least 0.70) | yes | prd.md:112 |

<!-- prereg-registry-marker: the rows above are the canonical confirmatory test registry (BI-12). Story 5.5's analyse.py consumes this table. -->

### 8b. The confirmatory-vs-exploratory contract (enforced in Story 5.5)

Story 5.5's `analysis/analyse.py` reads the confirmatory test registry above. Any
test or metric in the pipeline's output whose `test_id` is not in the registry is
stamped `exploratory: true` and surfaced in a separate "Exploratory analyses"
output section, so the thesis discusses confirmatory and exploratory results
distinctly. This document writes the registry and the contract; Story 5.5
implements the membership check and the flagging. [Source: epics.md:2298-2300;
prd.md:319]

### 8c. The traceability contract

Every Chapter 3 or Chapter 4 claim that depends on a confirmatory test cites the
pre-registration row for that test (`analysis/preregistration.md#<lowercased
test_id>`, for example `analysis/preregistration.md#rq1-dr-mcnemar`) alongside the
eval run ids that produced the number. The per-claim citations land with Stories
5.5, 5.6, 5.7, and 5.9 as those numbers are produced; this pre-registration cannot
cite run ids that do not yet exist. The traceability matrix row
`c3.9.8-preregistration` (docs/traceability.md, section 3.9.8) registers this plan
as canonical and states this forward contract. [Source: epics.md:2302-2304,
2320-2322; NFR42]

## Amendments

Amendments are dated, additive, and never rewrite the frozen text above.

### A1 (2026-08-17): provider substitution and post-freeze status

The frozen plan pins `claude-opus-4-8`. The recorded 200-run campaign
(2026-07) ran `deepseek-chat` through the OpenAI-compatible provider
(trust-tier cap 30), because the pinned provider was unavailable to the
project at execution time. Per this plan's own amendment rule, every
confirmatory test whose result depends on the analyst model is therefore
reported as EXPLORATORY against this plan; deterministic-arm results
(F, RS) are unaffected. The substitution, its disclosure trail, and the
post-graduation decision authority are recorded in
`docs/deferred-decisions.md` ADR-2026-08-17-01.

### A2 (2026-08-17): risk-window scoring model for the publication campaign

The frozen plan's detection metrics assume the per-package scoring model.
The publication campaign additionally runs with the rolling per-workload
risk window (`OLT_RISK_WINDOW_SECONDS`, ADR-2026-08-17-01) enabled, which
allows independently-arriving rule and baseline signals to sum. Runs
carry `risk_window_seconds` in their metadata so the two scoring models
are machine-distinguishable; window-enabled results are reported as
exploratory against this plan and pre-registered afresh for any future
confirmatory claim.
