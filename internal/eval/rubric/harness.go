package rubric

import (
	"fmt"
	"sort"

	"github.com/olokotoh/olaitan/internal/report/dfir"
)

// OfflineRunDirPrefix labels the OFFLINE synthetic rubric run-dir (BI-2): the
// emitted artefacts land under runs/rubric/<prefix><scenario>/ so a reader can
// tell the offline synthetic set apart from a future real cluster-captured run
// at a glance. The honest marker mirrors the Story-5.6 fr55-offline- prefix.
const OfflineRunDirPrefix = "rubric-offline-"

// OfflineRaterPrefix labels every synthetic rater (BI-2): the offline scores
// carry rater: synthetic-1 / synthetic-2 / ... so a placeholder score is never
// mistaken for a real rater's.
const OfflineRaterPrefix = "synthetic-"

// Result is the OFFLINE rubric proof's in-memory output: the blinded pairs (one
// per incident), the emitted rubric.score.v1 records (one per
// incident/variant/rater/dimension), and the run summary the emitter and the CLI
// banner read. It is byte-deterministic for a fixed input (seeded pairing, sorted
// record order, no wall-clock).
type Result struct {
	Scenario string
	Pairs    []BlindedPair
	Scores   []RubricScore
	Summary  Summary
}

// Summary carries the join/provenance keys the metadata.yaml records (OQ4): the
// scenario, the incident/rater counts, and the synthetic honesty flag.
type Summary struct {
	Scenario   string
	NIncidents int
	NRaters    int
	Synthetic  bool
}

// Options parameterise the OFFLINE rubric run. NRaters synthesises N>=2
// synthetic raters so ICC(2,k) has >= 2 raters to exercise the path (BI-2/AC5);
// the scores are clearly synthetic and never thesis-final.
type Options struct {
	Scenario string
	NRaters  int
}

// RunOffline runs the OFFLINE rubric proof end-to-end against the SINGLE
// synthetic S1 incident (BI-2/AC5): it builds the incident, blind-pairs the two
// variants (seeded, reproducible), and synthesises clearly-SYNTHETIC placeholder
// rater scores for every (incident, variant, rater, dimension) cell. The result
// is byte-deterministic. The synthetic scores are LABELLED synthetic on every
// record; they are NEVER a thesis-final RQ5 number.
func RunOffline(opts Options) (Result, error) {
	scenario := opts.Scenario
	if scenario == "" {
		scenario = "s1"
	}
	nRaters := opts.NRaters
	if nRaters < 2 {
		// ICC needs >= 2 raters; default to 2 synthetic raters so the offline
		// proof exercises the ICC path (it still degrades honestly at n=1
		// incident, which is the data-path proof, not a fabricated number).
		nRaters = 2
	}

	inc := SyntheticS1Incident()
	incidents := []dfir.Incident{inc}

	pairs := make([]BlindedPair, 0, len(incidents))
	for _, in := range incidents {
		pairs = append(pairs, BlindPair(in))
	}

	scores, err := synthesiseScores(scenario, incidents, nRaters)
	if err != nil {
		return Result{}, err
	}

	return Result{
		Scenario: scenario,
		Pairs:    pairs,
		Scores:   scores,
		Summary: Summary{
			Scenario:   scenario,
			NIncidents: len(incidents),
			NRaters:    nRaters,
			Synthetic:  true,
		},
	}, nil
}

// synthesiseScores produces clearly-SYNTHETIC placeholder rater scores for every
// (incident, variant, rater, dimension) cell (BI-2). The scores are derived
// deterministically (a fixed per-variant/per-dimension/per-rater formula within
// the Likert 1-5 range) so the offline artefact is byte-reproducible; they carry
// NO real-world meaning and are stamped synthetic: true. The LLM variant is given
// a deterministically slightly-higher placeholder than the templated baseline so
// the paired-difference path is exercised (a non-zero difference, so Wilcoxon
// does not short-circuit on all-zero differences), but with n=1 incident Wilcoxon
// still SKIPS honestly; the value is a data-path placeholder, not a finding.
func synthesiseScores(scenario string, incidents []dfir.Incident, nRaters int) ([]RubricScore, error) {
	var scores []RubricScore
	for _, inc := range incidents {
		incidentID := IncidentID(inc)
		for raterIdx := 1; raterIdx <= nRaters; raterIdx++ {
			rater := fmt.Sprintf("%s%d", OfflineRaterPrefix, raterIdx)
			for dimIdx, dim := range CanonicalDimensions {
				for _, variant := range []Variant{VariantLLM, VariantTemplated} {
					score := placeholderScore(variant, dimIdx, raterIdx)
					if score < LikertMin || score > LikertMax {
						return nil, fmt.Errorf("rubric: synthetic score %d out of Likert range [%d,%d]", score, LikertMin, LikertMax)
					}
					scores = append(scores, RubricScore{
						SchemaVersion: SchemaVersionRubricScore,
						IncidentID:    incidentID,
						Scenario:      scenario,
						Variant:       variant,
						Rater:         rater,
						Dimension:     dim,
						Score:         score,
						Synthetic:     true,
					})
				}
			}
		}
	}
	// Sort the records into a stable order so the emitted JSONL bytes are
	// deterministic (incident, rater, dimension, variant) regardless of map or
	// loop ordering changes.
	sort.SliceStable(scores, func(i, j int) bool {
		a, b := scores[i], scores[j]
		if a.IncidentID != b.IncidentID {
			return a.IncidentID < b.IncidentID
		}
		if a.Rater != b.Rater {
			return a.Rater < b.Rater
		}
		if a.Dimension != b.Dimension {
			return a.Dimension < b.Dimension
		}
		return a.Variant < b.Variant
	})
	return scores, nil
}

// placeholderScore returns a deterministic SYNTHETIC Likert score in [1,5] for a
// (variant, dimension index, rater index) cell. The LLM variant is offset one
// point above the templated baseline (clamped to the range) so the paired
// difference is non-zero (exercising the Wilcoxon path), with a small per-rater
// jitter so the ICC frame is not perfectly degenerate. It is a placeholder, NOT
// a finding: the n=1-incident sample makes Wilcoxon skip honestly regardless.
func placeholderScore(variant Variant, dimIdx, raterIdx int) int {
	base := 3 + (dimIdx % 2) // 3 or 4, deterministic per dimension
	if variant == VariantLLM {
		base++ // the synthetic LLM placeholder sits one point above the baseline
	}
	// A tiny per-rater jitter so two raters do not produce identical rows (the
	// ICC frame needs some across-rater variance to be non-degenerate).
	base += (raterIdx - 1) % 2
	if base < LikertMin {
		base = LikertMin
	}
	if base > LikertMax {
		base = LikertMax
	}
	return base
}
