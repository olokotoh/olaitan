package rubric

// SchemaVersionRubricScore is the schema_version stamped on every rubric-scores
// record (OQ4). It versions the per-(incident, variant, rater, dimension) Likert
// record contract the Go emitter writes and the Story-5.5 load_rubric_scores
// reader consumes; the two must not drift.
const SchemaVersionRubricScore = "rubric.score.v1"

// Dimension is one of the 5 CANONICAL PRD rubric dimensions (BI-5, FIXED by the
// pre-registration). The string keys are EXACTLY the keys Story 5.5's
// build_rubric_rows registry expects (analyse.py: clarity / completeness /
// attack-coverage / killchain / actionability), mapping to the prereg ids
// RQ5-RUBRIC-WILCOXON-{CLARITY,COMPLETENESS,ATTACK-COVERAGE,KILLCHAIN,ACTIONABILITY}.
// A 6th "overall usefulness" dimension is NOT added here: it would break the
// confirmatory family=5 Bonferroni (0.05/5 = 0.01) and is EXPLORATORY-only.
type Dimension string

const (
	DimClarity        Dimension = "clarity"
	DimCompleteness   Dimension = "completeness"
	DimAttackCoverage Dimension = "attack-coverage"
	DimKillchain      Dimension = "killchain"
	DimActionability  Dimension = "actionability"
)

// CanonicalDimensions is the FIXED, ordered list of the 5 confirmatory rubric
// dimensions (BI-5). The order is stable (the scoring sheet and the emitted
// records iterate it) so the offline artefact bytes are deterministic. It is the
// authoritative family; do NOT add a 6th member.
var CanonicalDimensions = []Dimension{
	DimClarity,
	DimCompleteness,
	DimAttackCoverage,
	DimKillchain,
	DimActionability,
}

// LikertMin and LikertMax are the documented Likert scale bounds (1-5) the
// rubric is collected on (AC4; the scale + anchors are committed in the rubric
// DEFINITION doc analysis/rubric/rubric-definition.md). Scores outside the range
// are rejected by the emitter (an honest validation error, never a silent clamp).
const (
	LikertMin = 1
	LikertMax = 5
)

// RubricScore is ONE rubric.score.v1 record: a single rater's Likert score for a
// single (incident, variant, dimension) cell (OQ4). One record per
// (incident_id, variant, rater, dimension). The JSON field names are the wire
// contract the Story-5.5 reader parses; they are LOCKED so the Go emitter and
// the Python reader cannot drift.
type RubricScore struct {
	SchemaVersion string    `json:"schema_version"`
	IncidentID    string    `json:"incident_id"`
	Scenario      string    `json:"scenario"`
	Variant       Variant   `json:"variant"`
	Rater         string    `json:"rater"`
	Dimension     Dimension `json:"dimension"`
	Score         int       `json:"score"`
	// Synthetic is the HONESTY marker (BI-2): true on the OFFLINE synthetic set,
	// so a reader can never mistake a placeholder score for a real rater score.
	Synthetic bool `json:"synthetic"`
}
