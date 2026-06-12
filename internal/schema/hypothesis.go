package schema

// L1HypothesisSchemaVersion is the canonical schema_version value the L1
// runner stamps on every validated hypothesis (Story 3.5 BI-4).
const L1HypothesisSchemaVersion = "l1_hypothesis.v1"

// L1Hypothesis is the structured first-pass analyst verdict produced by
// the L1 sub-agent (FR21, Story 3.5). The model emits the verdict fields;
// schema_version is optional on the model side and force-stamped to
// L1HypothesisSchemaVersion by the runner after validation, so a model
// that omits or mangles it cannot burn a Story 3.10 retry strike on
// metadata. The on-wire shape is mirrored in
// docs/schemas/l1_hypothesis.yaml (documentation) and
// docs/schemas/l1_hypothesis.json (authoritative validation source).
type L1Hypothesis struct {
	SchemaVersion  string             `json:"schema_version,omitempty"`
	Hypothesis     string             `json:"hypothesis"`
	CitedEvidence  []EvidenceCitation `json:"cited_evidence"`
	FollowUpProbes []string           `json:"follow_up_probes,omitempty"`
	Confidence     int                `json:"confidence"`
}

// EvidenceCitation references one event from the input EvidencePackage.
// EventID must name an event present in the package; a citation outside
// the package is a schema violation handled by the Story 3.10 validation
// policy (Story 3.5 AC3).
type EvidenceCitation struct {
	EventID string `json:"event_id"`
	Note    string `json:"note,omitempty"`
}
