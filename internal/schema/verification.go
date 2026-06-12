package schema

// L2VerificationSchemaVersion is the canonical schema_version value the
// L2 runner stamps on every validated verification (Story 3.6 BI-3).
const L2VerificationSchemaVersion = "l2_verification.v1"

// Verdict values for L2Verification.Verdict (closed set, enforced by
// the l2_verification.v1 JSON schema enum).
const (
	VerdictConfirmed    = "confirmed"
	VerdictRefuted      = "refuted"
	VerdictInconclusive = "inconclusive"
)

// L2Verification is the structured verification verdict produced by the
// L2 sub-agent over an EvidencePackage plus the L1Hypothesis (FR23,
// Story 3.6). The model emits the verdict fields; schema_version is
// optional (or null) on the model side and force-stamped to
// L2VerificationSchemaVersion by the runner after validation. The
// on-wire shape is mirrored in docs/schemas/l2_verification.yaml
// (documentation) and docs/schemas/l2_verification.json (authoritative
// validation source).
type L2Verification struct {
	SchemaVersion         string                 `json:"schema_version,omitempty"`
	Verdict               string                 `json:"verdict"`
	VerifiedEvidence      []EvidenceVerification `json:"verified_evidence"`
	ContradictoryFindings []string               `json:"contradictory_findings,omitempty"`
	Confidence            int                    `json:"confidence"`
}

// EvidenceVerification is one entry of the evidence-by-evidence
// verification narrative. EventID must name an event present in the
// input package (the Story 3.5 referential rule, runner-enforced);
// Finding is the non-empty narrative for that event.
type EvidenceVerification struct {
	EventID string `json:"event_id"`
	Finding string `json:"finding"`
}
