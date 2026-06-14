package dfir

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// parseForensicReport runs the validation pipeline mirroring the analyst
// parseL1Hypothesis / parseSeniorVerdict (Story 3.5 BI-6): trim, strip ONE
// wrapping markdown code fence, JSON-schema validate against the embedded
// report.v1 contract, then decode. Programmatic checks cover the whitespace
// classes JSON Schema cannot express (a whitespace-only body is rejected so a
// blank report never renders as a success).
//
// Only the model-supplied fields (narrative and any model-supplied posture
// findings) are read off the decode here; the deterministic front-matter and
// the factual sections are force-stamped / rendered from the authoritative
// incident (AC2, round-1 review follow-up), so a model that returns a
// hallucinated incident_id / final_state / technique cannot influence the
// report header or the factual sections even though those fields are
// schema-required (the model must still PRODUCE them for the schema to pass,
// which keeps the contract honest).
func parseForensicReport(sch *jsonschema.Schema, raw string) (ForensicReport, error) {
	var zero ForensicReport
	body := strings.TrimSpace(raw)
	if body == "" {
		return zero, errors.New("empty response body")
	}
	body = stripWrappingFence(body)
	if body == "" {
		return zero, errors.New("empty response body after stripping the code fence")
	}

	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(body))
	if err != nil {
		return zero, fmt.Errorf("decode response JSON: %w", err)
	}
	if err := sch.Validate(inst); err != nil {
		return zero, fmt.Errorf("validate against %s: %w", SchemaVersionForensicReport, err)
	}

	var report ForensicReport
	if err := json.Unmarshal([]byte(body), &report); err != nil {
		return zero, fmt.Errorf("decode into ForensicReport: %w", err)
	}

	// minLength counts code points, so a whitespace-only narrative passes the
	// schema; reject it here so a blank report never renders as a success.
	if strings.TrimSpace(report.Narrative) == "" {
		return zero, errors.New("report narrative is whitespace-only")
	}
	return report, nil
}

// stripWrappingFence removes ONE wrapping markdown code fence if and only if the
// trimmed body starts with a fence line and ends with a closing fence (the
// analyst stripWrappingFence semantics, Story 3.5 BI-6.2). The entire first line
// (the fence and any language tag) is discarded; a single-line crammed payload
// strips to "" and lands in the empty-after-fence branch, a multi-line crammed
// payload reaches the JSON decoder and fails there. Partial or unclosed fences
// are returned unchanged and fail JSON decoding. Both LF and bare-CR terminate
// the fence line.
func stripWrappingFence(body string) string {
	if !strings.HasPrefix(body, "```") {
		return body
	}
	nl := strings.IndexAny(body, "\r\n")
	if nl < 0 {
		return body
	}
	rest := strings.TrimSpace(body[nl+1:])
	if !strings.HasSuffix(rest, "```") {
		return body
	}
	return strings.TrimSpace(strings.TrimSuffix(rest, "```"))
}
