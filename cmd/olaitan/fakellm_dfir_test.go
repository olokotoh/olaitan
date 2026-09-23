package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/olokotoh/olaitan/internal/report/dfir"
)

// The DFIR request is identified by the USER-turn instruction the DFIR agent
// actually sends (dfir.UserInstruction), not by the system prompt file. That
// is the trap this test documents: feeding it
// internal/agent/prompts/defaults/dfir.txt routes to "l1", because that file
// says "write the interpretive analyst narrative" while the instruction the
// provider sends says "Produce ...". The test uses the exported constant
// itself, so rewording the instruction in dfir.go without updating
// fakeLLMRole turns this test red instead of silently routing live DFIR
// requests back to "l1".

// TestFakeLLMRoutesDFIRInstructionToDFIR is Story 10.7. The fake-LLM had no
// DFIR role at all, so a report-archive run against the fixture provider fell
// through to "l1" and returned an l1-shaped verdict where the report schema
// expects a narrative.
func TestFakeLLMRoutesDFIRInstructionToDFIR(t *testing.T) {
	content, err := json.Marshal(dfir.UserInstruction)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"messages":[{"role":"user","content":` + string(content) + `}]}`
	if got := fakeLLMRole(body); got != "dfir" {
		t.Errorf("the DFIR user instruction routed to %q, not \"dfir\"; "+
			"the fake-LLM would answer a DFIR request with an %s-shaped verdict", got, got)
	}
}

// TestFakeLLMOtherRolesStillRoute guards the fix: adding the DFIR arm must not
// swallow the roles that were already working.
func TestFakeLLMOtherRolesStillRoute(t *testing.T) {
	for _, tc := range []struct{ instruction, want string }{
		{"You are the senior analyst finalising the assessment.", "senior"},
		{"Verify the L1 analyst's hypothesis against the evidence.", "l2"},
		{"Form an initial hypothesis from the evidence.", "l1"},
	} {
		if got := fakeLLMRole(tc.instruction); got != tc.want {
			t.Errorf("%q routed to %q, want %q", tc.instruction, got, tc.want)
		}
	}
}

// TestFakeLLMDFIRVerdictMatchesReportSchema is AC1's other half: report.v1
// permits exactly one property, narrative, with additionalProperties false.
func TestFakeLLMDFIRVerdictMatchesReportSchema(t *testing.T) {
	v := fakeLLMVerdict("dfir", "evt-1")
	if !strings.Contains(v, `"narrative"`) {
		t.Errorf("dfir verdict carries no narrative property: %s", v)
	}
	for _, forbidden := range []string{`"verdict"`, `"confidence"`, `"hypothesis"`, `"verified_evidence"`} {
		if strings.Contains(v, forbidden) {
			t.Errorf("dfir verdict carries %s, which report.v1 forbids (additionalProperties false): %s", forbidden, v)
		}
	}
}

// TestFakeLLMDFIRNarrativeIsLabelledFixture: the DFIR narrative is canned
// text, and it ends up inside archived reports that are quoted as live
// evidence (Story 10.7 AC4). It must say it is fixture output and must not
// assert incident facts (a ServiceAccount token read, an escalation to
// RESTRICTED) that the real incident may contradict: the AC4 incident was an
// /etc/shadow read that finalised at SUSPICIOUS.
func TestFakeLLMDFIRNarrativeIsLabelledFixture(t *testing.T) {
	var v struct {
		Narrative string `json:"narrative"`
	}
	if err := json.Unmarshal([]byte(fakeLLMVerdict("dfir", "evt-1")), &v); err != nil {
		t.Fatalf("dfir verdict is not JSON: %v", err)
	}
	if !strings.Contains(v.Narrative, "fixture narrative from the fake LLM") {
		t.Errorf("dfir narrative does not label itself as fixture output: %q", v.Narrative)
	}
	for _, claim := range []string{"ServiceAccount", "RESTRICTED", "SUSPICIOUS", "external connection"} {
		if strings.Contains(v.Narrative, claim) {
			t.Errorf("dfir fixture narrative asserts an incident fact (%q) no model derived: %q", claim, v.Narrative)
		}
	}
}
