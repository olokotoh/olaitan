package main

import (
	"strings"
	"testing"
)

// dfirUserInstructionPrefix mirrors internal/report/dfir/dfir.go's
// dfirUserInstruction, which is unexported. fakeLLMRole matches the USER-turn
// instruction each agent composes, not the system prompt file, which is the
// trap this test exists to document: feeding it
// internal/agent/prompts/defaults/dfir.txt routes to "l1", because that file
// says "write the interpretive analyst narrative" while the instruction the
// provider actually sends says "Produce ...". Both strings are real; only the
// second one reaches the model request.
const dfirUserInstructionPrefix = "Produce the interpretive analyst narrative for the finalised incident "

// TestFakeLLMRoutesDFIRInstructionToDFIR is Story 10.7. The fake-LLM had no
// DFIR role at all, so a report-archive run against the fixture provider fell
// through to "l1" and returned an l1-shaped verdict where the report schema
// expects a narrative.
func TestFakeLLMRoutesDFIRInstructionToDFIR(t *testing.T) {
	body := `{"messages":[{"role":"user","content":"` + dfirUserInstructionPrefix + `abc-123."}]}`
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
