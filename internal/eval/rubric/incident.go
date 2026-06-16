// Package rubric hosts the Story 5.7 DFIR rubric study harness (RQ5), the
// OFFLINE component that produces the two report variants over the same
// incident evidence ((a) the Story-4.4 Olaitan DFIR LLM report, reused
// READ-ONLY, and (b) a NEW no-LLM templated baseline), distributes them as
// blind-randomised variant pairs to raters via a static-file workflow, and
// emits the per-(incident, variant, rater, dimension) rubric-scores artefact in
// the EXACT shape Story 5.5's analyse.build_rubric_rows consumes.
//
// # Scope and honesty fence (BI-2, the code-only-defer decision)
//
// 5.7 ships the GENERATORS + the seeded blind-randomised pairing + the
// rubric-scores artefact format + the static-file rater workflow + the
// committed rubric DEFINITION doc + an OFFLINE end-to-end proof against a SINGLE
// synthetic S1 incident. The REAL rater study (N>=3 human raters x N=10
// cluster-captured incidents per scenario) needs real raters + cluster-captured
// incidents and is a DEFERRED carry-forward, NOT this story's done-ness. The
// offline fixture scores are LABELLED synthetic (synthetic: true on every
// record, a rubric-offline- run-dir prefix, rater: synthetic-*) and are NEVER a
// thesis-final RQ5 number.
//
// # Variant (a): the Story-4.4 DFIR report, reused READ-ONLY (BI-1)
//
// Variant (a) is rendered by the FROZEN dfir.ForensicReport.Render(evt) renderer
// (internal/report/dfir/report.go). For the OFFLINE proof the harness constructs
// a ForensicReport with a SYNTHETIC narrative (a fixed string; NO live LLM call,
// like Story 5.6's fake provider) and calls Render. ForensicReport and Render
// are already exported with public fields, so no additive export to
// internal/report/dfir was required; this package consumes them read-only and
// changes NO Story-4.4 behaviour.
//
// # Variant (b): the NEW no-LLM templated baseline (BI-7)
//
// Variant (b) renders the SAME factual sections from the SAME incident evidence
// via a fixed Markdown template (templated.go) and makes NO LLM call. The
// (a)-vs-(b) contrast is the analyst narrative: (a) carries the LLM narrative,
// (b) carries a fixed templated stub.
//
// # Determinism (OQ5)
//
// The synthetic incident is built deterministically (no time.Now() in rendered
// content), the blind-randomised pairing RNG is seeded from the incident_id, and
// no map-iteration ordering leaks into rendered bytes, so both variants, the
// blinded pairs, and the emitted scores artefact are byte-reproducible (the
// offline golden is stable).
//
// # Ring discipline
//
// This package may import the report renderer it reuses read-only
// (internal/report/dfir), the schema substrate (internal/schema), and the
// response-side event it renders over (internal/response/settling). It does NOT
// import internal/decision/score or any FSM package, and it does NOT modify the
// Story-4.4 DFIR agent, the Story-5.5 statistics helpers, or the cluster-driven
// cmd/olaitan-eval Runner loop.
package rubric

import (
	"time"

	"github.com/olokotoh/olaitan/internal/report/dfir"
	"github.com/olokotoh/olaitan/internal/response/settling"
	"github.com/olokotoh/olaitan/internal/schema"
)

// SyntheticIncidentEpoch is the fixed UTC base time the synthetic incident is
// built from. A FIXED constant (not time.Now()) keeps the rendered timeline
// bytes deterministic across runs, so the offline golden never drifts (OQ5).
var syntheticIncidentEpoch = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

// SyntheticS1Incident builds the SINGLE deterministic synthetic S1 incident the
// OFFLINE proof renders both variants over (BI-2). It populates a representative
// settling.IncidentFinalised (a short kill-chain History), a schema.EvidencePackage,
// and a schema.ThreatAssessment carrying the S1 ATT&CK technique (T1611) and a
// kill-chain stage, all stamped deterministically off syntheticIncidentEpoch so
// the rendered reports are byte-reproducible.
//
// The incident_id is fixed (the seed for the blind-randomised pairing, OQ5) and
// carries the offline-synthetic marker so a reader can never mistake it for a
// real cluster-captured incident (BI-2). The REAL input is the N=10-per-scenario
// incidents captured during the Story-5.4 main runs (runs/<run_id>/); this
// single synthetic incident is the offline stand-in for the data-path proof.
func SyntheticS1Incident() dfir.Incident {
	const (
		incidentID = "rubric-offline-synthetic-s1-0001"
		workloadID = "default/Deployment/payments-api"
	)
	identity := schema.WorkloadIdentity{
		Namespace: "default",
		OwnerKind: "Deployment",
		OwnerName: "payments-api",
	}
	// A short, representative kill-chain History (control-plane facts only; the
	// renderer strips pod names and trigger-event ids). Timestamps step off the
	// fixed epoch so the rendered timeline is deterministic.
	history := []schema.StateTransition{
		{
			Timestamp:   syntheticIncidentEpoch,
			FromState:   schema.StateClean,
			ToState:     schema.StateSuspicious,
			TriggerType: "automated",
			Confidence:  35,
			Reason:      schema.ReasonEscalationThresholdCrossed,
			WorkloadID:  workloadID,
			PackageID:   incidentID,
		},
		{
			Timestamp:   syntheticIncidentEpoch.Add(5 * time.Minute),
			FromState:   schema.StateSuspicious,
			ToState:     schema.StateRestricted,
			TriggerType: "automated",
			Confidence:  55,
			Reason:      schema.ReasonEscalationThresholdCrossed,
			WorkloadID:  workloadID,
			PackageID:   incidentID,
		},
		{
			Timestamp:   syntheticIncidentEpoch.Add(12 * time.Minute),
			FromState:   schema.StateRestricted,
			ToState:     schema.StateQuarantined,
			TriggerType: "automated",
			Confidence:  72,
			Reason:      schema.ReasonEscalationThresholdCrossed,
			WorkloadID:  workloadID,
			PackageID:   incidentID,
		},
	}
	event := settling.IncidentFinalised{
		SchemaVersion: "incidents.finalised.v1",
		PackageID:     incidentID,
		WorkloadID:    workloadID,
		FinalState:    string(schema.StateQuarantined),
		ThreatScore:   72,
		FinalisedAt:   syntheticIncidentEpoch.Add(15 * time.Minute),
		History:       history,
	}
	pkg := schema.EvidencePackage{
		SchemaVersion:    "evidence.package.v1",
		PackageID:        incidentID,
		WorkloadID:       workloadID,
		WorkloadIdentity: identity,
		AssembledAt:      syntheticIncidentEpoch,
		WindowStart:      syntheticIncidentEpoch.Add(-10 * time.Minute),
		WindowEnd:        syntheticIncidentEpoch.Add(15 * time.Minute),
	}
	assessment := &schema.ThreatAssessment{
		ThreatType:       "container-escape",
		RecommendedState: schema.StateQuarantined,
		Reasoning:        "Synthetic S1 container-escape kill chain for the offline rubric proof.",
		MitreTechniques:  []string{"T1611"},
		KillChainStage:   "privilege-escalation",
		Mode:             schema.AnalysisMode("standard"),
	}
	return dfir.Incident{
		Event:      event,
		Package:    pkg,
		Assessment: assessment,
	}
}

// IncidentID returns the stable idempotency key for an incident (the package_id
// on the finalised event). It is the join key the rubric-scores records carry
// and the seed source for the blind-randomised pairing (OQ5).
func IncidentID(inc dfir.Incident) string {
	return inc.Event.PackageID
}
