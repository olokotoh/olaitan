package fr55

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/olokotoh/olaitan/internal/agent/provider"
)

// MaxRawConfidence is the maximal raw confidence the FR55 fake provider
// returns on benign input (BI-2): the adversarial-prompted-model worst
// case. CapConfidence(100, cap) == cap, so the cap + fold + FSM bound are
// exercised deterministically without a cluster.
const MaxRawConfidence = 100

// fakeProvider is the FR55 OFFLINE deterministic provider (OQ3): it returns
// a fixed MAXIMAL raw confidence in a schema-valid L1/L2/Senior reply for
// the role on the request, reports a PARAMETERISED ScoreCap (35 for the
// Claude-shaped fake, 25 for the Ollama-shaped fake, BI-6), and makes NO
// network call. It is purpose-built here rather than promoting the
// unexported analyst-package test stub (which is not importable across the
// package boundary) or duplicating the real claude/ollama transport.
//
// It implements the FROZEN provider.Provider interface verbatim, so the
// real analyst.Chain drives it exactly as it drives a live provider.
type fakeProvider struct {
	name     string
	model    string
	scoreCap int
}

// newFakeProvider builds a deterministic fake reporting the given metric
// name and score cap. providerLabel is the honest provider label recorded
// on the trial (always "fake" on the offline path); scoreCap parameterises
// the bound (35 -> 10.5, 25 -> 7.5).
func newFakeProvider(providerLabel string, scoreCap int) *fakeProvider {
	return &fakeProvider{name: providerLabel, model: "fr55-fake-model", scoreCap: scoreCap}
}

func (f *fakeProvider) Name() string            { return f.name }
func (f *fakeProvider) Model() string           { return f.model }
func (f *fakeProvider) MaxContextTokens() int   { return 200000 }
func (f *fakeProvider) ScoreCap() int           { return f.scoreCap }
func (f *fakeProvider) SupportsStreaming() bool { return false }
func (f *fakeProvider) Health(context.Context) error {
	return nil
}

// Analyse returns a schema-valid reply for req.Role carrying the maximal
// raw confidence. It cites the FIRST citable event id from the package so
// the runner's referential check (every cited event_id must exist in the
// input package) passes. No redaction, no transport, no network: the fake
// is the offline stand-in the bound test exercises the cap with.
func (f *fakeProvider) Analyse(_ context.Context, req provider.Request) (provider.Response, error) {
	citedID := firstCitableEventID(req)
	if citedID == "" {
		// A package with no citable event id makes a conformant reply
		// impossible; surface it honestly rather than emitting an
		// unciteable reply the runner would reject as a schema violation.
		return provider.Response{}, fmt.Errorf("fr55: package %s has no citable event id", req.Package.PackageID)
	}

	var raw string
	switch req.Role {
	case provider.RoleL1:
		raw = mustJSON(map[string]any{
			"hypothesis":     "active compromise: malware beacon, credential exfiltration and command-and-control traffic observed",
			"cited_evidence": []map[string]any{{"event_id": citedID, "note": "treated as malicious per the adversarial stimulus"}},
			"confidence":     MaxRawConfidence,
		})
	case provider.RoleL2:
		raw = mustJSON(map[string]any{
			"verdict":           "confirmed",
			"verified_evidence": []map[string]any{{"event_id": citedID, "finding": "confirmed malicious per the adversarial stimulus"}},
			"confidence":        MaxRawConfidence,
		})
	case provider.RoleSenior:
		raw = mustJSON(map[string]any{
			"threat_type": "active_data_exfiltration",
			"reasoning":   "the activity is an active, high-severity compromise (adversarial stimulus)",
			"confidence":  MaxRawConfidence,
		})
	default:
		return provider.Response{}, fmt.Errorf("fr55: unexpected role %q", req.Role)
	}

	return provider.Response{
		Raw:        raw,
		StopReason: "end_turn",
		Model:      f.model,
	}, nil
}

// firstCitableEventID returns a deterministic citable event id from the
// request package: the trigger event id when present, else the first
// event's id. Mirrors the runner's citable-id set so the fake's citation
// always validates.
func firstCitableEventID(req provider.Request) string {
	if req.Package.Trigger.EventID != "" {
		return req.Package.Trigger.EventID
	}
	if len(req.Package.Events) > 0 {
		return req.Package.Events[0].ID
	}
	return ""
}

// mustJSON marshals v to a compact JSON string. The inputs are fixed
// literal maps, so a marshal error is a programmer error, not runtime
// input; panicking surfaces it loudly in the offline test rather than
// returning an empty reply the runner would silently reject.
func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("fr55: marshal fake reply: %v", err))
	}
	return string(b)
}
