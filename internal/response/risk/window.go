// Package risk maintains a short rolling per-workload aggregate of the
// strongest detection signals seen recently, so the ThreatScore reflects a
// workload's CORRELATED evidence over a decay window rather than each
// EvidencePackage in isolation.
//
// Motivation: the rules and baseline engines each fire their own single-signal
// EvidencePackage through the correlator, so a workload's rule match and its
// baseline deviation arrive at the FSM as SEPARATE packages. Scoring each in
// isolation means the rule and baseline terms never sum, so a sustained
// multi-signal attack cannot escalate past the band a single signal justifies.
// A real graduated response should reflect the whole recent picture: a workload
// showing BOTH a high-severity rule match AND an anomalous baseline deviation
// within a short window is more dangerous than either alone.
//
// The window keeps, per workload, the single strongest RuleMatch (by severity)
// and the single strongest BaselineDeviation (by sigma) plus the max capped LLM
// confidence, all observed within TTL. Entries older than TTL reset, so risk
// decays when a workload goes quiet. The LLM value observed is ALREADY the
// per-provider-capped value (the trust-bound fence, FR55), so aggregation
// cannot inflate the LLM term beyond its cap.
package risk

import (
	"sync"
	"time"

	"github.com/olokotoh/olaitan/internal/decision/severitybucket"
	"github.com/olokotoh/olaitan/internal/schema"
)

// entry is a workload's current rolling aggregate.
type entry struct {
	rule      *schema.RuleMatch
	ruleScore int
	dev       *schema.BaselineDeviation
	llmCapped int
	updatedAt time.Time
}

// Window is a concurrency-safe per-workload rolling signal aggregate with TTL
// decay. A zero TTL disables aggregation (Observe returns the package's own
// signals unchanged, preserving the pre-risk-window per-package behaviour).
type Window struct {
	ttl time.Duration
	mu  sync.Mutex
	m   map[string]*entry
}

// New builds a Window with the given decay TTL. ttl <= 0 disables aggregation.
func New(ttl time.Duration) *Window {
	return &Window{ttl: ttl, m: make(map[string]*entry)}
}

// Observe folds one package's strongest signals into the workload's rolling
// aggregate and returns the aggregate to score: the strongest RuleMatch and
// BaselineDeviation seen within TTL, plus the max capped LLM confidence. With a
// disabled window (ttl <= 0) it returns the package's own signals and the
// passed llmCapped unchanged.
func (w *Window) Observe(workloadID string, pkg schema.EvidencePackage, llmCapped int, now time.Time) ([]schema.RuleMatch, []schema.BaselineDeviation, int) {
	if w == nil || w.ttl <= 0 {
		return pkg.RuleMatches, pkg.BaselineDeviations, llmCapped
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	e, ok := w.m[workloadID]
	if !ok || now.Sub(e.updatedAt) > w.ttl {
		e = &entry{}
		w.m[workloadID] = e
	}

	// Strongest rule match by bucketed severity.
	for i := range pkg.RuleMatches {
		rm := pkg.RuleMatches[i]
		s := severitybucket.Score(rm.Severity)
		if e.rule == nil || s > e.ruleScore {
			cp := rm
			e.rule = &cp
			e.ruleScore = s
		}
	}
	// Strongest baseline deviation by sigma.
	for i := range pkg.BaselineDeviations {
		bd := pkg.BaselineDeviations[i]
		if e.dev == nil || bd.Sigma > e.dev.Sigma {
			cp := bd
			e.dev = &cp
		}
	}
	if llmCapped > e.llmCapped {
		e.llmCapped = llmCapped
	}
	e.updatedAt = now

	var rules []schema.RuleMatch
	if e.rule != nil {
		rules = []schema.RuleMatch{*e.rule}
	}
	var devs []schema.BaselineDeviation
	if e.dev != nil {
		devs = []schema.BaselineDeviation{*e.dev}
	}
	return rules, devs, e.llmCapped
}
