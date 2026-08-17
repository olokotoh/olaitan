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
// The window keeps, per workload, the single strongest RuleMatch (by numeric
// severity), the single strongest BaselineDeviation (by sigma), and the max
// capped LLM confidence. Each retained signal carries ITS OWN observation
// timestamp and expires independently once it is older than TTL, so risk truly
// decays: a critical rule match observed at t=0 stops contributing at t=TTL
// even if unrelated weak packages keep arriving for the workload (PR #92
// review: the previous single updatedAt was refreshed by every package, which
// turned the decay TTL into an inactivity timeout and blocked FSM
// de-escalation under sustained benign traffic). Entries whose signals have
// all expired are deleted by a lazy sweep at most once per TTL, bounding the
// map under workload churn (PR #92 review: unbounded growth).
//
// The LLM value observed is ALREADY the per-provider-capped value (the
// trust-bound fence, FR55), so aggregation cannot inflate the LLM term beyond
// its cap.
package risk

import (
	"math"
	"strconv"
	"sync"
	"time"

	"github.com/olokotoh/olaitan/internal/schema"
)

// severityRank ranks a RuleMatch severity for "strongest match" selection,
// mirroring EXACTLY how the score calculator reads severity: a numeric string
// is its value clamped to [0, 100]; anything non-numeric returns -1 because
// the calculator's strconv.Atoi loop skips it, i.e. it contributes zero to the
// rule term (PR #92 review: ranking keywords via severitybucket let a
// "critical" match displace a numeric "90" as strongest and zero the
// aggregate's rule term, making the windowed score LOWER than the solo score).
func severityRank(sev string) int {
	n, err := strconv.Atoi(sev)
	if err != nil {
		return -1
	}
	if n < 0 {
		return 0
	}
	if n > 100 {
		return 100
	}
	return n
}

// entry is a workload's current rolling aggregate. Every retained signal
// carries its own observation time so each decays independently.
type entry struct {
	rule      *schema.RuleMatch
	ruleScore int
	ruleAt    time.Time
	dev       *schema.BaselineDeviation
	devAt     time.Time
	llmCapped int
	llmAt     time.Time
}

// expire clears any retained signal older than ttl and reports whether the
// entry still holds anything.
func (e *entry) expire(now time.Time, ttl time.Duration) bool {
	if e.rule != nil && now.Sub(e.ruleAt) > ttl {
		e.rule, e.ruleScore = nil, 0
	}
	if e.dev != nil && now.Sub(e.devAt) > ttl {
		e.dev = nil
	}
	if e.llmCapped > 0 && now.Sub(e.llmAt) > ttl {
		e.llmCapped = 0
	}
	return e.rule != nil || e.dev != nil || e.llmCapped > 0
}

// Window is a concurrency-safe per-workload rolling signal aggregate with
// per-signal TTL decay. A zero TTL disables aggregation (Observe returns the
// package's own signals unchanged, preserving the pre-risk-window per-package
// behaviour).
type Window struct {
	ttl       time.Duration
	mu        sync.Mutex
	m         map[string]*entry
	lastSweep time.Time
}

// New builds a Window with the given decay TTL. ttl <= 0 disables aggregation.
func New(ttl time.Duration) *Window {
	return &Window{ttl: ttl, m: make(map[string]*entry)}
}

// Enabled reports whether the window actually aggregates (a nil window or a
// non-positive TTL is pass-through). Used by the FSM consumer's transition
// logging so an operator can tell a windowed score from a solo one.
func (w *Window) Enabled() bool {
	return w != nil && w.ttl > 0
}

// Observe folds one package's strongest signals into the workload's rolling
// aggregate and returns the aggregate to score: the strongest RuleMatch and
// BaselineDeviation still live within TTL, plus the max live capped LLM
// confidence. When the aggregate holds no stored rule (or deviation), the
// package's own matches (or deviations) are returned unchanged, so a workload
// with no retained history scores exactly as it would without the window.
// With a disabled window (ttl <= 0) it returns the package's own signals and
// the passed llmCapped unchanged.
//
// The caller should pass time.Now() directly (NOT time.Now().UTC()): stripping
// the monotonic reading would make TTL arithmetic wall-clock sensitive, so an
// NTP step could retain stale signals past TTL or flush live ones (PR #92
// review).
func (w *Window) Observe(workloadID string, pkg schema.EvidencePackage, llmCapped int, now time.Time) ([]schema.RuleMatch, []schema.BaselineDeviation, int) {
	if w == nil || w.ttl <= 0 {
		return pkg.RuleMatches, pkg.BaselineDeviations, llmCapped
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	// Lazy sweep at most once per TTL: drop entries whose signals have all
	// expired so churned workload IDs do not accumulate forever.
	if now.Sub(w.lastSweep) > w.ttl {
		for id, e := range w.m {
			if !e.expire(now, w.ttl) {
				delete(w.m, id)
			}
		}
		w.lastSweep = now
	}

	e, ok := w.m[workloadID]
	if !ok {
		e = &entry{}
	} else {
		e.expire(now, w.ttl)
	}

	// Strongest rule match by numeric severity (non-numeric ranks -1 and can
	// never displace a numeric match; the calculator scores it zero anyway).
	for i := range pkg.RuleMatches {
		rm := pkg.RuleMatches[i]
		s := severityRank(rm.Severity)
		if s < 0 {
			continue
		}
		if e.rule == nil || s > e.ruleScore {
			cp := rm
			e.rule = &cp
			e.ruleScore = s
			e.ruleAt = now
		}
	}
	// Strongest baseline deviation by sigma. NaN/Inf/negative sigmas are
	// skipped, mirroring the score calculator: a poisoned sigma must never
	// become the retained strongest and suppress a real deviation.
	for i := range pkg.BaselineDeviations {
		bd := pkg.BaselineDeviations[i]
		if math.IsNaN(bd.Sigma) || math.IsInf(bd.Sigma, 0) || bd.Sigma < 0 {
			continue
		}
		if e.dev == nil || bd.Sigma > e.dev.Sigma {
			cp := bd
			e.dev = &cp
			e.devAt = now
		}
	}
	if llmCapped > e.llmCapped {
		e.llmCapped = llmCapped
		e.llmAt = now
	}

	// Persist the entry only when it retains something; a signal-less
	// package must neither create map growth nor refresh anyone's decay.
	if e.rule != nil || e.dev != nil || e.llmCapped > 0 {
		w.m[workloadID] = e
	} else {
		delete(w.m, workloadID)
	}

	rules := pkg.RuleMatches
	if e.rule != nil {
		rules = []schema.RuleMatch{*e.rule}
	}
	devs := pkg.BaselineDeviations
	if e.dev != nil {
		devs = []schema.BaselineDeviation{*e.dev}
	}
	llm := llmCapped
	if e.llmCapped > llm {
		llm = e.llmCapped
	}
	return rules, devs, llm
}
