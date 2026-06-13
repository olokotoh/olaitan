package analyst

import (
	"math"
	"strconv"

	"github.com/olokotoh/olaitan/internal/schema"
)

// TriggerSeverityFloor and TriggerSigmaFloor are the FR19 investigation
// trigger thresholds (Story 3.8 AC1): a chain spawns only for a package
// carrying a rule match of severity >= 50 OR a baseline deviation of at
// least 3 sigma.
const (
	TriggerSeverityFloor = 50
	TriggerSigmaFloor    = 3.0
)

// ShouldTriggerChain reports whether pkg qualifies for an LLM
// investigation chain under FR19 (Story 3.8 AC1): true iff any rule
// match has a resolved severity >= TriggerSeverityFloor OR any baseline
// deviation has sigma >= TriggerSigmaFloor.
//
// RuleMatch.Severity is wire-typed as a string but in this dialect is
// always strconv.Itoa of an integer in [0,100] (parser.go); it is parsed
// with strconv.Atoi here, NOT the keyword bucket, so a future keyword
// label cannot silently drift the FR19 contract. A non-numeric severity
// is treated as non-triggering (defensive; never panics). A NaN/Inf or
// negative sigma is structurally invalid (the baseline engine never
// emits one) and is skipped, mirroring score.Calculator.Score so a
// poisoned signal cannot trip the gate by surprise.
//
// Assembler reality (assembler.go:138-143): a published package carries
// EITHER one rule match OR one baseline deviation OR neither (a
// multi-signal trigger carries neither). A multi-signal-only package
// therefore never trips this gate, which is correct: FR19 is a
// rule-or-baseline gate and a bare multi-signal correlation is not by
// itself a chain trigger.
func ShouldTriggerChain(pkg schema.EvidencePackage) bool {
	for _, rm := range pkg.RuleMatches {
		s, err := strconv.Atoi(rm.Severity)
		if err != nil {
			continue
		}
		if s >= TriggerSeverityFloor {
			return true
		}
	}
	for _, bd := range pkg.BaselineDeviations {
		if math.IsNaN(bd.Sigma) || math.IsInf(bd.Sigma, 0) || bd.Sigma < 0 {
			continue
		}
		if bd.Sigma >= TriggerSigmaFloor {
			return true
		}
	}
	return false
}
