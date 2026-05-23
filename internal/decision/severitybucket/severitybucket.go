// Package severitybucket centralises the severity-label-to-score
// mapping used by the Story 1.14 correlator assembler for overflow
// prioritisation and the Story 1.18 rules-engine emission path for
// the severity_bucket label on
// olaitan_decision_rules_matches_by_attribute_total.
//
// The package exists to prevent drift between the two call sites
// (the original lived as an unexported helper in
// internal/correlator/assembler/assembler.go and would have had to
// be duplicated for the rules engine's emission path). Behaviour is
// preserved verbatim: the label -> score table, the syslog numeric
// override, and the default-low fall-through are identical to the
// pre-Story-1.18 assembler implementation.
//
// Score boundaries for the Bucket helper:
//
//	score <  50 -> "low"
//	score 50-69 -> "medium"
//	score 70-89 -> "high"
//	score >= 90 -> "critical"
//
// The four-bucket envelope is fixed and is the load-bearing label
// cardinality for AC2 of Story 1.18.
package severitybucket

import (
	"strconv"
	"strings"
)

const (
	// BucketLow / BucketMedium / BucketHigh / BucketCritical are the
	// four exported bucket names. Story 1.18 documents these as the
	// canonical label values for the severity_bucket label.
	BucketLow      = "low"
	BucketMedium   = "medium"
	BucketHigh     = "high"
	BucketCritical = "critical"
)

// Score maps a free-form severity label (or stringified syslog
// numeric code) to a 0-100 integer score. The mapping mirrors the
// pre-Story-1.18 assembler implementation:
//
//   - empty string -> 10 (default-low so a missing label does not
//     drown out tagged events during overflow prioritisation).
//   - syslog numeric "0".."7" -> syslogScore.
//   - "emergency"/"fatal"/"critical" -> 100.
//   - "alert"/"error"/"err"/"high" -> 80.
//   - "warning"/"warn"/"medium" -> 50.
//   - "notice"/"low" -> 30.
//   - anything else -> 10 (default-low).
//
// Numeric values outside the 0-7 syslog range fall through to keyword
// matching so an analyst-supplied "-1" or "8" lands on the default-low
// score rather than producing a misleading large-magnitude rank.
func Score(severity string) int {
	s := strings.ToLower(strings.TrimSpace(severity))
	if s == "" {
		return 10
	}
	if n, err := strconv.Atoi(s); err == nil {
		if n >= 0 && n <= 7 {
			return syslogScore(n)
		}
	}
	switch s {
	case "emergency", "fatal", "critical":
		return 100
	case "alert", "error", "err", "high":
		return 80
	case "warning", "warn", "medium":
		return 50
	case "notice", "low":
		return 30
	default:
		return 10
	}
}

// Bucket bucketises a 0-100 severity score into one of the four
// Story 1.18 buckets. Boundaries are inclusive at the lower edge
// and exclusive at the upper edge (medium = [50, 70), high = [70, 90),
// critical = [90, +Inf)). Negative scores fall into the low bucket
// (defensive default; the engine's emission gate cannot produce
// negative scores).
func Bucket(score int) string {
	switch {
	case score >= 90:
		return BucketCritical
	case score >= 70:
		return BucketHigh
	case score >= 50:
		return BucketMedium
	default:
		return BucketLow
	}
}

// BucketFromLabel is the Score + Bucket compose helper for callers
// that hold the raw severity label string (e.g. the rules engine
// reading schema.RuleMatch.Severity). Returns one of the four
// Bucket* constants.
func BucketFromLabel(severity string) string {
	return Bucket(Score(severity))
}

// syslogScore maps a numeric syslog severity (0=emergency .. 7=debug)
// to the 0-100 score space. The mapping preserves the assembler's
// pre-Story-1.18 behaviour exactly.
func syslogScore(n int) int {
	switch n {
	case 0:
		return 100
	case 1:
		return 90
	case 2:
		return 80
	case 3:
		return 70
	case 4:
		return 50
	case 5:
		return 40
	case 6:
		return 30
	case 7:
		return 10
	}
	return 10
}
