// Package parser converts OLT Sigma YAML rule files into typed *Rule
// values. The OLT dialect is a superset of upstream SIGMA-HQ: every
// upstream rule remains parseable, and OLT adds two required extras
// (`attack:` and the resolved severity convention) plus a stricter
// rule-ID grammar.
//
// The parser is a thin wrapper around github.com/runreveal/sigmalite's
// public API. It calls sigma.ParseRule to obtain a *sigma.Rule, then
// reads OLT-only fields from rule.Extra via the sigmalite Decoder
// interface. The wrap path is the strategy recorded by Story 1.2
// (ADR-2026-04-28-01); sigmalite source MUST NOT be vendored or
// patched. If a missing modifier ever surfaces it is upstreamed or
// adapted on the OLT side, never patched in-tree.
//
// Error string contracts: every public error returned from ParseRule
// is single-line and stable. Unit tests assert against the exact
// strings emitted here, and the spike POC at
// spikes/sigma-parser/wrap/main.go:parseOLTExtras carries the
// reference forms verbatim. Treat the strings as part of the API: do
// not rephrase without updating callers and tests in the same change.
package parser

import (
	"fmt"
	"regexp"
	"strconv"

	sigma "github.com/runreveal/sigmalite"
)

// AttackIDRegex matches MITRE ATT&CK base techniques (Tdddd) and
// sub-techniques (Tdddd.ddd). docs/sigma-extensions.md §4 is the
// dialect-side reference; the regex is exported so callers can reuse
// it for surface-level CI gates (Story 6.5 olaitan-lint).
var AttackIDRegex = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)

// RuleIDRegex matches the OLT rule-ID grammar: OLT-<CATEGORY>-NNN.
// The category set is closed and ordered to match
// docs/sigma-extensions.md §2; any new category requires a dialect
// spec update and a coordinated change here.
var RuleIDRegex = regexp.MustCompile(`^OLT-(EXEC|NET|FILE|PRIV|IMPACT|RECON|PERSIST|EXFIL|CRED|LATERAL)-[0-9]{3}$`)

// levelToSeverity is the SIGMA-HQ level→severity fallback per
// docs/sigma-extensions.md §8. The default (no severity, no level)
// is medium → 50, matching the spike POC.
var levelToSeverity = map[string]int{
	"informational": 10,
	"low":           30,
	"medium":        50,
	"high":          75,
	"critical":      90,
}

// defaultSeverity is the resolved value when a rule omits both
// severity: and level:.
const defaultSeverity = 50

// Rule is a typed wrapper around *sigma.Rule plus the OLT-only
// metadata resolved at parse time. SourcePath is set by the loader
// when the rule is read from disk; ParseRule leaves it blank so
// in-test callers can construct a Rule from bytes without a path.
//
// HasSeverity records whether the source YAML declared the
// `severity:` field explicitly. The deterministic ThreatScore
// consumer in Epic 2 must distinguish "operator chose 0 (the floor)"
// from "operator omitted severity and inherited the level fallback".
// Collapsing the two would lose the audit trail that lets a forensic
// reviewer reconstruct the operator's intent.
type Rule struct {
	*sigma.Rule

	Attack      []string
	Severity    int
	HasSeverity bool
	SourcePath  string
}

// ParseRule parses a single OLT Sigma rule YAML document. The rule's
// SourcePath is left blank; callers that own a file path should set
// it on the returned *Rule after parsing (the loader does this).
//
// Errors returned here are stable: the unit test suite asserts
// against the exact strings.
func ParseRule(yamlBytes []byte) (*Rule, error) {
	base, err := sigma.ParseRule(yamlBytes)
	if err != nil {
		return nil, err
	}
	if !RuleIDRegex.MatchString(base.ID) {
		return nil, fmt.Errorf("id: %q does not match %s", base.ID, RuleIDRegex.String())
	}
	attack, err := extractAttack(base)
	if err != nil {
		return nil, err
	}
	severity, hasSeverity, err := extractSeverity(base)
	if err != nil {
		return nil, err
	}
	return &Rule{
		Rule:        base,
		Attack:      attack,
		Severity:    severity,
		HasSeverity: hasSeverity,
	}, nil
}

func extractAttack(base *sigma.Rule) ([]string, error) {
	dec, ok := base.Extra["attack"]
	if !ok {
		return nil, fmt.Errorf("attack: required field is missing")
	}
	if dec == nil {
		return nil, fmt.Errorf("attack: must be a non-empty list")
	}
	var tags []string
	if err := dec.Decode(&tags); err != nil {
		return nil, fmt.Errorf("attack: must be a non-empty list (decode error: %w)", err)
	}
	if len(tags) == 0 {
		return nil, fmt.Errorf("attack: must be a non-empty list")
	}
	for _, id := range tags {
		if !AttackIDRegex.MatchString(id) {
			return nil, fmt.Errorf("attack: %q does not match %s", id, AttackIDRegex.String())
		}
	}
	return tags, nil
}

// extractSeverity resolves the rule's severity in three steps:
//
//  1. If the YAML has an explicit `severity:` field, use it. Explicit
//     `null` is rejected because operators who write `severity: null`
//     have made an explicit choice and should be told to either
//     remove the key or supply an integer. Out-of-range integers are
//     rejected.
//  2. Otherwise, if the rule has a `level:` field, look it up in the
//     SIGMA-HQ level table.
//  3. Otherwise, default to medium (50).
//
// HasSeverity is true only in case 1.
func extractSeverity(base *sigma.Rule) (int, bool, error) {
	if dec, ok := base.Extra["severity"]; ok {
		if dec == nil {
			return 0, false, fmt.Errorf("severity: explicit null is not permitted; omit the key to use the level fallback, or supply an integer 0-100")
		}
		var probe any
		if err := dec.Decode(&probe); err != nil {
			return 0, false, fmt.Errorf("severity: %w", err)
		}
		if probe == nil {
			return 0, false, fmt.Errorf("severity: explicit null is not permitted; omit the key to use the level fallback, or supply an integer 0-100")
		}
		var sev int
		if err := dec.Decode(&sev); err != nil {
			return 0, false, fmt.Errorf("severity: %w", err)
		}
		if sev < 0 || sev > 100 {
			return 0, false, fmt.Errorf("severity: %d is outside [0, 100]", sev)
		}
		return sev, true, nil
	}
	if base.Level != "" {
		level := string(base.Level)
		if mapped, found := levelToSeverity[level]; found {
			return mapped, false, nil
		}
		return 0, false, fmt.Errorf("level: %q is not a SIGMA-HQ level (informational, low, medium, high, critical)", level)
	}
	return defaultSeverity, false, nil
}

// SeverityString renders r.Severity as a decimal string. The
// schema.RuleMatch.Severity field is wire-typed as a string so it
// stays forward-compatible with future severity grammars; in this
// dialect it is always the resolved integer.
func (r *Rule) SeverityString() string {
	return strconv.Itoa(r.Severity)
}
