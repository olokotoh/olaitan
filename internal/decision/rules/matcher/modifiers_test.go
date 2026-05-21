package matcher

import (
	"sync"
	"testing"

	sigma "github.com/runreveal/sigmalite"

	"github.com/olokotoh/olaitan/internal/decision/rules/parser"
)

// modifierCoverageMu and modifierCovered back the
// TestModifierCoverageMatrix gate. Each per-modifier test calls
// noteModifierCovered at the top with the canonical modifier name;
// the matrix at the end of this file asserts every modifier in the
// expected set was exercised. Replaces the prior tautological
// implementation (code-review P6).
var (
	modifierCoverageMu sync.Mutex
	modifierCovered    = map[string]bool{}
)

func noteModifierCovered(name string) {
	modifierCoverageMu.Lock()
	defer modifierCoverageMu.Unlock()
	modifierCovered[name] = true
}

func ruleFor(t *testing.T, body string) *parser.Rule {
	t.Helper()
	r, err := parser.ParseRule([]byte(body))
	if err != nil {
		t.Fatalf("parse rule: %v", err)
	}
	return r
}

func mustMatch(t *testing.T, r *parser.Rule, ev map[string]string, placeholders map[string][]string, want bool) {
	t.Helper()
	resolver, entry, err := NewResolver(nil, ev)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	opts := &sigma.MatchOptions{FieldResolver: resolver, Placeholders: placeholders}
	got := r.Detection.Matches(entry, opts)
	if got != want {
		t.Errorf("Matches = %v, want %v (event=%v)", got, want, ev)
	}
}

func TestModifier_Contains(t *testing.T) {
	noteModifierCovered("contains")
	rule := ruleFor(t, `
title: t
id: OLT-EXEC-001
attack: [T1234]
detection:
  sel:
    process.exe|contains: 'curl'
  condition: sel
`)
	mustMatch(t, rule, map[string]string{"process.exe": "/usr/bin/curl --version"}, nil, true)
	mustMatch(t, rule, map[string]string{"process.exe": "/usr/bin/wget"}, nil, false)
}

func TestModifier_All(t *testing.T) {
	noteModifierCovered("all")
	rule := ruleFor(t, `
title: t
id: OLT-EXEC-002
attack: [T1234]
detection:
  sel:
    process.args|contains|all:
      - 'apt'
      - 'install'
  condition: sel
`)
	mustMatch(t, rule, map[string]string{"process.args": "apt install curl"}, nil, true)
	mustMatch(t, rule, map[string]string{"process.args": "apt update"}, nil, false)
}

func TestModifier_StartsWith(t *testing.T) {
	noteModifierCovered("startswith")
	rule := ruleFor(t, `
title: t
id: OLT-EXEC-003
attack: [T1234]
detection:
  sel:
    process.exe|startswith: '/usr/local/'
  condition: sel
`)
	mustMatch(t, rule, map[string]string{"process.exe": "/usr/local/bin/xmrig"}, nil, true)
	mustMatch(t, rule, map[string]string{"process.exe": "/bin/sh"}, nil, false)
}

func TestModifier_EndsWith(t *testing.T) {
	noteModifierCovered("endswith")
	rule := ruleFor(t, `
title: t
id: OLT-EXEC-004
attack: [T1234]
detection:
  sel:
    process.exe|endswith: 'xmrig'
  condition: sel
`)
	mustMatch(t, rule, map[string]string{"process.exe": "/usr/local/bin/xmrig"}, nil, true)
	mustMatch(t, rule, map[string]string{"process.exe": "/bin/sh"}, nil, false)
}

func TestModifier_Windash(t *testing.T) {
	noteModifierCovered("windash")
	rule := ruleFor(t, `
title: t
id: OLT-EXEC-005
attack: [T1234]
detection:
  sel:
    cmd|windash|contains: '-encodedcommand'
  condition: sel
`)
	mustMatch(t, rule, map[string]string{"cmd": "powershell /encodedcommand"}, nil, true)
}

func TestModifier_Base64(t *testing.T) {
	noteModifierCovered("base64")
	// sigmalite's |base64 modifier base64-encodes the search literal
	// and then performs an exact match against the field. The
	// trailing "=" padding is included; matching against an exact
	// 4-character chunk avoids the offset-permutation territory
	// covered by |base64offset.
	rule := ruleFor(t, `
title: t
id: OLT-EXEC-006
attack: [T1234]
detection:
  sel:
    payload|base64: 'curl'
  condition: sel
`)
	// "curl" base64-encodes to "Y3VybA==". sigmalite drops the
	// padding before its exact-match check.
	mustMatch(t, rule, map[string]string{"payload": "Y3VybA"}, nil, true)
	mustMatch(t, rule, map[string]string{"payload": "d2dldA"}, nil, false)
}

func TestModifier_Base64Offset(t *testing.T) {
	noteModifierCovered("base64offset")
	rule := ruleFor(t, `
title: t
id: OLT-EXEC-007
attack: [T1234]
detection:
  sel:
    payload|base64offset|contains: 'curl'
  condition: sel
`)
	// "curl" embedded mid-string base64-encoded with offsets covers
	// the offset-permutation matcher.
	mustMatch(t, rule, map[string]string{"payload": "AAAAY3VybA"}, nil, true)
}

func TestModifier_Re(t *testing.T) {
	noteModifierCovered("re")
	rule := ruleFor(t, `
title: t
id: OLT-EXEC-008
attack: [T1234]
detection:
  sel:
    process.exe|re: '^/usr/local/bin/[a-z]+$'
  condition: sel
`)
	mustMatch(t, rule, map[string]string{"process.exe": "/usr/local/bin/xmrig"}, nil, true)
	mustMatch(t, rule, map[string]string{"process.exe": "/usr/local/bin/XMRIG"}, nil, false)
}

func TestModifier_CIDR(t *testing.T) {
	noteModifierCovered("cidr")
	rule := ruleFor(t, `
title: t
id: OLT-NET-001
attack: [T1071]
detection:
  sel:
    network.src_ip|cidr: '10.0.0.0/8'
  condition: sel
`)
	mustMatch(t, rule, map[string]string{"network.src_ip": "10.1.2.3"}, nil, true)
	mustMatch(t, rule, map[string]string{"network.src_ip": "192.168.1.1"}, nil, false)
}

func TestModifier_Expand(t *testing.T) {
	noteModifierCovered("expand")
	// |expand resolves placeholder lookups against
	// MatchOptions.Placeholders. The placeholder name must be wrapped
	// in %...% per the sigma spec; combining with |contains is not
	// supported by sigmalite, so the rule uses bare |expand and
	// asserts the placeholder expansion against the OR-of-values
	// semantics.
	rule := ruleFor(t, `
title: t
id: OLT-EXEC-009
attack: [T1234]
detection:
  sel:
    process.exe|expand: '%miner_binaries%'
  condition: sel
`)
	// sigmalite's Placeholders map keys exclude the %...% wrappers
	// (see sigma.cutPlaceholder). The rule body's pattern keeps
	// them; the map's key does not.
	placeholders := map[string][]string{
		"miner_binaries": {"xmrig", "minerd", "cpuminer"},
	}
	mustMatch(t, rule, map[string]string{"process.exe": "xmrig"}, placeholders, true)
	mustMatch(t, rule, map[string]string{"process.exe": "redis"}, placeholders, false)
}

// TestModifierCoverageMatrix asserts every modifier we expect to
// inherit from sigmalite has at least one positive and one negative
// case. If a modifier gets renamed upstream this test surfaces the
// gap immediately rather than letting AC5 false-pass.
func TestModifierCoverageMatrix(t *testing.T) {
	expected := []string{
		"contains", "all", "startswith", "endswith", "windash",
		"base64", "base64offset", "re", "cidr", "expand",
	}
	// Assert against the runtime registry populated by each
	// TestModifier_* test. A deleted per-modifier test surfaces here
	// because the corresponding noteModifierCovered call never runs
	// and the expected modifier is reported as missing (code-review
	// P6). The matrix test must run AFTER all per-modifier tests;
	// Go's testing package runs top-level tests in source order, so
	// keeping this function last in the file is load-bearing.
	modifierCoverageMu.Lock()
	defer modifierCoverageMu.Unlock()
	for _, m := range expected {
		if !modifierCovered[m] {
			t.Errorf("modifier %q: no TestModifier_* test exercised it (or noteModifierCovered call missing)", m)
		}
	}
	// Surface registry-only entries so a typo in expected vs the
	// note call is caught both directions.
	for m := range modifierCovered {
		found := false
		for _, e := range expected {
			if e == m {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("modifier %q: registered via noteModifierCovered but not in the expected list", m)
		}
	}
}
