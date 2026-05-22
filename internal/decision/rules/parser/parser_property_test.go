package parser

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// validAttackGen yields strings that match attackIDRegex by
// construction (base techniques and sub-techniques). The shrinker is
// unimportant here because the property is "every valid form is
// accepted"; failure on a generated value indicates a real parser
// regression, not a generator artefact.
func validAttackGen() gopter.Gen {
	return gen.OneGenOf(
		gen.IntRange(1000, 9999).Map(func(n int) string {
			return fmt.Sprintf("T%04d", n)
		}),
		gen.Const(0).FlatMap(func(_ interface{}) gopter.Gen {
			return gopter.CombineGens(gen.IntRange(1000, 9999), gen.IntRange(0, 999)).Map(func(values []interface{}) string {
				return fmt.Sprintf("T%04d.%03d", values[0].(int), values[1].(int))
			})
		}, reflectStringType()),
	)
}

// invalidAttackGen yields strings that the regex MUST reject.
func invalidAttackGen() gopter.Gen {
	return gen.OneConstOf("T12", "T12345", "T1234.12", "T1234.1234", "X1234", "t1234", "", " T1234", "T1234 ")
}

// validSeverityGen yields integers in [0, 100].
func validSeverityGen() gopter.Gen {
	return gen.IntRange(0, 100)
}

// outOfRangeSeverityGen yields integers outside [0, 100] (we keep the
// range tight so the parser's bounded-int error path is exercised
// without the YAML decoder overflowing).
func outOfRangeSeverityGen() gopter.Gen {
	return gen.OneGenOf(
		gen.IntRange(-50, -1),
		gen.IntRange(101, 150),
	)
}

// validRuleIDGen yields IDs that match RuleIDRegex.
func validRuleIDGen() gopter.Gen {
	categories := []interface{}{"EXEC", "NET", "FILE", "PRIV", "IMPACT", "RECON", "PERSIST", "EXFIL", "CRED", "LATERAL"}
	return gopter.CombineGens(
		gen.OneConstOf(categories...),
		gen.IntRange(0, 999),
	).Map(func(values []interface{}) string {
		return fmt.Sprintf("OLT-%s-%03d", values[0].(string), values[1].(int))
	})
}

// invalidRuleIDGen yields IDs the parser MUST reject.
func invalidRuleIDGen() gopter.Gen {
	return gen.OneConstOf("OLT-EXEC-1", "OLT-EXEC-1000", "olt-exec-001", "OLT-OTHER-001", "SIGMA-EXEC-001", "")
}

// reflectStringType is a small helper because gopter.CombineGens does
// not export the equivalent for the FlatMap target type.
func reflectStringType() reflect.Type { return reflect.TypeOf("") }

// TestProperty_ValidAttackTokensAccepted asserts every regex-passing
// token is accepted by parser.ParseRule.
func TestProperty_ValidAttackTokensAccepted(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 200
	props := gopter.NewProperties(params)

	props.Property("valid ATT&CK token accepted", prop.ForAll(
		func(tok string) bool {
			ruleYAML := fmt.Sprintf("title: t\nid: OLT-EXEC-001\nattack:\n  - %s\ndetection:\n  sel:\n    a: b\n  condition: sel\n", tok)
			_, err := ParseRule([]byte(ruleYAML))
			return err == nil
		},
		validAttackGen(),
	))
	props.TestingRun(t)
}

// TestProperty_InvalidAttackTokensRejected asserts every regex-
// failing token is rejected with the expected error shape.
func TestProperty_InvalidAttackTokensRejected(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	props := gopter.NewProperties(params)

	props.Property("invalid ATT&CK token rejected", prop.ForAll(
		func(tok string) bool {
			ruleYAML := fmt.Sprintf("title: t\nid: OLT-EXEC-001\nattack:\n  - %q\ndetection:\n  sel:\n    a: b\n  condition: sel\n", tok)
			_, err := ParseRule([]byte(ruleYAML))
			if err == nil {
				return false
			}
			return strings.Contains(err.Error(), "attack:")
		},
		invalidAttackGen(),
	))
	props.TestingRun(t)
}

// TestProperty_InRangeSeverityAccepted asserts every severity in
// [0, 100] is accepted and round-trips through Rule.Severity.
func TestProperty_InRangeSeverityAccepted(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 200
	props := gopter.NewProperties(params)

	props.Property("in-range severity accepted", prop.ForAll(
		func(sev int) bool {
			ruleYAML := fmt.Sprintf("title: t\nid: OLT-EXEC-001\nattack:\n  - T1234\nseverity: %d\ndetection:\n  sel:\n    a: b\n  condition: sel\n", sev)
			r, err := ParseRule([]byte(ruleYAML))
			if err != nil {
				return false
			}
			return r.Severity == sev && r.HasSeverity
		},
		validSeverityGen(),
	))
	props.TestingRun(t)
}

// TestProperty_OutOfRangeSeverityRejected asserts severities outside
// [0, 100] surface a single-line error mentioning the offending int.
func TestProperty_OutOfRangeSeverityRejected(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	props := gopter.NewProperties(params)

	props.Property("out-of-range severity rejected", prop.ForAll(
		func(sev int) bool {
			ruleYAML := fmt.Sprintf("title: t\nid: OLT-EXEC-001\nattack:\n  - T1234\nseverity: %d\ndetection:\n  sel:\n    a: b\n  condition: sel\n", sev)
			_, err := ParseRule([]byte(ruleYAML))
			if err == nil {
				return false
			}
			return strings.Contains(err.Error(), "severity:") && strings.Contains(err.Error(), "outside [0, 100]")
		},
		outOfRangeSeverityGen(),
	))
	props.TestingRun(t)
}

// TestProperty_ValidRuleIDsAccepted asserts every regex-matching ID
// is accepted at parse time.
func TestProperty_ValidRuleIDsAccepted(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 200
	props := gopter.NewProperties(params)

	props.Property("valid OLT rule ID accepted", prop.ForAll(
		func(id string) bool {
			ruleYAML := fmt.Sprintf("title: t\nid: %s\nattack:\n  - T1234\ndetection:\n  sel:\n    a: b\n  condition: sel\n", id)
			_, err := ParseRule([]byte(ruleYAML))
			return err == nil
		},
		validRuleIDGen(),
	))
	props.TestingRun(t)
}

// TestProperty_InvalidRuleIDsRejected asserts every regex-failing ID
// is rejected with the expected error shape.
func TestProperty_InvalidRuleIDsRejected(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 100
	props := gopter.NewProperties(params)

	props.Property("invalid OLT rule ID rejected", prop.ForAll(
		func(id string) bool {
			ruleYAML := fmt.Sprintf("title: t\nid: %s\nattack:\n  - T1234\ndetection:\n  sel:\n    a: b\n  condition: sel\n", id)
			_, err := ParseRule([]byte(ruleYAML))
			if err == nil {
				return false
			}
			return strings.Contains(err.Error(), "id:") && strings.Contains(err.Error(), "does not match")
		},
		invalidRuleIDGen(),
	))
	props.TestingRun(t)
}
