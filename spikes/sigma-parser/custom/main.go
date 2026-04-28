// Spike POC for Story 1.2: hand-rolled OLT-only parser path. Loads the
// OLT-IMPACT-005 rule, evaluates it against the same three fixtures the
// wrap POC uses, and prints PASS/FAIL. The POC exists to give an honest
// LOC and complexity estimate for AC7's fallback custom-parser plan; it
// is intentionally naive (no parser-combinator framework, no full
// SIGMA-HQ modifier coverage) and operates only on the OLT subset
// needed by OLT-IMPACT-005.
package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type rule struct {
	Title          string         `yaml:"title"`
	ID             string         `yaml:"id"`
	Description    string         `yaml:"description"`
	Status         string         `yaml:"status"`
	Attack         []string       `yaml:"attack"`
	Severity       int            `yaml:"severity"`
	Detection      map[string]any `yaml:"detection"`
	FalsePositives []string       `yaml:"falsepositives"`
	Fields         []string       `yaml:"fields"`
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "[custom] error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	rulePath, _ := filepath.Abs("../testdata/OLT-IMPACT-005.yaml")
	raw, err := os.ReadFile(rulePath)
	if err != nil {
		return fmt.Errorf("read rule: %w", err)
	}
	r := rule{}
	if err := yaml.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("parse rule: %w", err)
	}
	if err := lintID(r.ID); err != nil {
		return fmt.Errorf("rule id: %w", err)
	}
	fmt.Printf("[custom] parsed rule id=%s title=%q attack=%v severity=%d\n",
		r.ID, r.Title, r.Attack, r.Severity)

	fixtures := []struct {
		name      string
		path      string
		wantMatch bool
	}{
		{"positive", "../testdata/fixtures/positive.json", true},
		{"negative_namespace", "../testdata/fixtures/negative_namespace.json", false},
		{"negative_process", "../testdata/fixtures/negative_process.json", false},
	}

	pass := 0
	for _, fx := range fixtures {
		event, err := loadEvent(fx.path)
		if err != nil {
			return fmt.Errorf("load %s: %w", fx.name, err)
		}
		got, err := evaluate(r, event)
		if err != nil {
			return fmt.Errorf("eval %s: %w", fx.name, err)
		}
		status := "PASS"
		if got != fx.wantMatch {
			status = "FAIL"
		} else {
			pass++
		}
		fmt.Printf("[custom] %-22s want=%v got=%v %s\n", fx.name, fx.wantMatch, got, status)
	}
	fmt.Printf("[custom] fixtures: %d/%d passed\n", pass, len(fixtures))
	if pass != len(fixtures) {
		os.Exit(1)
	}
	return nil
}

func loadEvent(path string) (map[string]any, error) {
	abs, _ := filepath.Abs(path)
	raw, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// evaluate walks the detection block. The `condition` key names the
// search-identifier blocks that must each succeed for an AND match.
// Operators other than AND (OR, NOT, parentheses) are out of scope for
// this POC; SIGMA-HQ's full grammar is what argues for the wrap path.
func evaluate(r rule, event map[string]any) (bool, error) {
	condRaw, ok := r.Detection["condition"]
	if !ok {
		return false, fmt.Errorf("detection.condition missing")
	}
	condStr, ok := condRaw.(string)
	if !ok {
		return false, fmt.Errorf("detection.condition must be a string")
	}
	identifiers := parseAndCondition(condStr)
	if len(identifiers) == 0 {
		return false, fmt.Errorf("only flat AND conditions supported in this POC")
	}
	for _, id := range identifiers {
		blockRaw, ok := r.Detection[id]
		if !ok {
			return false, fmt.Errorf("detection.%s missing", id)
		}
		block, ok := blockRaw.(map[string]any)
		if !ok {
			return false, fmt.Errorf("detection.%s must be a map", id)
		}
		matched, err := matchBlock(block, event)
		if err != nil {
			return false, fmt.Errorf("%s: %w", id, err)
		}
		if !matched {
			return false, nil
		}
	}
	return true, nil
}

var identRe = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_.-]*`)

func parseAndCondition(s string) []string {
	tokens := strings.Split(s, " and ")
	if len(tokens) == 0 {
		return nil
	}
	out := make([]string, 0, len(tokens))
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if !identRe.MatchString(t) || strings.ContainsAny(t, " ()|") {
			return nil
		}
		out = append(out, t)
	}
	return out
}

// matchBlock applies a SIGMA-HQ-style block: every `field|modifier`
// entry must match. Patterns may be a single value or a list.
func matchBlock(block map[string]any, event map[string]any) (bool, error) {
	for fieldKey, patternRaw := range block {
		fieldName, modifier := splitFieldModifier(fieldKey)
		patterns, err := patternList(patternRaw)
		if err != nil {
			return false, fmt.Errorf("field %q: %w", fieldKey, err)
		}
		eventValue, ok := lookup(event, fieldName)
		if !ok {
			return false, nil
		}
		if !anyPatternMatches(eventValue, patterns, modifier) {
			return false, nil
		}
	}
	return true, nil
}

func splitFieldModifier(key string) (string, string) {
	if idx := strings.Index(key, "|"); idx >= 0 {
		return key[:idx], key[idx+1:]
	}
	return key, ""
}

func patternList(raw any) ([]string, error) {
	switch v := raw.(type) {
	case string:
		return []string{v}, nil
	case int:
		return []string{strconv.Itoa(v)}, nil
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			out = append(out, stringify(item))
		}
		return out, nil
	default:
		return []string{stringify(v)}, nil
	}
}

func lookup(event map[string]any, field string) (string, bool) {
	v, ok := event[field]
	if !ok {
		return "", false
	}
	return stringify(v), true
}

func anyPatternMatches(eventValue string, patterns []string, modifier string) bool {
	for _, pat := range patterns {
		if patternMatches(eventValue, pat, modifier) {
			return true
		}
	}
	return false
}

func patternMatches(value, pattern, modifier string) bool {
	switch modifier {
	case "":
		return value == pattern
	case "contains":
		return strings.Contains(value, pattern)
	case "startswith":
		return strings.HasPrefix(value, pattern)
	case "endswith":
		return strings.HasSuffix(value, pattern)
	case "re":
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false
		}
		return re.MatchString(value)
	case "cidr":
		prefix, err := netip.ParsePrefix(pattern)
		if err != nil {
			return false
		}
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return false
		}
		return prefix.Contains(addr)
	default:
		return false
	}
}

func stringify(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	case nil:
		return ""
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

var oltIDRegex = regexp.MustCompile(`^OLT-(EXEC|NET|FILE|PRIV|IMPACT|RECON|PERSIST|EXFIL|CRED|LATERAL)-[0-9]{3}$`)

func lintID(id string) error {
	if !oltIDRegex.MatchString(id) {
		return fmt.Errorf("rule id %q does not match %s", id, oltIDRegex.String())
	}
	return nil
}
