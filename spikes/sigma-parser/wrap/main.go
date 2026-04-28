// Spike POC for Story 1.2: wrap-existing-parser path using
// github.com/runreveal/sigmalite. Produces a RuleMatch for the matching
// fixture so Story 1.15 inherits the exact return type from
// internal/schema/detection.go.
//
// Throwaway code. The production parser lands in
// internal/decision/rules/parser/ when Story 1.15 wires it.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	sigma "github.com/runreveal/sigmalite"
)

// ruleMatch mirrors the production internal/schema.RuleMatch shape so the
// hand-off into Story 1.15 lands a familiar struct.
type ruleMatch struct {
	RuleID    string   `json:"rule_id"`
	RuleName  string   `json:"rule_name"`
	Severity  string   `json:"severity"`
	MitreTags []string `json:"mitre_tags,omitempty"`
	EventID   string   `json:"event_id"`
}

// oltExtras is the OLT-only metadata pulled from the rule's Extra map after
// sigmalite parses standard SIGMA-HQ fields. severity is OLT's numeric
// override, attack carries MITRE technique IDs.
type oltExtras struct {
	Attack   []string
	Severity int
}

func parseOLTExtras(rule *sigma.Rule) (oltExtras, error) {
	out := oltExtras{}
	if dec, ok := rule.Extra["attack"]; ok && dec != nil {
		var tags []string
		if err := dec.Decode(&tags); err != nil {
			return out, fmt.Errorf("attack: %w", err)
		}
		out.Attack = tags
	}
	if dec, ok := rule.Extra["severity"]; ok && dec != nil {
		var sev int
		if err := dec.Decode(&sev); err != nil {
			return out, fmt.Errorf("severity: %w", err)
		}
		out.Severity = sev
	}
	return out, nil
}

// oltResolver implements sigmalite.FieldResolver. It splits the lookup space
// into two halves: the workload-posture half (k8s.*) backed by a separate
// map, and the streaming-event half (process.*, network.*, etc.) backed by
// the LogEntry.Fields map. This is the binding point the wrap path uses to
// teach sigmalite about OLT's Kubernetes-native field references without
// patching the upstream parser.
type oltResolver struct {
	posture map[string]string
}

func (r *oltResolver) Resolve(field string, entry *sigma.LogEntry) []string {
	if strings.HasPrefix(field, "k8s.") {
		if v, ok := r.posture[field]; ok {
			return []string{v}
		}
		return nil
	}
	if v, ok := entry.Fields[field]; ok {
		return []string{v}
	}
	lower := strings.ToLower(field)
	for k, v := range entry.Fields {
		if strings.ToLower(k) == lower {
			return []string{v}
		}
	}
	return nil
}

// loadFixture reads a flat JSON event map and splits it into the streaming
// event fields (LogEntry.Fields) and the workload posture fields
// (resolver.posture). All values are stringified so sigmalite's
// pattern-matching contract holds against numeric ports and the like.
func loadFixture(path string) (*sigma.LogEntry, map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, err
	}
	entry := &sigma.LogEntry{Fields: map[string]string{}}
	posture := map[string]string{}
	for k, v := range doc {
		s := stringify(v)
		if strings.HasPrefix(k, "k8s.") {
			posture[k] = s
		} else {
			entry.Fields[k] = s
		}
	}
	return entry, posture, nil
}

func stringify(v any) string {
	switch t := v.(type) {
	case string:
		return t
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

func evaluate(rule *sigma.Rule, entry *sigma.LogEntry, posture map[string]string) bool {
	opts := &sigma.MatchOptions{FieldResolver: &oltResolver{posture: posture}}
	return rule.Detection.Matches(entry, opts)
}

type fixture struct {
	Name      string
	Path      string
	WantMatch bool
}

var fixtures = []fixture{
	{Name: "positive", Path: "../testdata/fixtures/positive.json", WantMatch: true},
	{Name: "negative_namespace", Path: "../testdata/fixtures/negative_namespace.json", WantMatch: false},
	{Name: "negative_process", Path: "../testdata/fixtures/negative_process.json", WantMatch: false},
}

func runFixtures(rule *sigma.Rule, extras oltExtras) (int, error) {
	pass := 0
	for _, fx := range fixtures {
		entry, posture, err := loadFixture(fx.Path)
		if err != nil {
			return pass, fmt.Errorf("load %s: %w", fx.Name, err)
		}
		got := evaluate(rule, entry, posture)
		status := "PASS"
		if got != fx.WantMatch {
			status = "FAIL"
		} else {
			pass++
		}
		fmt.Printf("[wrap] %-22s want=%v got=%v %s\n", fx.Name, fx.WantMatch, got, status)
		if got && fx.WantMatch {
			match := ruleMatch{
				RuleID:    rule.ID,
				RuleName:  rule.Title,
				Severity:  strconv.Itoa(extras.Severity),
				MitreTags: extras.Attack,
				EventID:   fx.Name,
			}
			out, _ := json.Marshal(match)
			fmt.Printf("[wrap]   RuleMatch=%s\n", out)
		}
	}
	return pass, nil
}

// runBench performs the AC5 latency rough cut: a 100-iteration warm-up
// followed by 1000 timed evaluations of one fixture against a 10-rule
// corpus. The corpus is the real OLT-IMPACT-005 plus nine id-mutated
// duplicates so the matcher walks the same AST shape ten times per
// iteration.
func runBench(originalYAML []byte) error {
	const warmup, n = 100, 1000

	corpus := make([]*sigma.Rule, 0, 10)
	for i := 0; i < 10; i++ {
		mutated := mutateID(originalYAML, i)
		r, err := sigma.ParseRule(mutated)
		if err != nil {
			return fmt.Errorf("parse mutated rule %d: %w", i, err)
		}
		corpus = append(corpus, r)
	}

	entries := make([]*sigma.LogEntry, len(fixtures))
	postures := make([]map[string]string, len(fixtures))
	for i, fx := range fixtures {
		entry, posture, err := loadFixture(fx.Path)
		if err != nil {
			return err
		}
		entries[i] = entry
		postures[i] = posture
	}

	for i := 0; i < warmup; i++ {
		idx := i % len(fixtures)
		for _, r := range corpus {
			_ = evaluate(r, entries[idx], postures[idx])
		}
	}

	samples := make([]time.Duration, n)
	totalStart := time.Now()
	for i := 0; i < n; i++ {
		idx := i % len(fixtures)
		start := time.Now()
		for _, r := range corpus {
			_ = evaluate(r, entries[idx], postures[idx])
		}
		samples[i] = time.Since(start)
	}
	total := time.Since(totalStart)

	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	median := samples[n/2]
	p99 := samples[n*99/100]
	min := samples[0]
	max := samples[n-1]

	fmt.Printf("[wrap-bench] corpus=%d iterations=%d warmup=%d\n", len(corpus), n, warmup)
	fmt.Printf("[wrap-bench] total=%s min=%s median=%s p99=%s max=%s\n", total, min, median, p99, max)
	return nil
}

// mutateID rewrites the rule's id field so the 10-rule corpus contains
// distinct rules. Using a string replace keeps the mutation cheap and
// avoids re-serialising YAML.
func mutateID(yamlBytes []byte, n int) []byte {
	if n == 0 {
		return yamlBytes
	}
	s := string(yamlBytes)
	out := strings.Replace(s, "id: OLT-IMPACT-005", fmt.Sprintf("id: OLT-IMPACT-%03d", 100+n), 1)
	return []byte(out)
}

func main() {
	bench := flag.Bool("bench", false, "run AC5 performance rough cut after the fixture pass")
	rulePath := flag.String("rule", "../testdata/OLT-IMPACT-005.yaml", "path to the rule YAML (relative to wrap/)")
	flag.Parse()

	abs, err := filepath.Abs(*rulePath)
	if err != nil {
		fail("resolve rule path: %v", err)
	}
	yamlBytes, err := os.ReadFile(abs)
	if err != nil {
		fail("read rule: %v", err)
	}

	rule, err := sigma.ParseRule(yamlBytes)
	if err != nil {
		fail("parse rule: %v", err)
	}
	extras, err := parseOLTExtras(rule)
	if err != nil {
		fail("parse OLT extras: %v", err)
	}
	fmt.Printf("[wrap] parsed rule id=%s title=%q attack=%v severity=%d\n",
		rule.ID, rule.Title, extras.Attack, extras.Severity)

	pass, err := runFixtures(rule, extras)
	if err != nil {
		fail("run fixtures: %v", err)
	}
	fmt.Printf("[wrap] fixtures: %d/%d passed\n", pass, len(fixtures))
	if pass != len(fixtures) {
		os.Exit(1)
	}

	if *bench {
		if err := runBench(yamlBytes); err != nil {
			fail("bench: %v", err)
		}
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[wrap] error: "+format+"\n", args...)
	os.Exit(1)
}
