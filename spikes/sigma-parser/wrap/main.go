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
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	sigma "github.com/runreveal/sigmalite"
)

// sourceDir resolves to the directory containing this file. Anchoring
// relative paths against it lets `go run .` from inside wrap/ and
// `go run ./spikes/sigma-parser/wrap` from repo root behave identically.
func sourceDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Dir(file)
}

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
// sigmalite parses standard SIGMA-HQ fields. Severity is the resolved
// numeric severity (explicit OLT field, else the level-table fallback per
// docs/sigma-extensions.md §8). HasSeverity records whether the rule
// declared severity explicitly so callers can distinguish 0-the-default
// from 0-the-explicit-floor.
type oltExtras struct {
	Attack      []string
	Severity    int
	HasSeverity bool
}

// attackIDRegex matches base techniques (Tdddd) and sub-techniques
// (Tdddd.ddd). Source: docs/sigma-extensions.md §4.
var attackIDRegex = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)

// levelToSeverity maps SIGMA-HQ's level: strings to OLT severities per
// docs/sigma-extensions.md §8. The default (no severity, no level) is
// treated as level: medium → 50.
var levelToSeverity = map[string]int{
	"informational": 10,
	"low":           30,
	"medium":        50,
	"high":          75,
	"critical":      90,
}

func parseOLTExtras(rule *sigma.Rule) (oltExtras, error) {
	out := oltExtras{Severity: 50}

	dec, ok := rule.Extra["attack"]
	if !ok {
		return out, fmt.Errorf("attack: required field is missing")
	}
	if dec == nil {
		return out, fmt.Errorf("attack: must be a non-empty list")
	}
	var tags []string
	if err := dec.Decode(&tags); err != nil {
		return out, fmt.Errorf("attack: must be a non-empty list (decode error: %w)", err)
	}
	if len(tags) == 0 {
		return out, fmt.Errorf("attack: must be a non-empty list")
	}
	for _, id := range tags {
		if !attackIDRegex.MatchString(id) {
			return out, fmt.Errorf("attack: %q does not match %s", id, attackIDRegex.String())
		}
	}
	out.Attack = tags

	if dec, ok := rule.Extra["severity"]; ok {
		if dec == nil {
			return out, fmt.Errorf("severity: explicit null is not permitted; omit the key to use the level fallback, or supply an integer 0-100")
		}
		var probe any
		if err := dec.Decode(&probe); err != nil {
			return out, fmt.Errorf("severity: %w", err)
		}
		if probe == nil {
			return out, fmt.Errorf("severity: explicit null is not permitted; omit the key to use the level fallback, or supply an integer 0-100")
		}
		var sev int
		if err := dec.Decode(&sev); err != nil {
			return out, fmt.Errorf("severity: %w", err)
		}
		if sev < 0 || sev > 100 {
			return out, fmt.Errorf("severity: %d is outside [0, 100]", sev)
		}
		out.Severity = sev
		out.HasSeverity = true
	} else if rule.Level != "" {
		level := string(rule.Level)
		if mapped, found := levelToSeverity[level]; found {
			out.Severity = mapped
		} else {
			return out, fmt.Errorf("level: %q is not a SIGMA-HQ level (informational, low, medium, high, critical)", level)
		}
	}

	return out, nil
}

// severityString renders the resolved severity for the RuleMatch JSON.
// The struct contract holds a string so the field is forward-compatible
// with future severity grammars; today it is always the resolved int.
func severityString(extras oltExtras) string {
	return strconv.Itoa(extras.Severity)
}

// oltResolver implements sigmalite.FieldResolver. It splits the lookup
// space into two halves: the workload-posture half (k8s.*) backed by a
// separate map, and the streaming-event half (process.*, network.*,
// etc.) backed by lowered-key indices built once at fixture load.
// Field-name lookups are case-insensitive and deterministic; the
// case-fold scan that previously walked the event map per call is
// replaced with O(1) lookups against pre-lowered keys.
type oltResolver struct {
	posture map[string]string // already lowered keys
	fields  map[string]string // already lowered keys, mirrors entry.Fields
}

func (r *oltResolver) Resolve(field string, entry *sigma.LogEntry) []string {
	lower := strings.ToLower(field)
	if strings.HasPrefix(lower, "k8s.") {
		if v, ok := r.posture[lower]; ok {
			return []string{v}
		}
		return nil
	}
	if v, ok := r.fields[lower]; ok {
		return []string{v}
	}
	return nil
}

// loadFixture reads a flat JSON event map and splits it into the streaming
// event fields (LogEntry.Fields, preserved for sigmalite's bookkeeping)
// and a paired oltResolver carrying the lowered-key indices the resolver
// uses at evaluation time. All values are stringified so sigmalite's
// pattern-matching contract holds against numeric ports and the like.
// If two source keys collide on case (e.g. `Image` and `image`), the
// fixture is rejected: case-collisions are silent footguns and the
// dialect spec uses lowercase exclusively.
func loadFixture(path string) (*sigma.LogEntry, *oltResolver, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, err
	}
	entry := &sigma.LogEntry{Fields: map[string]string{}}
	resolver := &oltResolver{
		posture: map[string]string{},
		fields:  map[string]string{},
	}
	for k, v := range doc {
		lower := strings.ToLower(k)
		s := stringify(v)
		if strings.HasPrefix(lower, "k8s.") {
			if _, dup := resolver.posture[lower]; dup {
				return nil, nil, fmt.Errorf("posture key %q collides on case", k)
			}
			resolver.posture[lower] = s
		} else {
			if _, dup := resolver.fields[lower]; dup {
				return nil, nil, fmt.Errorf("event key %q collides on case", k)
			}
			resolver.fields[lower] = s
			entry.Fields[k] = s
		}
	}
	return entry, resolver, nil
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

// evaluate runs the rule's detection against a pre-built MatchOptions.
// The opts pointer is built once at fixture load (see buildOpts) and
// reused for the lifetime of the run so the AC5 numbers measure rule
// evaluation rather than per-call MatchOptions allocation. The ADR's
// Performance section makes this hoisting claim explicitly; if you
// change the signature you must also update that claim.
func evaluate(rule *sigma.Rule, entry *sigma.LogEntry, opts *sigma.MatchOptions) bool {
	return rule.Detection.Matches(entry, opts)
}

func buildOpts(resolver *oltResolver) *sigma.MatchOptions {
	return &sigma.MatchOptions{FieldResolver: resolver}
}

type fixture struct {
	Name      string
	Path      string
	WantMatch bool
}

var fixtures = []fixture{
	{Name: "positive", Path: filepath.Join(sourceDir(), "..", "testdata", "fixtures", "positive.json"), WantMatch: true},
	{Name: "negative_namespace", Path: filepath.Join(sourceDir(), "..", "testdata", "fixtures", "negative_namespace.json"), WantMatch: false},
	{Name: "negative_process", Path: filepath.Join(sourceDir(), "..", "testdata", "fixtures", "negative_process.json"), WantMatch: false},
	{Name: "negative_missing_process", Path: filepath.Join(sourceDir(), "..", "testdata", "fixtures", "negative_missing_process.json"), WantMatch: false},
}

// buildRuleMatch constructs the production-shaped RuleMatch for a
// matching fixture. Extracted so the test layer can assert the same
// byte-for-byte JSON contract the runtime path emits, rather than
// fabricating a struct in-test.
func buildRuleMatch(rule *sigma.Rule, extras oltExtras, fixtureName string) ruleMatch {
	return ruleMatch{
		RuleID:    rule.ID,
		RuleName:  rule.Title,
		Severity:  severityString(extras),
		MitreTags: extras.Attack,
		EventID:   fixtureName,
	}
}

func runFixtures(rule *sigma.Rule, extras oltExtras) (int, error) {
	pass := 0
	for _, fx := range fixtures {
		entry, resolver, err := loadFixture(fx.Path)
		if err != nil {
			return pass, fmt.Errorf("load %s: %w", fx.Name, err)
		}
		got := evaluate(rule, entry, buildOpts(resolver))
		status := "PASS"
		if got != fx.WantMatch {
			status = "FAIL"
		} else {
			pass++
		}
		fmt.Printf("[wrap] %-22s want=%v got=%v %s\n", fx.Name, fx.WantMatch, got, status)
		if got && fx.WantMatch {
			match := buildRuleMatch(rule, extras, fx.Name)
			out, _ := json.Marshal(match)
			fmt.Printf("[wrap]   RuleMatch=%s\n", out)
		}
	}
	return pass, nil
}

// runBench performs the AC5 latency rough cut: a 100-iteration warm-up
// followed by 1000 timed evaluations of each fixture against a 10-rule
// corpus. The corpus is the real OLT-IMPACT-005 plus nine id-mutated
// duplicates so the matcher walks the same AST shape ten times per
// iteration. Each fixture is timed separately because match-path and
// short-circuit-miss-path latencies are qualitatively different and
// conflating them into one distribution misleads the ADR consumer.
func runBench(originalYAML []byte) error {
	const warmup, n = 100, 1000

	corpus, err := buildCorpus(originalYAML)
	if err != nil {
		return err
	}

	type loaded struct {
		entry *sigma.LogEntry
		opts  *sigma.MatchOptions
	}
	loadedFixtures := make([]loaded, len(fixtures))
	for i, fx := range fixtures {
		entry, resolver, err := loadFixture(fx.Path)
		if err != nil {
			return err
		}
		loadedFixtures[i] = loaded{entry: entry, opts: buildOpts(resolver)}
	}

	for i := 0; i < warmup; i++ {
		idx := i % len(fixtures)
		for _, r := range corpus {
			_ = evaluate(r, loadedFixtures[idx].entry, loadedFixtures[idx].opts)
		}
	}

	fmt.Printf("[wrap-bench] corpus=%d iterations=%d warmup=%d\n", len(corpus), n, warmup)
	for i, fx := range fixtures {
		samples := make([]time.Duration, n)
		totalStart := time.Now()
		for j := 0; j < n; j++ {
			start := time.Now()
			for _, r := range corpus {
				_ = evaluate(r, loadedFixtures[i].entry, loadedFixtures[i].opts)
			}
			samples[j] = time.Since(start)
		}
		total := time.Since(totalStart)

		sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
		median := samples[(n-1)/2]
		p99 := samples[(n-1)*99/100]
		min := samples[0]
		max := samples[n-1]

		fmt.Printf("[wrap-bench] %-22s total=%s min=%s median=%s p99=%s max=%s\n",
			fx.Name, total, min, median, p99, max)
	}
	return nil
}

// buildCorpus produces 10 distinct rules from a single source YAML by
// rewriting the id field. Fails loudly if mutation produced any
// duplicate IDs so the AC5 numbers cannot silently degenerate to a
// 1-rule corpus measured ten times.
func buildCorpus(originalYAML []byte) ([]*sigma.Rule, error) {
	const corpusSize = 10
	corpus := make([]*sigma.Rule, 0, corpusSize)
	seen := make(map[string]struct{}, corpusSize)
	for i := 0; i < corpusSize; i++ {
		mutated, err := mutateID(originalYAML, i)
		if err != nil {
			return nil, fmt.Errorf("mutate rule %d: %w", i, err)
		}
		r, err := sigma.ParseRule(mutated)
		if err != nil {
			return nil, fmt.Errorf("parse mutated rule %d: %w", i, err)
		}
		if _, dup := seen[r.ID]; dup {
			return nil, fmt.Errorf("mutateID produced duplicate id %q at index %d", r.ID, i)
		}
		seen[r.ID] = struct{}{}
		corpus = append(corpus, r)
	}
	return corpus, nil
}

// mutateID rewrites the rule's id field so the 10-rule corpus contains
// distinct rules. Returns an error if the literal anchor is missing
// (silent no-op would let the corpus degenerate to ten copies of the
// same rule, which the bench would happily measure).
func mutateID(yamlBytes []byte, n int) ([]byte, error) {
	const anchor = "id: OLT-IMPACT-005"
	if n == 0 {
		return yamlBytes, nil
	}
	s := string(yamlBytes)
	if !strings.Contains(s, anchor) {
		return nil, fmt.Errorf("anchor %q not found in rule YAML; mutation cannot produce a distinct id", anchor)
	}
	out := strings.Replace(s, anchor, fmt.Sprintf("id: OLT-IMPACT-%03d", 100+n), 1)
	return []byte(out), nil
}

func main() {
	bench := flag.Bool("bench", false, "run AC5 performance rough cut after the fixture pass")
	rulePath := flag.String("rule", filepath.Join(sourceDir(), "..", "testdata", "OLT-IMPACT-005.yaml"), "path to the rule YAML (defaults to the spike's testdata)")
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
