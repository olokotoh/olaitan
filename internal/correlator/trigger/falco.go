package trigger

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/olokotoh/olaitan/internal/schema"
)

// Story 10.3: a Falco alert on a real pod starts an investigation by
// itself once it is at or above a priority floor (default "warning",
// decided 2026-09-11). Before this, the only root trigger was multi-signal
// convergence, which needs two sources; the default install runs one, so a
// real attack produced nothing past EVENTS_RAW. Falco is a rules engine,
// so its verdict enters through the existing rule_match path.

// DefaultFalcoTriggerFloor is the priority at and above which a Falco alert
// starts an investigation. "warning" admits 17 of Falco 0.45's 24 default
// rules (3 Critical, 14 Warning) and leaves out Notice rules such as
// "Terminal shell in container", which any kubectl exec trips.
const DefaultFalcoTriggerFloor = "warning"

// falcoPriorityRank orders Falco priorities; higher is more severe.
var falcoPriorityRank = map[string]int{
	"debug": 0, "informational": 1, "notice": 2, "warning": 3,
	"error": 4, "critical": 5, "alert": 6, "emergency": 7,
}

// falcoSeverity maps a Falco priority onto the OLT 0-100 severity scale
// the score calculator reads (total = rule_weight 0.4 * max severity).
// Warning 50 scores 20, the SUSPICIOUS band, on its own; Critical (90 ->
// 36) and even Alert/Emergency (95 -> 38) stay below RESTRICTED (40).
// Escalating further takes the baseline or analyst tiers agreeing, which
// keeps the response graduated. Capped at 95, not 100: 0.4 x 100 is exactly
// the RESTRICTED threshold, so one alert would have jumped two states.
var falcoSeverity = map[string]int{
	"warning": 50, "error": 75, "critical": 90, "alert": 95, "emergency": 95,
}

var mitreTechnique = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

// ValidateFalcoTriggerFloor accepts "" (the default), "off", or a priority
// from warning upward. A lower floor is refused: Notice rules fire on a
// plain `kubectl exec`, so every operator shell would open an investigation.
func ValidateFalcoTriggerFloor(floor string) error {
	f := strings.ToLower(strings.TrimSpace(floor))
	if f == "" || f == "off" {
		return nil
	}
	if _, ok := falcoSeverity[f]; ok {
		return nil
	}
	return fmt.Errorf("falco trigger floor %q: want off, warning, error, critical, alert or emergency", floor)
}

// FalcoRuleMatch returns the rule match a Falco alert contributes, and
// whether it should start an investigation under floor ("" means
// DefaultFalcoTriggerFloor, "off" disables). It never fires for host
// events (no pod), for Falco's own internal events, or for anything that
// is not a Falco alert with a known priority.
func FalcoRuleMatch(ev schema.Event, floor string) (schema.RuleMatch, bool) {
	if ev.Source != schema.SourceFalco || ev.Pod.Namespace == "" || ev.Pod.Name == "" {
		return schema.RuleMatch{}, false
	}
	f := strings.ToLower(strings.TrimSpace(floor))
	if f == "" {
		f = DefaultFalcoTriggerFloor
	}
	floorRank, ok := falcoPriorityRank[f]
	if !ok || f == "off" {
		return schema.RuleMatch{}, false
	}
	var raw struct {
		Rule     string   `json:"rule"`
		Priority string   `json:"priority"`
		Tags     []string `json:"tags"`
		Source   string   `json:"source"`
	}
	if err := json.Unmarshal(ev.Raw, &raw); err != nil || raw.Rule == "" {
		return schema.RuleMatch{}, false
	}
	if raw.Source == "internal" {
		return schema.RuleMatch{}, false
	}
	prio := strings.ToLower(raw.Priority)
	rank, known := falcoPriorityRank[prio]
	if !known || rank < floorRank {
		return schema.RuleMatch{}, false
	}
	sev, ok := falcoSeverity[prio]
	if !ok {
		return schema.RuleMatch{}, false
	}
	var mitre []string
	for _, tag := range raw.Tags {
		if mitreTechnique.MatchString(tag) {
			mitre = append(mitre, tag)
		}
	}
	return schema.RuleMatch{
		RuleID:    "falco:" + raw.Rule,
		RuleName:  raw.Rule,
		Severity:  strconv.Itoa(sev),
		MitreTags: mitre,
		EventID:   ev.ID,
	}, true
}
