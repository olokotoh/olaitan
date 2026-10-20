package correlator

import (
	"context"
	"errors"

	corev1 "k8s.io/api/core/v1"

	"github.com/olokotoh/olaitan/internal/correlator/trigger"
	"github.com/olokotoh/olaitan/internal/correlator/window"
	"github.com/olokotoh/olaitan/internal/schema"
)

// EventRuleEvaluator evaluates the OLT rule corpus against ONE event (Story
// 1.15's per-event path, realised by Story 11.2b). The rules engine
// implements it; the correlator calls it for an event that joined a window
// which had already fired, because under the Story 1.14 D1 rising edge such an
// event never reaches a published package and so never reaches a rule.
//
// NoteEmitted is called once per match the correlator actually published, so
// the engine's per-rule match counter counts this path like its own.
type EventRuleEvaluator interface {
	EvaluateEvent(posture *schema.WorkloadPosture, ev schema.Event) []schema.RuleMatch
	NoteEmitted(m schema.RuleMatch)
}

type evaluatorHolder struct{ e EventRuleEvaluator }

// SetEventRuleEvaluator wires the per-event rule path. nil turns it off.
// Wire it before Run (the rules engine is built after the correlator, since
// the engine emits through the correlator).
func (c *Correlator) SetEventRuleEvaluator(e EventRuleEvaluator) {
	if e == nil {
		c.evaluator.Store(nil)
		return
	}
	c.evaluator.Store(&evaluatorHolder{e: e})
}

func (c *Correlator) eventEvaluator() EventRuleEvaluator {
	if h := c.evaluator.Load(); h != nil {
		return h.e
	}
	return nil
}

// identityPosture is the posture the per-event path evaluates against: the
// resolved identity only. The corpus reads k8s.pod.namespace and
// k8s.workload.owner_kind, both identity fields; the published package
// carries the full posture from the assembler as usual.
func identityPosture(identity schema.WorkloadIdentity) *schema.WorkloadPosture {
	return &schema.WorkloadPosture{Identity: identity}
}

// preclaimSnapshotRules records, for a snapshot the rules engine is about to
// evaluate, every OLT rule it will match, so the per-event path does not
// publish a second package for the same (workload, rule) in this window.
func (c *Correlator) preclaimSnapshotRules(workloadID string, identity schema.WorkloadIdentity, snap window.Snapshot) {
	ev := c.eventEvaluator()
	if ev == nil {
		return
	}
	p := identityPosture(identity)
	for i := range snap.Events {
		for _, m := range ev.EvaluateEvent(p, snap.Events[i]) {
			c.claimIn(&c.ruleFired, workloadID, m.RuleID)
		}
	}
}

// fireLateEventRules evaluates one late event and publishes ONE rule_match
// package per newly matched (workload, rule) in this window. The package holds
// only this event (no snapshot re-publish), so the baseline and the analyst
// chain never re-score events they already saw. The trigger carries
// Origin=late_event so its MTTD is measurable on its own.
func (c *Correlator) fireLateEventRules(ctx context.Context, workloadID string, identity schema.WorkloadIdentity, pod *corev1.Pod, ev schema.Event) (*schema.EvidencePackage, error) {
	eval := c.eventEvaluator()
	if eval == nil {
		return nil, nil
	}
	matches := eval.EvaluateEvent(identityPosture(identity), ev)
	if len(matches) == 0 {
		return nil, nil
	}
	snap := window.Snapshot{WorkloadID: workloadID, Events: []schema.Event{ev}, Start: ev.Timestamp, End: ev.Timestamp}
	var (
		first *schema.EvidencePackage
		errs  []error
	)
	for _, m := range matches {
		if !c.claimIn(&c.ruleFired, workloadID, m.RuleID) {
			continue
		}
		tr := trigger.RuleMatch(workloadID, m, c.clock().UTC())
		tr.Origin = schema.TriggerOriginLateEvent
		tr.ResolvedIdentity = &identity
		tr.Pod = pod
		pkg, err := c.publishTrigger(ctx, tr, snap)
		if err != nil {
			// Release the claim so the next matching event can retry.
			c.ruleFired.Delete(workloadID + "\x00" + m.RuleID)
			errs = append(errs, err)
			continue
		}
		if pkg == nil {
			continue // size-cap skip, logged by publishTrigger
		}
		eval.NoteEmitted(m)
		if c.metrics.lateEventRulePackages != nil {
			c.metrics.lateEventRulePackages.WithLabelValues(m.RuleID).Inc()
		}
		if first == nil {
			first = pkg
		}
	}
	return first, errors.Join(errs...)
}
