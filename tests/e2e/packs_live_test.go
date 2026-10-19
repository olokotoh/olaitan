//go:build e2e && live

package e2e_test

// Story 11.2c RESERVED LIVE GATE (Task 11, D8). This is the ONLY place the
// third-party attack packs prove DETECTION, not just wiring. It runs the REAL
// pack runner (internal/eval/attack.PackRunner) against a live Calico+Falco
// cluster and asserts a keyed, time-ordered detection signal per technique.
// It is double-tagged `e2e && live` so it NEVER runs in the default CI gate
// (which is kindnet, no Falco/Calico) and only runs when an operator invokes:
//
//	go test -tags 'e2e live' ./tests/e2e/ -run TestPackLive -v
//
// on the supervised cluster (with 11.2b merged first per D9, so one bring-up
// covers s1-s5 AND both packs). The honesty fence (D7): everything in the
// default CI proves command construction, pins, MITRE citation, and
// revert-always; THIS test is where "the attack really detonated and Olaitan
// really saw it" is established, with evidence.
//
// Attribution (Murat/D8): detection is asserted as a per-run DELTA over a
// snapshot taken immediately before detonation, scoped by the technique's
// expected OLT rule_id when one is wired, plus the correlator evidence-package
// delta; a NEGATIVE CONTROL window first proves the signal is absent without a
// detonation, so a passing delta is this technique's doing and not residue or
// background noise. This mirrors the accepted rigor of assertScenarioSignal
// for s1-s5. Each technique detonates in its OWN per-run namespace (the
// runner's teardown), which is the natural isolation join key and the cheap
// "cluster is clean" assertion.

import (
	"context"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/eval/attack"
)

// packLiveCase is one technique to detonate and the signal it must raise.
type packLiveCase struct {
	pack   attack.PackID
	techID string
	// expectRule is the OLT rule_id expected to match, or "" when no OLT rule
	// is wired yet for this technique - in which case the evidence-package
	// delta (the correlator assembled a real package from the attack) is the
	// detection signal, and the gate run RECORDS that no specific OLT rule
	// fired (Dr. Quinn's expected-signal map: an honest "detected via <organ>,
	// OLT rule is future work", never a silent pass and never a false gap).
	expectRule string
	organ      attack.Organ
}

// packLiveCases is built from the curated pack tables so the gate and the
// unit-tested tables cannot drift. event-generator runs first (the required
// spine, directly pinned and ready); Stratus rows run only once the wrapper
// image is built and its Job manifest committed (renderJob returns an explicit
// deferral until then, and the case is skipped with that message).
func packLiveCases() []packLiveCase {
	var cs []packLiveCase
	for _, tq := range attack.EventGenTechniques() {
		cs = append(cs, packLiveCase{pack: tq.Pack, techID: tq.ID, expectRule: tq.ExpectOLT, organ: tq.Organ})
	}
	for _, tq := range attack.StratusTechniques() {
		if tq.Privileged {
			// hostPath / privileged-pod need a PSA-exempt namespace (D10); the
			// operator enables them explicitly, so they are not in the default
			// gate set.
			continue
		}
		cs = append(cs, packLiveCase{pack: tq.Pack, techID: tq.ID, expectRule: tq.ExpectOLT, organ: tq.Organ})
	}
	return cs
}

// packSignal is the detection snapshot the delta is taken against.
type packSignal struct {
	ruleMatches float64 // matches for the case's expectRule (0 when unscoped)
	evidence    float64 // olaitan_correlator_evidence_packages_total
}

func snapshotPackSignal(t *testing.T, rule string) packSignal {
	t.Helper()
	m := scrapeMetrics(t)
	var rm float64
	if rule != "" {
		rm = m["olaitan_decision_rules_matches_by_attribute_total"].sumWhere(map[string]string{"rule_id": rule})
	}
	return packSignal{
		ruleMatches: rm,
		evidence:    m["olaitan_correlator_evidence_packages_total"].sumWhere(nil),
	}
}

// TestPackLive is the reserved live gate for the attack packs.
func TestPackLive(t *testing.T) {
	requireKindContext(t) // refuse to attack anything but the sanctioned e2e cluster
	// The detection deltas are read from the aggregator's /metrics on
	// localhost:metricsLocalPort; open (and, via t.Cleanup, tear down) that
	// port-forward here like the other e2e harnesses do, so the gate does not
	// depend on an operator's hand-run forward. A listener already on the port
	// (a stale hand-run forward) would answer portForward's readiness dial and
	// hide a forward that failed to bind, so refuse to start over one.
	if conn, err := net.DialTimeout("tcp", "localhost:"+metricsLocalPort, 200*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatalf("localhost:%s is already in use (a stale port-forward?); stop it so the gate opens its own", metricsLocalPort)
	}
	portForward(t, "deploy/"+defaultReleaseName+"-aggregator", metricsLocalPort, "9090")

	packsRoot := filepath.Join(repoRoot(), "deploy", "demo", "packs")
	logger := slog.New(slog.NewTextHandler(logWriter{t}, nil))

	runners := map[attack.PackID]*attack.PackRunner{}
	for _, pack := range []attack.PackID{attack.PackFalcoEventGen, attack.PackStratus} {
		r, err := attack.NewPackRunner(pack, attack.ExecCmd, logger)
		if err != nil {
			t.Fatalf("NewPackRunner(%s): %v", pack, err)
		}
		r.PacksRoot = packsRoot
		runners[pack] = r
	}

	for _, c := range packLiveCases() {
		c := c
		t.Run(string(c.pack)+"/"+c.techID, func(t *testing.T) {
			runner := runners[c.pack]

			// NEGATIVE CONTROL. The signal must be ABSENT without a detonation.
			// Two regimes, because the evidence counter is GLOBAL (labelled only
			// by trigger_type, not namespace) while a rule_id match is scoped
			// (review round 1, Blind/Edge Case Hunter):
			//   - expectRule != "" (keyed): the rule_id is attributable even on a
			//     busy cluster; the negative control asserts it does NOT match in
			//     the quiet window.
			//   - expectRule == "" (unkeyed, evidence-only): evidence is only
			//     attributable if the cluster is QUIET. If the global evidence
			//     counter moves on its own during the quiet window, this test
			//     CANNOT honestly attribute a later rise to the detonation, so it
			//     SKIPS with guidance (wire an OLT rule) rather than claiming a
			//     detection it cannot stand behind.
			base := snapshotPackSignal(t, c.expectRule)
			time.Sleep(negativeControlWindow)
			nc := snapshotPackSignal(t, c.expectRule)
			if c.expectRule != "" && nc.ruleMatches > base.ruleMatches {
				t.Fatalf("negative control FAILED: rule %s matched %v->%v with no detonation; not attributable",
					c.expectRule, base.ruleMatches, nc.ruleMatches)
			}
			if c.expectRule == "" && nc.evidence > base.evidence {
				t.Skipf("environment too noisy for evidence-based attribution of %s (global evidence %v->%v in the quiet window with no detonation); wire an OLT rule (ExpectOLT) to get a scoped, attributable signal",
					c.techID, base.evidence, nc.evidence)
			}

			// DETONATE (real, in its own per-run namespace; the runner tears
			// the namespace down even on failure).
			before := snapshotPackSignal(t, c.expectRule)
			tDet := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), packLiveBudget)
			err := runner.Detonate(ctx, c.techID)
			cancel()
			if err != nil {
				if isDeferredPack(err) {
					t.Skipf("pack technique %s deferred: %v", c.techID, err)
				}
				t.Fatalf("detonate %s: %v", c.techID, err)
			}

			// POLL for the detection delta within budget. The signal is the
			// scoped rule_id delta when keyed, else the evidence delta (valid
			// because the negative control proved the quiet baseline stable).
			deadline := time.Now().Add(packLiveDetectBudget)
			detected := false
			var last packSignal
			for time.Now().Before(deadline) {
				last = snapshotPackSignal(t, c.expectRule)
				if c.expectRule != "" {
					detected = last.ruleMatches > before.ruleMatches
				} else {
					detected = last.evidence > before.evidence
				}
				if detected {
					t.Logf("DETECTED %s via %s after %s: rule %s %v->%v, evidence %v->%v",
						c.techID, c.organ, time.Since(tDet).Round(time.Second),
						c.expectRule, before.ruleMatches, last.ruleMatches, before.evidence, last.evidence)
					if c.expectRule == "" {
						t.Logf("NOTE: no OLT rule keys on %s; attributed via correlator evidence under a proven-quiet negative control (expected-signal map: an OLT rule is future work)", c.techID)
					}
					break
				}
				time.Sleep(packLivePollInterval)
			}
			if !detected {
				t.Errorf("NO detection for %s within %s (rule %s %v->%v, evidence %v->%v); either the technique did not reach its organ (%s) or a rule/plumbing gap exists",
					c.techID, packLiveDetectBudget, c.expectRule, before.ruleMatches, last.ruleMatches, before.evidence, last.evidence, c.organ)
			}

			// CLEANUP VERIFIED: the runner deletes the per-run namespace; prove
			// it is actually gone (the cheap total "cluster is clean" check).
			assertNoPackNamespaceLeak(t)
		})
	}
}

const (
	negativeControlWindow = 20 * time.Second
	packLiveBudget        = 5 * time.Minute
	packLiveDetectBudget  = 120 * time.Second
	packLivePollInterval  = 5 * time.Second
)

// isDeferredPack reports whether err is the explicit "wrapper image not built
// yet" deferral from the pack renderer, so Stratus rows skip cleanly until the
// supervised build step rather than failing the gate.
func isDeferredPack(err error) bool {
	return err != nil && strings.Contains(err.Error(), "deferred")
}

// assertNoPackNamespaceLeak proves no olt-pack-* namespace survives a run.
func assertNoPackNamespaceLeak(t *testing.T) {
	t.Helper()
	out := kubectl(t, "get", "ns", "-o", "name")
	if strings.Contains(out, "olt-pack-") {
		t.Errorf("per-run pack namespace leaked after teardown:\n%s", out)
	}
}
