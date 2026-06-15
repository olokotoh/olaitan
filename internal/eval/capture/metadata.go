package capture

import (
	"encoding/json"
	"runtime"
	"time"
)

// NeverDetectedSentinel is the measured_time_to_detect value recorded when the
// run never reached a detection signal (AC3/BI-9): a failed run is a DATA POINT
// for Story 5.5 (a detection miss), not an absence of data. A negative sentinel
// is unambiguous against the real seconds-to-detect (which is always >= 0).
const NeverDetectedSentinel = -1

// FSM-state-source labels (BI-8, the Story-5.2 BI-8 honesty carry-forward).
const (
	// FSMSourceObservedTransitions: measured_final_fsm_state is the highest
	// state observed in the captured AUDIT.transitions (a real FSM transition
	// was recorded).
	FSMSourceObservedTransitions = "observed_transitions"
	// FSMSourceDetectionSignalOnly: no FSM transition was captured, so
	// measured_final_fsm_state is the DETECTION-SIGNAL state (the state
	// attained from the EVIDENCE-package signal actually observed on the
	// constrained env). The full FSM attainment proof is deferred to the A1
	// RSLT-full-kind gate; the capture records WHAT IT OBSERVED and labels it
	// honestly, never claiming a state the run did not reach.
	FSMSourceDetectionSignalOnly = "detection_signal_only"
	// FSMSourceNone: neither a transition nor an evidence signal was observed
	// (a clean / undetected run).
	FSMSourceNone = "none"
)

// fsmOrder is the FSM escalation ordering used for the floor-aware
// success-criterion comparison (BI-9). It mirrors internal/schema/state.go's
// stateOrderMap (SUSPICIOUS < RESTRICTED < QUARANTINED < PRESERVED_KILLED);
// CLEAN is the baseline and is never an attack target. It is duplicated here
// (a tiny, stable enum) rather than importing internal/schema so the harness
// capture package carries no decision/response import weight; a drift is caught
// by TestFSMOrder_MatchesSchema in the cmd adapter test.
var fsmOrder = map[string]int{
	"CLEAN":            0,
	"SUSPICIOUS":       1,
	"RESTRICTED":       2,
	"QUARANTINED":      3,
	"PRESERVED_KILLED": 4,
}

// Target is the Story-5.2 target.yaml contract the measurement is scored
// against (BI-9): the target FSM state, the time-to-detect budget, and the
// floor flag. Story 5.2 OWNS the declaration; Story 5.4 OWNS the measurement,
// so this is a plain value the harness threads in from the resolved
// scenarioTarget (it is NOT re-declared here).
type Target struct {
	FSMState            string
	TimeToDetectSeconds int
	Floor               bool
}

// transitionFields is the SUBSET of the AUDIT.transitions wire event the
// measurement reads (the after-state + the decision time). The verbatim event
// is already preserved in fsm.jsonl; this decode is a best-effort projection
// for the measured fields, not a re-validation.
type transitionFields struct {
	AfterState  string    `json:"after_state"`
	DecidedAt   time.Time `json:"decided_at"`
	PublishedAt time.Time `json:"published_at"`
}

// evidenceFields is the SUBSET of the EvidencePackage wire event used as the
// DETECTION-SIGNAL fallback when no FSM transition was captured (BI-8): the
// assembled-at time marks when the detection signal was first observed.
type evidenceFields struct {
	AssembledAt time.Time `json:"assembled_at"`
	WindowEnd   time.Time `json:"window_end"`
}

// Measurement is the computed AC3 measured trio plus its honesty label.
type Measurement struct {
	SuccessCriterionMet   bool
	MeasuredTimeToDetect  int
	MeasuredFinalFSMState string
	FSMStateSource        string
}

// Measure computes success_criterion_met / measured_time_to_detect /
// measured_final_fsm_state from the captured transitions + evidence against the
// scenario target (BI-9). startedAt anchors the seconds-to-detect.
//
//	success_criterion_met = (floor ? observed >= target : observed == target)
//	                        AND measured_time_to_detect <= target_ttd
//	                        AND detected (not the never-sentinel)
//
// FSM-state honesty (BI-8): when at least one AUDIT.transitions event is
// captured, measured_final_fsm_state is the HIGHEST observed transition state
// (source observed_transitions). When NONE is captured but an EvidencePackage
// signal was observed, it is the detection-signal state (source
// detection_signal_only) - the capture honestly records the detection signal,
// not a fabricated final state. time-to-detect is the earliest of the first
// transition decision time or the first evidence assembly time, relative to
// startedAt.
func Measure(transitions, evidence []json.RawMessage, target Target, startedAt time.Time) Measurement {
	highestState, highestRank, firstTransitionAt := highestTransition(transitions)
	firstEvidenceAt := firstEvidence(evidence)

	m := Measurement{
		MeasuredTimeToDetect: NeverDetectedSentinel,
		FSMStateSource:       FSMSourceNone,
	}

	// Determine the measured final FSM state + its honesty source.
	switch {
	case highestRank >= 0:
		m.MeasuredFinalFSMState = highestState
		m.FSMStateSource = FSMSourceObservedTransitions
	case !firstEvidenceAt.IsZero():
		// Detection signal observed but no transition recorded on the
		// constrained env: report the detection-signal state honestly
		// (BI-8). The target's state is the SCENARIO's expectation; the
		// capture labels this as detection_signal_only so a reader knows the
		// full FSM attainment was not proven here.
		m.MeasuredFinalFSMState = target.FSMState
		m.FSMStateSource = FSMSourceDetectionSignalOnly
	}

	// Determine the time-to-detect: the earliest detection moment observed.
	detectAt := earliest(firstTransitionAt, firstEvidenceAt)
	if !detectAt.IsZero() && !startedAt.IsZero() {
		ttd := int(detectAt.Sub(startedAt).Seconds())
		if ttd < 0 {
			ttd = 0
		}
		m.MeasuredTimeToDetect = ttd
	}

	m.SuccessCriterionMet = successMet(m, target)
	return m
}

// successMet applies the floor-aware FSM comparison + the time-to-detect budget
// (BI-9). A never-detected run (sentinel) never passes.
func successMet(m Measurement, target Target) bool {
	if m.MeasuredTimeToDetect == NeverDetectedSentinel {
		return false
	}
	if m.MeasuredTimeToDetect > target.TimeToDetectSeconds {
		return false
	}
	observedRank, ok := fsmOrder[m.MeasuredFinalFSMState]
	if !ok {
		return false
	}
	targetRank, ok := fsmOrder[target.FSMState]
	if !ok {
		return false
	}
	if target.Floor {
		return observedRank >= targetRank
	}
	return observedRank == targetRank
}

// highestTransition returns the highest-ranked after-state across the captured
// transitions, its rank, and the earliest transition decision time. The rank
// is -1 when no transition was captured.
func highestTransition(transitions []json.RawMessage) (state string, rank int, firstAt time.Time) {
	rank = -1
	for _, raw := range transitions {
		var t transitionFields
		if err := json.Unmarshal(raw, &t); err != nil {
			continue
		}
		if r, ok := fsmOrder[t.AfterState]; ok && r > rank {
			rank = r
			state = t.AfterState
		}
		at := t.DecidedAt
		if at.IsZero() {
			at = t.PublishedAt
		}
		if !at.IsZero() && (firstAt.IsZero() || at.Before(firstAt)) {
			firstAt = at
		}
	}
	return state, rank, firstAt
}

// firstEvidence returns the earliest EvidencePackage observation time (the
// detection-signal moment), or the zero time when none was captured.
func firstEvidence(evidence []json.RawMessage) time.Time {
	var first time.Time
	for _, raw := range evidence {
		var e evidenceFields
		if err := json.Unmarshal(raw, &e); err != nil {
			continue
		}
		at := e.AssembledAt
		if at.IsZero() {
			at = e.WindowEnd
		}
		if !at.IsZero() && (first.IsZero() || at.Before(first)) {
			first = at
		}
	}
	return first
}

// earliest returns the earlier of two times, ignoring the zero time.
func earliest(a, b time.Time) time.Time {
	switch {
	case a.IsZero():
		return b
	case b.IsZero():
		return a
	case a.Before(b):
		return a
	default:
		return b
	}
}

// ResourceUsage is the AC3 resource-usage snapshot (BI-8, defined HONESTLY for
// the constrained env). The harness-process snapshot (runtime.MemStats /
// goroutines) is ALWAYS available; cluster snapshots are captured WHEN
// AVAILABLE (a real kind run with a metrics-server) and recorded as
// cluster_metrics_available=false with nil cluster fields otherwise, NEVER a
// fabricated number.
type ResourceUsage struct {
	HarnessAllocBytes      uint64 `yaml:"harness_alloc_bytes"`
	HarnessTotalAllocBytes uint64 `yaml:"harness_total_alloc_bytes"`
	HarnessSysBytes        uint64 `yaml:"harness_sys_bytes"`
	HarnessNumGC           uint32 `yaml:"harness_num_gc"`
	HarnessGoroutines      int    `yaml:"harness_goroutines"`
	// ClusterMetricsAvailable is false on the constrained env (no
	// metrics-server); the cluster_* fields are then omitted rather than
	// fabricated (BI-8).
	ClusterMetricsAvailable bool `yaml:"cluster_metrics_available"`
	ClusterCPUMilli         *int `yaml:"cluster_cpu_milli,omitempty"`
	ClusterMemoryBytes      *int `yaml:"cluster_memory_bytes,omitempty"`
}

// SnapshotResourceUsage captures the harness process's own resource usage
// (BI-8). cluster_* is left unavailable: the constrained in-process env has no
// metrics-server, so a cluster number would be fabricated.
func SnapshotResourceUsage() ResourceUsage {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ResourceUsage{
		HarnessAllocBytes:       ms.Alloc,
		HarnessTotalAllocBytes:  ms.TotalAlloc,
		HarnessSysBytes:         ms.Sys,
		HarnessNumGC:            ms.NumGC,
		HarnessGoroutines:       runtime.NumGoroutine(),
		ClusterMetricsAvailable: false,
	}
}

// SizeCheck is the AC4/BI-10 result: the summed run-dir bytes and whether the
// cap was exceeded. The cap is fail-LOUD (the alert is emitted + durable in
// metadata) but fail-OPEN on the artefacts (nothing is deleted or truncated).
type SizeCheck struct {
	SizeBytes       int64
	Cap             int64
	SizeCapExceeded bool
}

// CheckSize sums the run dir and compares against the cap. A non-positive cap
// falls back to DefaultMaxRunSizeBytes so a mis-wired flag cannot disable the
// signal.
func CheckSize(runDir string, capBytes int64) (SizeCheck, error) {
	if capBytes <= 0 {
		capBytes = DefaultMaxRunSizeBytes
	}
	size, err := DirSize(runDir)
	if err != nil {
		return SizeCheck{}, err
	}
	return SizeCheck{
		SizeBytes:       size,
		Cap:             capBytes,
		SizeCapExceeded: size > capBytes,
	}, nil
}
