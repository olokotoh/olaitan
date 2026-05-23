// Package baseline wires the Story 1.17 Welford baseline engine into
// the Ring-2 trigger contract. The engine consumes EvidencePackages
// from subjects.EvidencePackages, maintains per-workload Gaussian
// baselines for five default metrics via Welford's online algorithm,
// and emits one downstream baseline_deviation-triggered
// EvidencePackage per metric whose observation exceeds the configured
// sigma multiplier above the running mean (FR16, FR17).
//
// Package layout:
//
//	internal/decision/baseline/
//	├── welford.go         ← this file: Welford state and updates
//	├── store.go           ← Redis-backed persistence (HGETALL + HSET)
//	├── warmup.go          ← restart-aware warm-up controller (FR18)
//	├── metrics.go         ← five default metric extractors
//	└── engine.go          ← JetStream-consuming Engine
//
// One-way dependency direction: this package does NOT import
// correlator. The correlator's FireBaselineDeviation satisfies the
// engine's local BaselineDeviationEmitter interface by signature,
// mirroring the Story 1.15 RuleMatchEmitter pattern.
//
// Re-entrancy guard: the engine short-circuits inbound packages whose
// Trigger.Type equals trigger.TypeBaselineDeviation so a deviation
// that fires its own downstream package cannot recurse.
//
// Why Welford (over batch recompute): the controller sustains a
// per-workload, per-evaluation update rate that makes batch-recompute
// of mean/variance non-starter. Welford's online algorithm is the
// numerically-stable single-pass equivalent (NFR35).
package baseline

import (
	"fmt"
	"math"
	"strconv"
)

// Welford holds the running count, mean, and sum-of-squared-deltas
// for a single metric stream. The zero value is the empty state
// (count zero, mean zero, m2 zero) and is safe to Update.
type Welford struct {
	Count int64
	Mean  float64
	M2    float64
}

// Update folds a single observation into the running statistics
// using Welford's canonical online algorithm. The mean is updated
// first against the new sample count; M2 then accumulates the
// product of the pre-update delta and the post-update delta. The
// algorithm is numerically stable for streams of any length and
// reproduces batch (mean, variance) to within float64 round-off.
func (w *Welford) Update(x float64) {
	n := w.Count + 1
	delta := x - w.Mean
	w.Mean += delta / float64(n)
	delta2 := x - w.Mean
	w.M2 += delta * delta2
	w.Count = n
}

// Variance returns the sample variance (Bessel-corrected, divided
// by Count-1) of the observations folded in so far. Returns 0 when
// Count is below 2 because sample variance is undefined for a
// zero- or one-sample stream; callers compare to zero before
// dividing.
func (w *Welford) Variance() float64 {
	if w.Count < 2 {
		return 0
	}
	return w.M2 / float64(w.Count-1)
}

// StdDev returns the square root of Variance, or 0 when Variance is
// 0 or NaN. The NaN guard protects against pathological inputs
// (every observation identical at the float64 grain) where M2 can
// accumulate a tiny negative round-off residual.
func (w *Welford) StdDev() float64 {
	v := w.Variance()
	if v <= 0 || math.IsNaN(v) {
		return 0
	}
	return math.Sqrt(v)
}

// Sigma returns (x - Mean) / StdDev when StdDev is positive,
// otherwise 0. A zero return is the engine's signal that the
// observation cannot be sigma-tested (insufficient samples or
// degenerate stream) and must not be emitted as a deviation.
func (w *Welford) Sigma(x float64) float64 {
	sd := w.StdDev()
	if sd <= 0 || math.IsNaN(sd) {
		return 0
	}
	return (x - w.Mean) / sd
}

// Reset zeroes Count, Mean, and M2 in place. Called by the warm-up
// controller on a restart event before persisting the cleared
// state. Reset is a pure-memory operation; the durability half
// lives in store.go's Save.
func (w *Welford) Reset() {
	w.Count = 0
	w.Mean = 0
	w.M2 = 0
}

// MarshalRedisHash emits the three-field hash representation of
// the Welford state. Fields are encoded as decimal strings via
// fmt.Sprintf("%g", ...) for the floats so round-trip via
// UnmarshalRedisHash preserves the float64 bit pattern across
// Redis's text-on-the-wire HSET/HGETALL surface. The "count"
// field is emitted as a base-10 integer string.
//
// The returned map keys are bare ("count", "mean", "m2"); the
// caller (store.go) prefixes them with the metric name and merges
// every metric's hash into a single HSET round-trip per workload.
func (w *Welford) MarshalRedisHash() map[string]any {
	return map[string]any{
		"count": strconv.FormatInt(w.Count, 10),
		"mean":  fmt.Sprintf("%g", w.Mean),
		"m2":    fmt.Sprintf("%g", w.M2),
	}
}

// UnmarshalRedisHash parses the three-field hash representation
// back into the Welford state. The input map keys MUST be bare
// ("count", "mean", "m2") with the metric-name prefix already
// stripped by the caller. An empty or partial map is accepted as
// the zero state so a never-seen metric starts cold without
// erroring.
func (w *Welford) UnmarshalRedisHash(fields map[string]string) error {
	if len(fields) == 0 {
		w.Reset()
		return nil
	}
	countStr, hasCount := fields["count"]
	meanStr, hasMean := fields["mean"]
	m2Str, hasM2 := fields["m2"]
	if !hasCount && !hasMean && !hasM2 {
		w.Reset()
		return nil
	}
	if !hasCount || !hasMean || !hasM2 {
		return fmt.Errorf("baseline: welford hash partial; need count+mean+m2 (got count=%v mean=%v m2=%v)", hasCount, hasMean, hasM2)
	}
	count, err := strconv.ParseInt(countStr, 10, 64)
	if err != nil {
		return fmt.Errorf("baseline: parse welford count %q: %w", countStr, err)
	}
	mean, err := strconv.ParseFloat(meanStr, 64)
	if err != nil {
		return fmt.Errorf("baseline: parse welford mean %q: %w", meanStr, err)
	}
	m2, err := strconv.ParseFloat(m2Str, 64)
	if err != nil {
		return fmt.Errorf("baseline: parse welford m2 %q: %w", m2Str, err)
	}
	w.Count = count
	w.Mean = mean
	w.M2 = m2
	return nil
}

// Merge combines two independently-computed Welford states into a
// single state equivalent to running Welford on the concatenation
// of both underlying streams (per Chan-Golub-LeVeque parallel
// variance combination). Used by the property test for sample
// additivity; not on the engine hot path.
func (w *Welford) Merge(other *Welford) {
	if other == nil || other.Count == 0 {
		return
	}
	if w.Count == 0 {
		*w = *other
		return
	}
	nA := float64(w.Count)
	nB := float64(other.Count)
	n := nA + nB
	delta := other.Mean - w.Mean
	w.Mean += delta * nB / n
	w.M2 += other.M2 + delta*delta*nA*nB/n
	w.Count += other.Count
}
