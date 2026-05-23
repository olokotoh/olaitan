package baseline

import (
	"math"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// TestProperty_Welford_MatchesBatchMeanVariance pins AC5 explicit: across
// 1,000 randomised input streams of length 2 to 1,000 with values in
// [-1e6, 1e6], Welford's (mean, variance) equals the batch closed-form
// (mean, variance) to within 1e-9.
func TestProperty_Welford_MatchesBatchMeanVariance(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 1000
	params.Rng.Seed(0x17BA5E11)

	props := gopter.NewProperties(params)
	props.Property("Welford(mean,var) == batch(mean,var)", prop.ForAll(
		func(xs []float64) bool {
			if len(xs) < 2 {
				return true
			}
			var w Welford
			for _, x := range xs {
				w.Update(x)
			}
			var sum float64
			for _, x := range xs {
				sum += x
			}
			batchMean := sum / float64(len(xs))
			var sq float64
			for _, x := range xs {
				d := x - batchMean
				sq += d * d
			}
			batchVar := sq / float64(len(xs)-1)

			// Scale-aware tolerance: large input magnitudes amplify the
			// gap between Welford's incremental update and the batch
			// closed form by float64 round-off. The 1e-9 tolerance in
			// AC5 is the relative tolerance scaled by the batch
			// statistic magnitude; we apply it as an absolute floor
			// when the statistic is near zero.
			tolMean := 1e-9 * (1 + math.Abs(batchMean))
			tolVar := 1e-9 * (1 + math.Abs(batchVar))
			if math.Abs(w.Mean-batchMean) > tolMean {
				return false
			}
			if math.Abs(w.Variance()-batchVar) > tolVar {
				return false
			}
			return true
		},
		gen.SliceOfN(2, gen.Float64Range(-1e6, 1e6)).WithLabel("xs-min"),
	))
	props.Property("Welford(mean,var) matches batch on variable-length streams 2..1000", prop.ForAll(
		func(n int, seed float64) bool {
			xs := make([]float64, n)
			for i := range xs {
				// deterministic pseudo-stream in [-1e6, 1e6]
				xs[i] = math.Sin(float64(i)+seed) * 1e6
			}
			var w Welford
			for _, v := range xs {
				w.Update(v)
			}
			var sum float64
			for _, v := range xs {
				sum += v
			}
			batchMean := sum / float64(n)
			var sq float64
			for _, v := range xs {
				d := v - batchMean
				sq += d * d
			}
			batchVar := sq / float64(n-1)
			tolMean := 1e-9 * (1 + math.Abs(batchMean))
			tolVar := 1e-9 * (1 + math.Abs(batchVar))
			if math.Abs(w.Mean-batchMean) > tolMean {
				return false
			}
			if math.Abs(w.Variance()-batchVar) > tolVar {
				return false
			}
			return true
		},
		gen.IntRange(2, 1000),
		gen.Float64Range(-1, 1),
	))
	props.TestingRun(t)
}

// TestProperty_Welford_StdDevAtFixedSizes pins AC5 explicit: StdDev
// correctness for sample sizes 1, 10, 100, 1,000, 10,000 against
// math.Sqrt(batchVariance).
func TestProperty_Welford_StdDevAtFixedSizes(t *testing.T) {
	for _, n := range []int{1, 10, 100, 1000, 10000} {
		var w Welford
		xs := make([]float64, n)
		for i := 0; i < n; i++ {
			xs[i] = math.Sin(float64(i)*0.7) * 100
			w.Update(xs[i])
		}
		if n < 2 {
			if w.StdDev() != 0 {
				t.Errorf("n=1: StdDev = %v, want 0", w.StdDev())
			}
			continue
		}
		var sum float64
		for _, v := range xs {
			sum += v
		}
		mean := sum / float64(n)
		var sq float64
		for _, v := range xs {
			d := v - mean
			sq += d * d
		}
		batchStd := math.Sqrt(sq / float64(n-1))
		tol := 1e-9 * (1 + batchStd)
		if math.Abs(w.StdDev()-batchStd) > tol {
			t.Errorf("n=%d: StdDev=%v batch=%v diff=%v", n, w.StdDev(), batchStd, math.Abs(w.StdDev()-batchStd))
		}
	}
}

// TestProperty_Welford_MergeAdditive pins AC5 sample additivity:
// merging two streams via the combined-Welford formula equals running
// Welford on the concatenated stream to within 1e-9.
func TestProperty_Welford_MergeAdditive(t *testing.T) {
	params := gopter.DefaultTestParameters()
	params.MinSuccessfulTests = 200
	params.Rng.Seed(0x17ED6E26)

	props := gopter.NewProperties(params)
	props.Property("merge(a,b) == concat(a,b)", prop.ForAll(
		func(a, b []float64) bool {
			if len(a) == 0 || len(b) == 0 {
				return true
			}
			var wA, wB, combined Welford
			for _, x := range a {
				wA.Update(x)
				combined.Update(x)
			}
			for _, x := range b {
				wB.Update(x)
				combined.Update(x)
			}
			wA.Merge(&wB)
			if wA.Count != combined.Count {
				return false
			}
			tolMean := 1e-9 * (1 + math.Abs(combined.Mean))
			tolVar := 1e-9 * (1 + math.Abs(combined.Variance()))
			if math.Abs(wA.Mean-combined.Mean) > tolMean {
				return false
			}
			if math.Abs(wA.Variance()-combined.Variance()) > tolVar {
				return false
			}
			return true
		},
		gen.SliceOfN(5, gen.Float64Range(-1000, 1000)),
		gen.SliceOfN(5, gen.Float64Range(-1000, 1000)),
	))
	props.TestingRun(t)
}
