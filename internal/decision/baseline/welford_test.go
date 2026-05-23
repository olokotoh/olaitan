package baseline

import (
	"math"
	"testing"
)

func TestWelford_EmptyState(t *testing.T) {
	var w Welford
	if w.Count != 0 {
		t.Errorf("empty Count = %d, want 0", w.Count)
	}
	if w.Variance() != 0 {
		t.Errorf("empty Variance = %v, want 0", w.Variance())
	}
	if w.StdDev() != 0 {
		t.Errorf("empty StdDev = %v, want 0", w.StdDev())
	}
	if got := w.Sigma(42); got != 0 {
		t.Errorf("empty Sigma(42) = %v, want 0 (no panic)", got)
	}
}

func TestWelford_SingleSample(t *testing.T) {
	var w Welford
	w.Update(7.5)
	if w.Count != 1 {
		t.Errorf("Count = %d, want 1", w.Count)
	}
	if w.Mean != 7.5 {
		t.Errorf("Mean = %v, want 7.5", w.Mean)
	}
	if w.Variance() != 0 {
		t.Errorf("Variance() = %v, want 0 (single sample is undefined)", w.Variance())
	}
}

func TestWelford_TwoSample(t *testing.T) {
	var w Welford
	w.Update(2)
	w.Update(8)
	wantMean := 5.0
	if math.Abs(w.Mean-wantMean) > 1e-12 {
		t.Errorf("Mean = %v, want %v", w.Mean, wantMean)
	}
	// Sample variance of {2, 8} is (a-b)^2/2 = 36/2 = 18.
	wantVar := 18.0
	if math.Abs(w.Variance()-wantVar) > 1e-12 {
		t.Errorf("Variance = %v, want %v", w.Variance(), wantVar)
	}
	wantStd := math.Sqrt(18)
	if math.Abs(w.StdDev()-wantStd) > 1e-12 {
		t.Errorf("StdDev = %v, want %v", w.StdDev(), wantStd)
	}
}

func TestWelford_TenSample_BatchAgreement(t *testing.T) {
	xs := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
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
	if math.Abs(w.Mean-batchMean) > 1e-12 {
		t.Errorf("Mean = %v, want %v", w.Mean, batchMean)
	}
	if math.Abs(w.Variance()-batchVar) > 1e-12 {
		t.Errorf("Variance = %v, want %v", w.Variance(), batchVar)
	}
}

func TestWelford_Sigma(t *testing.T) {
	var w Welford
	for _, x := range []float64{1, 2, 3, 4, 5} {
		w.Update(x)
	}
	// Mean = 3, sample variance = 2.5, std = sqrt(2.5).
	got := w.Sigma(3 + math.Sqrt(2.5))
	if math.Abs(got-1.0) > 1e-12 {
		t.Errorf("Sigma(mean+sigma) = %v, want 1.0", got)
	}
	got3 := w.Sigma(3 + 3*math.Sqrt(2.5))
	if math.Abs(got3-3.0) > 1e-12 {
		t.Errorf("Sigma(mean+3sigma) = %v, want 3.0", got3)
	}
}

func TestWelford_Reset(t *testing.T) {
	var w Welford
	for _, x := range []float64{10, 20, 30} {
		w.Update(x)
	}
	w.Reset()
	if w.Count != 0 || w.Mean != 0 || w.M2 != 0 {
		t.Errorf("after Reset: Count=%d Mean=%v M2=%v, want zeros", w.Count, w.Mean, w.M2)
	}
}

func TestWelford_MarshalUnmarshal_RoundTrip(t *testing.T) {
	var w Welford
	for _, x := range []float64{1.5, 2.5, 3.5, 4.5, 5.5} {
		w.Update(x)
	}
	hash := w.MarshalRedisHash()
	if got, ok := hash["count"]; !ok || got != "5" {
		t.Errorf("hash[count] = %v, want \"5\"", got)
	}
	if _, ok := hash["mean"]; !ok {
		t.Errorf("hash missing mean")
	}
	if _, ok := hash["m2"]; !ok {
		t.Errorf("hash missing m2")
	}

	// Convert any -> string for UnmarshalRedisHash.
	asStrings := make(map[string]string, len(hash))
	for k, v := range hash {
		asStrings[k] = v.(string)
	}

	var w2 Welford
	if err := w2.UnmarshalRedisHash(asStrings); err != nil {
		t.Fatalf("UnmarshalRedisHash: %v", err)
	}
	if w2.Count != w.Count {
		t.Errorf("Count round-trip: got %d want %d", w2.Count, w.Count)
	}
	if w2.Mean != w.Mean {
		t.Errorf("Mean round-trip: got %v want %v", w2.Mean, w.Mean)
	}
	if w2.M2 != w.M2 {
		t.Errorf("M2 round-trip: got %v want %v", w2.M2, w.M2)
	}
}

func TestWelford_UnmarshalRedisHash_Empty(t *testing.T) {
	var w Welford
	if err := w.UnmarshalRedisHash(map[string]string{}); err != nil {
		t.Errorf("empty hash: %v", err)
	}
	if w.Count != 0 || w.Mean != 0 || w.M2 != 0 {
		t.Errorf("empty hash should leave zero state")
	}
}

func TestWelford_UnmarshalRedisHash_Partial(t *testing.T) {
	var w Welford
	err := w.UnmarshalRedisHash(map[string]string{"count": "5", "mean": "2.5"})
	if err == nil {
		t.Errorf("partial hash should error")
	}
}

func TestWelford_UnmarshalRedisHash_BadInt(t *testing.T) {
	var w Welford
	err := w.UnmarshalRedisHash(map[string]string{"count": "abc", "mean": "1", "m2": "1"})
	if err == nil {
		t.Errorf("bad count should error")
	}
}

func TestWelford_Merge_EmptyOther(t *testing.T) {
	var w Welford
	w.Update(1)
	w.Update(2)
	var other Welford
	w.Merge(&other)
	if w.Count != 2 || w.Mean != 1.5 {
		t.Errorf("merge with empty changed state: %+v", w)
	}
}

func TestWelford_Merge_EmptySelf(t *testing.T) {
	var w Welford
	var other Welford
	other.Update(10)
	other.Update(20)
	w.Merge(&other)
	if w.Count != 2 || math.Abs(w.Mean-15) > 1e-12 {
		t.Errorf("merge into empty failed: %+v", w)
	}
}

func TestWelford_Merge_Equivalence(t *testing.T) {
	a := []float64{1, 2, 3, 4, 5}
	b := []float64{6, 7, 8, 9, 10}
	var combined Welford
	for _, x := range a {
		combined.Update(x)
	}
	for _, x := range b {
		combined.Update(x)
	}
	var wA, wB Welford
	for _, x := range a {
		wA.Update(x)
	}
	for _, x := range b {
		wB.Update(x)
	}
	wA.Merge(&wB)
	if wA.Count != combined.Count {
		t.Errorf("Count: merge=%d sequential=%d", wA.Count, combined.Count)
	}
	if math.Abs(wA.Mean-combined.Mean) > 1e-9 {
		t.Errorf("Mean: merge=%v sequential=%v", wA.Mean, combined.Mean)
	}
	if math.Abs(wA.Variance()-combined.Variance()) > 1e-9 {
		t.Errorf("Variance: merge=%v sequential=%v", wA.Variance(), combined.Variance())
	}
}
