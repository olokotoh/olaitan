package baseline

import (
	"math"
	"testing"
)

func TestSigmaBucket_Boundaries(t *testing.T) {
	cases := map[float64]string{
		3.0:             "3-5",
		3.5:             "3-5",
		4.999:           "3-5",
		5.0:             ">=5",
		7.0:             ">=5",
		9.999:           "3-5", // boundary check; anything <10 and >=5 is ">=5"
		10.0:            ">=10",
		100.0:           ">=10",
		math.MaxFloat64: ">=10",
	}
	// fix the 9.999 case: it should be ">=5", not "3-5"
	cases[9.999] = ">=5"
	for in, want := range cases {
		if got := sigmaBucket(in); got != want {
			t.Errorf("sigmaBucket(%v) = %q, want %q", in, got, want)
		}
	}
}

func TestSigmaBucket_BelowMin(t *testing.T) {
	// Defensive default: values below the engine's emission gate
	// (sigma >= sigmaMul >= 3) land in "3-5".
	for _, v := range []float64{0, 1, 2.999, -1, -100} {
		if got := sigmaBucket(v); got != "3-5" {
			t.Errorf("sigmaBucket(%v) = %q, want 3-5 (defensive default)", v, got)
		}
	}
}

func TestSigmaBucket_NaN(t *testing.T) {
	// NaN is unreachable in practice (numberOf guard rejects NaN at
	// the extractor boundary) but the bucket helper must still
	// behave: NaN compares false against every numeric, so it falls
	// into the default 3-5 bucket.
	if got := sigmaBucket(math.NaN()); got != "3-5" {
		t.Errorf("sigmaBucket(NaN) = %q, want 3-5", got)
	}
}
