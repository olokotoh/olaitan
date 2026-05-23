package severitybucket

import "testing"

func TestScore_NamedLabels(t *testing.T) {
	cases := map[string]int{
		"":          10,
		"emergency": 100,
		"fatal":     100,
		"critical":  100,
		"alert":     80,
		"error":     80,
		"err":       80,
		"high":      80,
		"warning":   50,
		"warn":      50,
		"medium":    50,
		"notice":    30,
		"low":       30,
		"unknown":   10,
		"WARN":      50, // case-insensitive
		"  alert ":  80, // whitespace-tolerant
	}
	for in, want := range cases {
		if got := Score(in); got != want {
			t.Errorf("Score(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestScore_SyslogNumeric(t *testing.T) {
	cases := map[string]int{
		"0": 100,
		"1": 90,
		"2": 80,
		"3": 70,
		"4": 50,
		"5": 40,
		"6": 30,
		"7": 10,
	}
	for in, want := range cases {
		if got := Score(in); got != want {
			t.Errorf("Score(syslog %q) = %d, want %d", in, got, want)
		}
	}
}

func TestScore_OutOfRangeNumeric(t *testing.T) {
	// Numerics outside 0..7 fall through to keyword matching ->
	// default-low (score 10). Pre-Story-1.18 assembler behaviour.
	for _, s := range []string{"-1", "8", "42", "100"} {
		if got := Score(s); got != 10 {
			t.Errorf("Score(%q) = %d, want 10 (default-low)", s, got)
		}
	}
}

func TestBucket_Boundaries(t *testing.T) {
	cases := map[int]string{
		-1:  BucketLow,
		0:   BucketLow,
		49:  BucketLow,
		50:  BucketMedium,
		69:  BucketMedium,
		70:  BucketHigh,
		89:  BucketHigh,
		90:  BucketCritical,
		100: BucketCritical,
		200: BucketCritical,
	}
	for in, want := range cases {
		if got := Bucket(in); got != want {
			t.Errorf("Bucket(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestBucketFromLabel_RoundTrip(t *testing.T) {
	cases := map[string]string{
		"emergency": BucketCritical,
		"critical":  BucketCritical,
		"alert":     BucketHigh,
		"error":     BucketHigh,
		"high":      BucketHigh,
		"warning":   BucketMedium,
		"medium":    BucketMedium,
		"notice":    BucketLow,
		"low":       BucketLow,
		"unknown":   BucketLow,
		"":          BucketLow,
		"0":         BucketCritical, // syslog emergency
		"4":         BucketMedium,   // syslog warning
		"7":         BucketLow,      // syslog debug
	}
	for in, want := range cases {
		if got := BucketFromLabel(in); got != want {
			t.Errorf("BucketFromLabel(%q) = %q, want %q", in, got, want)
		}
	}
}
