package baseline

// sigma bucket boundaries per Story 1.18 Task 7.2 (relabelled in the
// PR #27 review follow-up):
//
//	[3, 5)  -> "3-5"
//	[5, 10) -> "5-10"
//	>= 10   -> "10+"
//
// Labels are non-overlapping ranges so an operator query for any
// single label returns the observations that genuinely fall in that
// range, not a superset. The lower bound of 3 reflects the default
// SigmaMultiplier = 3.0 (DefaultSigmaMultiplier); deviations below 3
// are not emitted by engine.handleDecoded (the sigma gate enforces
// `sigma >= sigmaMul > 0`), so there is no "<3" bucket.
//
// The helper is private to the baseline package because no other
// component bucketises sigma; if Story 2.x or 3.x needs the same
// bucketisation it can be promoted in line with the severitybucket
// shared-package precedent.
const (
	sigmaBucket3to5  = "3-5"
	sigmaBucket5to10 = "5-10"
	sigmaBucketGe10  = "10+"
)

// sigmaBucket returns the canonical bucket label for a deviation's
// sigma magnitude. Values below 3 (unreachable from the engine's
// emission path; the gate enforces sigma >= sigmaMul >= 3.0) map to
// "3-5" as a defensive default. NaN inputs are not reachable in
// practice (the numberOf extractor guard rejects NaN at the metric
// boundary per Story 1.17 follow-up D2) but would also land in
// "3-5" via the IEEE-754 NaN-vs-comparison fallthrough.
func sigmaBucket(sigma float64) string {
	switch {
	case sigma >= 10:
		return sigmaBucketGe10
	case sigma >= 5:
		return sigmaBucket5to10
	default:
		return sigmaBucket3to5
	}
}
