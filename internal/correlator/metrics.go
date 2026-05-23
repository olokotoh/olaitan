package correlator

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/olokotoh/olaitan/internal/metrics"
)

// correlatorMetrics carries the Story 1.18 deterministic-detection
// observability handles registered against a *metrics.Registry. The
// fields are zero-initialised when no registry is supplied; every
// hot-path observation in publishTrigger is nil-guarded so the
// correlator can run without a metrics surface (tests, multi-process
// eval harness, future eval-only deployments).
//
// Per Story 1.18 BI-3, the registration is done inside Correlator.New
// when cfg.MetricsRegistry != nil, mirroring the rules engine and
// baseline engine registration patterns.
//
// Per Story 1.18 BI-5, windowSizeBytes incurs one redundant JSON
// marshal per publish (the natsclient.PublishJS marshals internally
// but does not return the byte length); the ~1 ms p99 cost at the
// 128 KiB ceiling is below the NFR2 trigger-to-publish budget.
type correlatorMetrics struct {
	evidencePackages *prometheus.CounterVec
	windowSizeBytes  prometheus.Histogram
	// overflow_summarised_total is registered as a reader-callback
	// counter against c.overflowSummarisedCount, so no writeable
	// handle is stored here; the production observe path bumps the
	// atomic directly.
}

// windowSizeBytesBuckets covers the assembler.DefaultMaxPackageBytes
// 128 KiB cap. The trailing 262144 bucket exists so a regression
// that allows packages to slip past the cap surfaces as visible
// rather than landing in +Inf invisibly.
var windowSizeBytesBuckets = []float64{
	1024,
	4096,
	8192,
	16384,
	32768,
	65536,
	131072,
	262144,
}

// registerMetrics binds the three Story 1.18 correlator metric
// families to reg. Returns the first registration error encountered.
//
//   - olaitan_correlator_evidence_packages_total{trigger_type}
//     CounterVec with three known label values
//     (multi_signal / rule_match / baseline_deviation). Cardinality
//     bounded for the lifetime of the project.
//   - olaitan_correlator_window_size_bytes Histogram with
//     architecture-cap-sized buckets.
//   - olaitan_correlator_overflow_summarised_total reader-callback
//     Counter backed by the overflowSummarised atomic on the
//     Correlator. One increment per package whose pkg.Overflow != nil.
func (c *Correlator) registerMetrics(reg *metrics.Registry) error {
	v, err := reg.RegisterCounterVec(
		"olaitan_correlator_evidence_packages_total",
		"Cumulative EvidencePackages successfully published to EVIDENCE.packages grouped by trigger type. The counter is bumped only after the JetStream publish returns no error, so the rate reflects published-to-bus packages, not assemble attempts. Label values are the three trigger.TypeMultiSignal/TypeRuleMatch/TypeBaselineDeviation constants (multi_signal, rule_match, baseline_deviation).",
		[]string{"trigger_type"},
	)
	if err != nil {
		return err
	}
	c.metrics.evidencePackages = v

	h, err := reg.RegisterHistogram(
		"olaitan_correlator_window_size_bytes",
		"",
		"On-wire size in bytes of the EvidencePackage at publish time (post-overflow-summarisation). Buckets cover the assembler.DefaultMaxPackageBytes 128 KiB cap; observations above 131072 indicate the cap-enforcement path was bypassed or failed.",
		nil,
		windowSizeBytesBuckets,
	)
	if err != nil {
		return err
	}
	c.metrics.windowSizeBytes = h

	if err := reg.RegisterCounter(
		"olaitan_correlator_overflow_summarised_total",
		"",
		"Cumulative EvidencePackages whose Events slice was reduced by the assembler size-cap enforcement path (pkg.Overflow non-nil). Increment is one per publish, not per dropped event; for per-event accounting see pkg.Overflow.DroppedEventCount carried inline on the package.",
		nil,
		func() int64 { return c.overflowSummarisedCount.Load() },
	); err != nil {
		return err
	}
	return nil
}
