package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/errgroup"

	"github.com/olokotoh/olaitan/internal/collector/applog"
	"github.com/olokotoh/olaitan/internal/collector/audit"
	"github.com/olokotoh/olaitan/internal/collector/cni"
	"github.com/olokotoh/olaitan/internal/collector/cri"
	"github.com/olokotoh/olaitan/internal/collector/falco"
	"github.com/olokotoh/olaitan/internal/collector/posture"
	"github.com/olokotoh/olaitan/internal/config"
	"github.com/olokotoh/olaitan/internal/metrics"
	"github.com/olokotoh/olaitan/internal/sourcehealth"
)

// adapterMetrics is the structural-typed contract every streaming
// source adapter satisfies for Story 1.12's Prometheus surface plus the
// Story 1.13 rate-limit circuit breaker counter. Falco, audit, CRI,
// CNI, and applog all expose Health(), EventsTotal(), and EngagedTotal()
// without sharing a named interface, so the metrics wiring keys on
// Go's structural typing rather than introducing a new interface in
// internal/collector/.
//
// The contract intentionally stays narrow: per-adapter detail metrics
// (rejected-by-reason, translate errors, publish drops, oversize drops)
// are bound via Registry.RegisterCounter against the adapter's existing
// int64-returning getters; there is no per-adapter wrapper struct.
type adapterMetrics interface {
	Health() sourcehealth.Reader
	EventsTotal() int64
	EngagedTotal() int64
}

// startMetricsServer is the wiring helper called by both
// startCollectorRing and startAggregatorRing. It constructs a fresh
// metrics.Registry, binds every adapter under sources, optionally binds
// the posture client (or its disabled gauge), and starts the
// metrics.Server under g. The registry is returned for tests that want
// to gather metrics directly without going through HTTP.
//
// nodeName is the K8S_NODE_NAME value the collector subcommand reads
// from the downward API; passed through so per-adapter circuit-breaker
// counters carry the correct `node` const-label per Story 1.13 AC2.
// The aggregator subcommand has no streaming adapters, so an empty
// string is acceptable there.
//
// Returns a non-nil error if the metrics address is empty (defence in
// depth against a Validate bypass), if any adapter registration fails,
// or if posture wiring fails.
func startMetricsServer(
	ctx context.Context,
	g *errgroup.Group,
	log *slog.Logger,
	cfg *config.Config,
	nodeName string,
	sources map[string]adapterMetrics,
	postureCli *posture.Client,
) (*metrics.Registry, error) {
	if cfg == nil {
		return nil, fmt.Errorf("metrics: nil config")
	}
	if cfg.Metrics.Address == "" {
		return nil, fmt.Errorf("metrics: empty metrics.address (defence in depth; Validate should have caught this)")
	}

	reg := metrics.NewRegistry()

	for source, ad := range sources {
		if err := reg.RegisterAdapter(source, ad.Health(), ad.EventsTotal); err != nil {
			return nil, fmt.Errorf("metrics: register adapter %q: %w", source, err)
		}
		// Register per-adapter detail counters here, before the HTTP server
		// starts accepting scrapes. A scrape that lands between the
		// adapter registration and the detail-counter registration would
		// otherwise see source_healthy + sensor_events_total but missing
		// audit_rejected, cri_translate_errors, cni_*, etc.
		if err := registerAdapterCounters(reg, source, nodeName, ad); err != nil {
			return nil, fmt.Errorf("metrics: register detail counters %q: %w", source, err)
		}
	}

	if postureCli != nil {
		getters := metrics.PostureGetters{
			"cache_hit":    postureCli.PostureCacheHits,
			"cache_miss":   postureCli.PostureCacheMisses,
			"cache_bypass": postureCli.PostureCacheBypasses,
			"api_errors":   postureCli.PostureAPIErrors,
			"orphan_pods":  postureCli.PostureOrphanPods,
			"unavailable":  postureCli.PostureUnavailable,
		}
		if err := reg.RegisterPostureCounters(getters); err != nil {
			return nil, fmt.Errorf("metrics: register posture counters: %w", err)
		}
	} else if cfg.Detection.Posture.Enabled {
		// Posture is enabled in config but the client wasn't constructed
		// (collector ring: posture only lives in the aggregator). Skip
		// the disabled-gauge in this case; the aggregator-side
		// startMetricsServer call will register the counters.
	} else {
		if err := reg.RegisterPostureDisabled(); err != nil {
			return nil, fmt.Errorf("metrics: register posture_disabled: %w", err)
		}
	}

	srv := metrics.New(cfg.Metrics.Address, log, reg)
	g.Go(func() error {
		if err := srv.Start(ctx); err != nil {
			return fmt.Errorf("metrics: server %q: %w", cfg.Metrics.Address, err)
		}
		return nil
	})
	log.Info("metrics: server wired",
		"addr", cfg.Metrics.Address,
		"adapters", len(sources),
		"posture_enabled", postureCli != nil,
	)
	return reg, nil
}

// registerAdapterCounters binds the per-adapter detail counters that
// fall outside the source_healthy / sensor_events_total pair. Used by
// startCollectorRing once each adapter is constructed.
//
// nodeName is the K8S_NODE_NAME value passed through from
// startMetricsServer; the Story 1.13 circuit-breaker counter carries
// the node label per AC2 alongside the source const-label. Cardinality
// stays bounded at 5 sources x 1 node-per-pod = 5 series per pod
// (NFR32) because the DaemonSet topology guarantees one agent pod per
// node.
//
// The audit by-reason map is exposed via a per-reason labelled counter
// (one time-series per (source=audit, reason=<bucket>) pair). The
// other adapters expose single-value counters (translate errors, etc).
func registerAdapterCounters(reg *metrics.Registry, source, nodeName string, ad adapterMetrics) error {
	// Story 1.13: every streaming adapter exposes EngagedTotal via the
	// adapterMetrics structural-typed contract, so the circuit-breaker
	// counter registers identically across the five sources. Registered
	// up front (not inside the per-adapter switch) so a new adapter
	// type inherits the wiring without amending the switch.
	if err := reg.RegisterCounter(
		"olaitan_sensor_circuit_breaker_engaged_total", source,
		"Cumulative count of per-source rate-limit circuit breaker engage transitions on this node (Story 1.13).",
		prometheus.Labels{"node": nodeName},
		ad.EngagedTotal,
	); err != nil {
		return fmt.Errorf("metrics: register circuit_breaker_engaged_total[%s]: %w", source, err)
	}

	switch a := ad.(type) {
	case *audit.Adapter:
		// Six canonical reason buckets per Story 1.7, mirroring the
		// rejectedCounters type comment in internal/collector/audit/audit.go
		// (the adapter increments exactly these keys at the HTTP/translate
		// boundary). Register every bucket up front so a zero-value bucket
		// still gets a CounterFunc; otherwise dashboards see a missing
		// series until the first rejection arrives.
		//
		// Each CounterFunc reads RejectedByReasonValue (O(1) per call) so
		// a /metrics scrape acquires six RLocks rather than allocating six
		// fresh maps via Snapshot (Copilot review CR1 on PR #21).
		reasons := []string{"method_not_allowed", "unsupported_media_type", "payload_too_large", "decode_error", "trailing_json", "translate_failed"}
		for _, r := range reasons {
			r := r
			err := reg.RegisterCounter(
				"olaitan_sensor_audit_rejected_total",
				source,
				"Audit-webhook receiver events rejected at HTTP/translate boundary, bucketed by reason (Story 1.7).",
				prometheus.Labels{"reason": r},
				func() int64 { return int64(a.RejectedByReasonValue(r)) },
			)
			if err != nil {
				return fmt.Errorf("metrics: register audit_rejected_total[%s]: %w", r, err)
			}
		}
	case *cri.Adapter:
		if err := reg.RegisterCounter(
			"olaitan_sensor_cri_translate_errors_total", source,
			"CRI lifecycle events that failed translation and were log+dropped (Story 1.8).",
			nil, a.TranslateErrors); err != nil {
			return err
		}
		if err := reg.RegisterCounter(
			"olaitan_sensor_cri_publish_drops_total", source,
			"CRI events whose publish attempt returned a permanent error and were dropped (Story 1.8).",
			nil, a.PublishDrops); err != nil {
			return err
		}
	case *cni.Adapter:
		if err := reg.RegisterCounter(
			"olaitan_sensor_cni_translate_errors_total", source,
			"Calico flow records that failed translation and were log+dropped (Story 1.10).",
			nil, a.TranslateErrors); err != nil {
			return err
		}
		if err := reg.RegisterCounter(
			"olaitan_sensor_cni_publish_drops_total", source,
			"Calico events whose publish attempt returned a permanent error and were dropped (Story 1.10).",
			nil, a.PublishDrops); err != nil {
			return err
		}
		if err := reg.RegisterCounter(
			"olaitan_sensor_cni_oversize_dropped_total", source,
			"Calico events rejected at translate time because the marshalled form exceeded MaxEventBytes (Story 1.10).",
			nil, a.OversizeDropped); err != nil {
			return err
		}
		// Registered as a gauge (not a counter) because ConsecutiveEOFs
		// resets to 0 on every successful Recv; that violates Prometheus
		// counter monotonicity. Gauge naming convention omits _total
		// (Copilot review CR2 on PR #21).
		if err := reg.RegisterGauge(
			"olaitan_sensor_cni_consecutive_eofs", source,
			"EOFs from Goldmane stream.Recv since the last successful Recv; resets to 0 on success (Story 1.10).",
			nil, a.ConsecutiveEOFs); err != nil {
			return err
		}
	case *falco.Adapter:
		// Story 10.2: the http_output receiver. One series per status
		// code, registered up front so a code that has not happened yet
		// reads 0 instead of being absent. 401 climbing means something
		// is posting with the wrong token; 503 means NATS refused
		// publishes, and Falco does not retry, so those alerts are lost.
		for _, c := range falco.ResponseCodes {
			c := c
			if err := reg.RegisterCounter(
				"olaitan_sensor_falco_http_requests_total", source,
				"Falco http_output requests answered by the collector, by HTTP status code (Story 10.2).",
				prometheus.Labels{"code": c},
				func() int64 { return int64(a.RequestsByCode(c)) },
			); err != nil {
				return fmt.Errorf("metrics: register falco_http_requests_total[%s]: %w", c, err)
			}
		}
		if err := reg.RegisterCounter(
			"olaitan_sensor_falco_alerts_received_total", source,
			"Authenticated, decodable Falco alerts received, published or not; the gap to sensor_events_total is sampling plus publish failures (Story 10.2).",
			nil, a.AlertsReceivedTotal); err != nil {
			return err
		}
		if err := reg.RegisterCounter(
			"olaitan_sensor_falco_heartbeats_total", source,
			"Falco metrics snapshots received; they drive source_healthy{source=\"falco\"} and are never published as events (Story 10.2).",
			nil, a.HeartbeatsTotal); err != nil {
			return err
		}
		if err := reg.RegisterCounter(
			"olaitan_sensor_falco_publish_drops_total", source,
			"Falco alerts dropped on a permanent publish error, for example over the EVENTS_RAW per-message cap (Story 10.2).",
			nil, a.PublishDrops); err != nil {
			return err
		}
	case *applog.SidecarTracker:
		// Story 10.10: the applog sidecars on this node, by state.
		for _, st := range []struct {
			state string
			read  func() int64
		}{{"live", a.Live}, {"stale", a.Stale}, {"unhealthy", a.Unhealthy}} {
			if err := reg.RegisterGauge(
				"olaitan_sensor_applog_sidecars", source,
				"applog sidecars on this node by heartbeat state: live (heard within the stale threshold, 3 heartbeat intervals), stale (silent, pod probably gone or stuck), unhealthy (live but reporting its own tail or publish path failing) (Story 10.10).",
				prometheus.Labels{"state": st.state}, st.read); err != nil {
				return err
			}
		}
	case *applog.Adapter:
		// Story 1.9 detail counters. Story 1.12 does NOT pass an applog
		// Adapter into startCollectorRing's metricsSources because applog
		// runs in a per-pod sidecar process rather than the agent pod;
		// the registration here is the future-proofing hook for the
		// deferred sidecar metrics surface (deferred-work W7) so the
		// sidecar binary inherits the detail counter wiring without a
		// second per-adapter change (Copilot review CR3 on PR #21).
		if err := reg.RegisterCounter(
			"olaitan_sensor_applog_translate_errors_total", source,
			"Applog records that failed translation and were log+dropped (Story 1.9).",
			nil, a.TranslateErrors); err != nil {
			return err
		}
		if err := reg.RegisterCounter(
			"olaitan_sensor_applog_publish_drops_total", source,
			"Applog events whose publish attempt returned a permanent error and were dropped (Story 1.9).",
			nil, a.PublishDrops); err != nil {
			return err
		}
		if err := reg.RegisterCounter(
			"olaitan_sensor_applog_lines_shed_total", source,
			"LineRecords dropped due to back-pressure shedding under a stalled consumer (Story 1.9).",
			nil, a.LinesShed); err != nil {
			return err
		}
		if err := reg.RegisterCounter(
			"olaitan_sensor_applog_lost_on_shutdown_total", source,
			"Applog events whose publishWithRetry was cancelled mid-flight by ctx.Done (Story 1.9).",
			nil, a.LostOnShutdown); err != nil {
			return err
		}
	}
	return nil
}
