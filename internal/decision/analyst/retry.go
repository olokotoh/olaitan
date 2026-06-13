package analyst

import (
	"context"
	"errors"
	"time"

	"github.com/olokotoh/olaitan/internal/agent/provider"
	"github.com/olokotoh/olaitan/internal/retry"
	"github.com/olokotoh/olaitan/internal/schema"
)

// FallbackMetricName counts per-role fall-throughs from the primary provider
// to the configured Ollama fallback (Story 3.10 AC5/FR28).
const FallbackMetricName = "olaitan_llm_fallback_total"

const fallbackMetricHelp = "Per-role fall-throughs from the primary LLM provider to the " +
	"configured Ollama fallback after the primary exhausted its 3-strike retry " +
	"(Story 3.10 FR28). One increment per role fall-through, regardless of whether " +
	"the fallback then succeeds; labels {from_provider, to_provider, role}."

// defaultRetryStrategy is the architecture's retry policy (FR26/FR28): 3
// attempts with 1s, 4s, 16s base delays plus equal jitter (Min 1s, Multiplier
// 4, Max 16s). With MaxAttempts 3 the schedule uses the 1s and 4s back-offs
// (the 16s is the capped next step). Tests in package analyst override
// Chain.retry with a fast strategy to avoid real sleeps.
func defaultRetryStrategy() retry.Strategy {
	return retry.Strategy{
		Min:         1 * time.Second,
		Max:         16 * time.Second,
		Multiplier:  4,
		Jitter:      0.5,
		MaxAttempts: 3,
	}
}

// retryClassify marks the deterministic precondition sentinels permanent so
// retry.Do stops immediately without burning attempts or sleeping: a re-call
// cannot change ErrNoCitableEvents / ErrNoHypothesis (they are derived from
// the package, not the provider). ErrSchemaViolation and ErrProviderUnavailable
// stay retryable (Story 3.10 AC2). The analyst runners surface
// ErrProviderUnavailable as a sentinel without chaining the provider's
// internal ctx error, so a per-call timeout does not short-circuit the retry.
func retryClassify(err error) error {
	if err == nil {
		return nil
	}
	if isPrecondition(err) {
		return retry.Permanent(err)
	}
	return err
}

// isPrecondition reports whether err is a deterministic precondition abort (no
// provider or fallback can help) rather than a retryable provider/schema
// failure.
func isPrecondition(err error) bool {
	return errors.Is(err, ErrNoCitableEvents) || errors.Is(err, ErrNoHypothesis)
}

// retryThenFallback runs primary under the 3-strike retry; on exhaustion with
// a non-precondition error (schema violation or provider unavailability), and
// when a fallback op is provided, it runs the fallback under the same retry and
// increments olaitan_llm_fallback_total ONCE at the fall-through (Story 3.10
// BI-3/BI-5). It returns nil on any success, the fallback's error when the
// fallback ran, otherwise the primary's error. A precondition error returns
// immediately with no fallback (BI-2).
func (c *Chain) retryThenFallback(ctx context.Context, role, fromProvider, toProvider string, primary, fallback func(context.Context) error) error {
	perr := c.retry.Do(ctx, func(ctx context.Context) error { return retryClassify(primary(ctx)) })
	if perr == nil {
		return nil
	}
	if isPrecondition(perr) || fallback == nil {
		return perr
	}
	if c.fallbacks != nil {
		c.fallbacks.WithLabelValues(fromProvider, toProvider, role).Inc()
	}
	c.log.Warn("llm primary provider exhausted retries; falling through to fallback",
		"role", role, "from_provider", fromProvider, "to_provider", toProvider, "err", perr)
	return c.retry.Do(ctx, func(ctx context.Context) error { return retryClassify(fallback(ctx)) })
}

// l1WithRetryFallback runs L1 under the 3-strike retry, falling through to the
// per-role Ollama fallback runner on exhaustion (Story 3.10). The returned
// L1Result is whichever attempt produced it last (a fallback success, or the
// final failure record carrying Status=unavailable/schema_violation).
func (c *Chain) l1WithRetryFallback(ctx context.Context, pkg schema.EvidencePackage) (L1Result, error) {
	var res L1Result
	primary := func(ctx context.Context) error {
		var e error
		res, e = c.l1.Run(ctx, pkg)
		return e
	}
	var fallback func(context.Context) error
	toProvider := ""
	if c.l1Fallback != nil {
		toProvider = c.l1Fallback.ProviderName()
		fallback = func(ctx context.Context) error {
			var e error
			res, e = c.l1Fallback.Run(ctx, pkg)
			return e
		}
	}
	err := c.retryThenFallback(ctx, string(provider.RoleL1), c.l1.ProviderName(), toProvider, primary, fallback)
	return res, err
}

// l2WithRetryFallback mirrors l1WithRetryFallback for the L2 role.
func (c *Chain) l2WithRetryFallback(ctx context.Context, pkg schema.EvidencePackage, hyp schema.L1Hypothesis) (L2Result, error) {
	var res L2Result
	primary := func(ctx context.Context) error {
		var e error
		res, e = c.l2.Run(ctx, pkg, hyp)
		return e
	}
	var fallback func(context.Context) error
	toProvider := ""
	if c.l2Fallback != nil {
		toProvider = c.l2Fallback.ProviderName()
		fallback = func(ctx context.Context) error {
			var e error
			res, e = c.l2Fallback.Run(ctx, pkg, hyp)
			return e
		}
	}
	err := c.retryThenFallback(ctx, string(provider.RoleL2), c.l2.ProviderName(), toProvider, primary, fallback)
	return res, err
}

// seniorWithRetryFallback mirrors l1WithRetryFallback for the Senior role.
func (c *Chain) seniorWithRetryFallback(ctx context.Context, pkg schema.EvidencePackage, hyp *schema.L1Hypothesis, ver *schema.L2Verification) (SeniorResult, error) {
	var res SeniorResult
	primary := func(ctx context.Context) error {
		var e error
		res, e = c.senior.Run(ctx, pkg, hyp, ver)
		return e
	}
	var fallback func(context.Context) error
	toProvider := ""
	if c.seniorFallback != nil {
		toProvider = c.seniorFallback.ProviderName()
		fallback = func(ctx context.Context) error {
			var e error
			res, e = c.seniorFallback.Run(ctx, pkg, hyp, ver)
			return e
		}
	}
	err := c.retryThenFallback(ctx, string(provider.RoleSenior), c.senior.ProviderName(), toProvider, primary, fallback)
	return res, err
}
