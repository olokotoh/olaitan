// Package correlator wires Ring-2 event correlation over NATS.
package correlator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/olokotoh/olaitan/internal/collector/posture"
	"github.com/olokotoh/olaitan/internal/correlator/assembler"
	"github.com/olokotoh/olaitan/internal/correlator/trigger"
	"github.com/olokotoh/olaitan/internal/correlator/window"
	"github.com/olokotoh/olaitan/internal/keys"
	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// consumerMaxDeliver caps JetStream's per-message redelivery. After
// five failed AddEvent attempts the NATS server stops redelivery and
// publishes a $JS.EVENT.ADVISORY.CONSUMER.MAX_DELIVERIES advisory on
// the `EVENTS_RAW.olaitan-correlator` subject; Story 1.18 will
// consume that advisory for a true DLQ. Until then, capping the
// retry count prevents a poison event from looping forever.
const consumerMaxDeliver = 5

// publishAttemptTimeout caps a single PublishJS attempt so a stalled
// JetStream publish cannot block the correlator goroutine for the
// outer Run context's lifetime. The 2s ceiling matches the Story 1.6
// falco adapter convention (internal/collector/falco/falco.go).
const publishAttemptTimeout = 2 * time.Second

// fetchBackoff is the bounded sleep between consumer.Next attempts
// after a non-timeout error. Capped low so transient NATS errors
// cause noticeable but non-pathological retry spacing.
const fetchBackoff = time.Second

// identityCacheTTL caps how long a resolved (workloadID, identity)
// pair stays warm. The TTL is recomputed at New time from the
// configured window duration with a 60s ceiling so the cache cannot
// outlive the window's typical workload churn.
const identityCacheTTLCeiling = 60 * time.Second

// Config configures a Correlator.
type Config struct {
	NATS                  *natsclient.Client
	Kube                  kubernetes.Interface
	Assembler             *assembler.Assembler
	WindowDuration        time.Duration
	MultiSignalMinSources int
	Log                   *slog.Logger
}

// Correlator owns the per-workload window and evidence publish path.
type Correlator struct {
	nc         *natsclient.Client
	kube       kubernetes.Interface
	assembler  *assembler.Assembler
	window     *window.Store
	minSources atomic.Int64
	log        *slog.Logger

	identityCache    sync.Map // map[string]identityCacheEntry, key = namespace + "/" + podName
	identityCacheTTL time.Duration
}

type identityCacheEntry struct {
	workloadID string
	identity   schema.WorkloadIdentity
	expiry     time.Time
}

// New constructs a Correlator.
func New(cfg Config) (*Correlator, error) {
	if cfg.NATS == nil {
		return nil, fmt.Errorf("correlator: nats client is nil")
	}
	if cfg.Assembler == nil {
		return nil, fmt.Errorf("correlator: assembler is nil")
	}
	if cfg.WindowDuration <= 0 {
		cfg.WindowDuration = time.Minute
	}
	if cfg.MultiSignalMinSources <= 0 {
		cfg.MultiSignalMinSources = 2
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	ttl := cfg.WindowDuration
	if ttl > identityCacheTTLCeiling {
		ttl = identityCacheTTLCeiling
	}
	c := &Correlator{
		nc:               cfg.NATS,
		kube:             cfg.Kube,
		assembler:        cfg.Assembler,
		window:           window.NewStore(cfg.WindowDuration),
		log:              cfg.Log.With("component", "correlator"),
		identityCacheTTL: ttl,
	}
	c.minSources.Store(int64(cfg.MultiSignalMinSources))
	return c, nil
}

// UpdateConfig hot-reloads safe correlator knobs.
func (c *Correlator) UpdateConfig(windowDuration time.Duration, minSources int) {
	if windowDuration > 0 {
		c.window.SetWindowDuration(windowDuration)
		ttl := windowDuration
		if ttl > identityCacheTTLCeiling {
			ttl = identityCacheTTLCeiling
		}
		c.identityCacheTTL = ttl
	}
	if minSources >= 2 {
		c.minSources.Store(int64(minSources))
	}
}

// Run consumes the raw event JetStream hierarchy until ctx is cancelled.
func (c *Correlator) Run(ctx context.Context) error {
	stream, err := c.nc.JetStream().Stream(ctx, "EVENTS_RAW")
	if err != nil {
		return fmt.Errorf("correlator: stream EVENTS_RAW: %w", err)
	}
	consumer, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       "olaitan-correlator",
		AckPolicy:     jetstream.AckExplicitPolicy,
		FilterSubject: subjects.RawPrefix + ">",
		// MaxDeliver caps NATS-side redelivery. After consumerMaxDeliver
		// failed Acks the server stops redelivery and emits the
		// $JS.EVENT.ADVISORY.CONSUMER.MAX_DELIVERIES advisory on
		// subject EVENTS_RAW.olaitan-correlator; Story 1.18 will
		// subscribe to that advisory for a DLQ surface. Until then,
		// the cap prevents a poison event from looping forever.
		MaxDeliver: consumerMaxDeliver,
	})
	if err != nil {
		return fmt.Errorf("correlator: consumer: %w", err)
	}

	for {
		if err := ctx.Err(); err != nil {
			return nil
		}
		msg, err := consumer.Next(jetstream.FetchMaxWait(250 * time.Millisecond))
		if err != nil {
			if isExpectedFetchTimeout(err) {
				continue
			}
			c.log.Warn("correlator: consumer fetch failed", "err", err)
			// Bounded sleep so transient NATS errors don't busy-loop.
			// Honour context cancellation immediately.
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(fetchBackoff):
			}
			continue
		}
		var ev schema.Event
		if err := json.Unmarshal(msg.Data(), &ev); err != nil {
			c.log.Warn("correlator: dropping malformed event", "err", err)
			_ = msg.Ack()
			continue
		}
		if _, err := c.AddEvent(ctx, ev); err != nil {
			// AddEvent failures are dropped-and-acked: a bad event
			// must not crash-loop the ring (P1 closure). Validation
			// errors and assembler size-cap fatal errors share this
			// path; permanent failures are logged and the message is
			// acked so JetStream stops redelivering.
			c.log.Warn("correlator: dropping event after AddEvent failure",
				"event_id", ev.ID, "err", err)
		}
		_ = msg.Ack()
	}
}

func isExpectedFetchTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, jetstream.ErrNoMessages) {
		return true
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	// The jetstream client occasionally wraps the per-fetch timeout
	// as a bare error string rather than a sentinel; match on the
	// canonical message to avoid bouncing the backoff path.
	if strings.Contains(err.Error(), "nats: no messages") {
		return true
	}
	return false
}

// AddEvent inserts ev and publishes a package if multi-signal
// convergence has just transitioned from false to true for this
// workload (rising-edge per P23). Validation errors on the event's
// PodRef are treated as drop-and-continue so a malformed event cannot
// tear down the ring.
func (c *Correlator) AddEvent(ctx context.Context, ev schema.Event) (*schema.EvidencePackage, error) {
	workloadID, identity, err := c.resolveAndCacheIdentity(ctx, ev)
	if err != nil {
		// P14: validation errors are drop-and-continue. Surface them
		// as a wrapped error so the caller logs context, but the
		// outer Run loop already swallows the error and acks.
		return nil, fmt.Errorf("correlator: resolve workload: %w", err)
	}
	minSources := int(c.minSources.Load())
	snap, transitioned, err := c.window.AddAndCheckRisingEdge(workloadID, ev, minSources)
	if err != nil {
		return nil, err
	}
	if !transitioned {
		return nil, nil
	}
	tr := trigger.MultiSignal(snap, distinctSources(snap.Events), time.Now().UTC())
	tr.ResolvedIdentity = &identity
	return c.publishTrigger(ctx, tr, snap)
}

// FireRuleMatch handles the future Story 1.15 external rule trigger input.
func (c *Correlator) FireRuleMatch(ctx context.Context, workloadID string, match schema.RuleMatch) (*schema.EvidencePackage, error) {
	return c.publishTrigger(ctx, trigger.RuleMatch(workloadID, match, time.Now().UTC()), c.window.Snapshot(workloadID))
}

// FireBaselineDeviation handles the future Story 1.17 external baseline trigger input.
func (c *Correlator) FireBaselineDeviation(ctx context.Context, workloadID string, deviation schema.BaselineDeviation) (*schema.EvidencePackage, error) {
	return c.publishTrigger(ctx, trigger.BaselineDeviation(workloadID, deviation, time.Now().UTC()), c.window.Snapshot(workloadID))
}

func (c *Correlator) publishTrigger(ctx context.Context, tr trigger.Trigger, snap window.Snapshot) (*schema.EvidencePackage, error) {
	pkg, err := c.assembler.Assemble(ctx, tr, snap)
	if err != nil {
		if errors.Is(err, assembler.ErrSizeCapUnreachable) {
			// P15 closure: the package is un-publishable but the ring
			// must keep running. Log at error and skip the publish.
			c.log.Error("correlator: evidence package exceeds wire cap, skipping publish",
				"workload_id", tr.WorkloadID, "trigger_type", tr.Type, "err", err)
			return nil, nil
		}
		return nil, fmt.Errorf("correlator: assemble evidence: %w", err)
	}
	pubCtx, cancel := context.WithTimeout(ctx, publishAttemptTimeout)
	defer cancel()
	if _, err := c.nc.PublishJS(pubCtx, subjects.EvidencePackages, pkg, jetstream.WithMsgID(pkg.PackageID)); err != nil {
		return nil, fmt.Errorf("correlator: publish evidence: %w", err)
	}
	return pkg, nil
}

// resolveAndCacheIdentity returns the workload identity for ev's pod,
// using a TTL cache so multi-signal bursts don't trigger a Pods.Get
// storm against the apiserver. Cache key is (namespace, podName);
// TTL is bounded by identityCacheTTL.
func (c *Correlator) resolveAndCacheIdentity(ctx context.Context, ev schema.Event) (string, schema.WorkloadIdentity, error) {
	ref := ev.Pod
	if ref.Namespace == "" || ref.Name == "" {
		return "", schema.WorkloadIdentity{}, fmt.Errorf("event %q missing pod namespace/name", ev.ID)
	}
	key := ref.Namespace + "/" + ref.Name
	now := time.Now()
	if entry, ok := c.identityCache.Load(key); ok {
		ce, _ := entry.(identityCacheEntry)
		if now.Before(ce.expiry) {
			return ce.workloadID, ce.identity, nil
		}
		c.identityCache.Delete(key)
	}

	workloadID, identity, err := c.resolveIdentityUncached(ctx, ref)
	if err != nil {
		return "", schema.WorkloadIdentity{}, err
	}
	c.identityCache.Store(key, identityCacheEntry{
		workloadID: workloadID,
		identity:   identity,
		expiry:     now.Add(c.identityCacheTTL),
	})
	return workloadID, identity, nil
}

func (c *Correlator) resolveIdentityUncached(ctx context.Context, ref schema.PodRef) (string, schema.WorkloadIdentity, error) {
	if c.kube == nil {
		id, err := keys.PodFallbackID(ref.Namespace, ref.Name)
		if err != nil {
			return "", schema.WorkloadIdentity{}, err
		}
		return id, schema.WorkloadIdentity{Namespace: ref.Namespace, OwnerKind: "Pod", OwnerName: ref.Name, PodName: ref.Name}, nil
	}
	pod, err := c.kube.CoreV1().Pods(ref.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			id, ferr := keys.PodFallbackID(ref.Namespace, ref.Name)
			if ferr != nil {
				return "", schema.WorkloadIdentity{}, ferr
			}
			return id, schema.WorkloadIdentity{Namespace: ref.Namespace, OwnerKind: "Pod", OwnerName: ref.Name, PodName: ref.Name}, nil
		}
		return "", schema.WorkloadIdentity{}, fmt.Errorf("resolve pod %s/%s: %w", ref.Namespace, ref.Name, err)
	}
	identity, err := posture.ResolveWorkloadIdentity(ctx, c.kube, pod)
	if err != nil {
		id, ferr := keys.PodFallbackID(ref.Namespace, ref.Name)
		if ferr != nil {
			return "", schema.WorkloadIdentity{}, ferr
		}
		return id, schema.WorkloadIdentity{Namespace: ref.Namespace, OwnerKind: "Pod", OwnerName: ref.Name, PodName: ref.Name}, nil
	}
	if identity.OwnerKind == "Pod" {
		id, ferr := keys.PodFallbackID(identity.Namespace, identity.OwnerName)
		if ferr != nil {
			return "", schema.WorkloadIdentity{}, ferr
		}
		return id, identity, nil
	}
	id, err := keys.WorkloadID(identity.Namespace, identity.OwnerKind, identity.OwnerName)
	if err != nil {
		return "", schema.WorkloadIdentity{}, err
	}
	return id, identity, nil
}

func distinctSources(events []schema.Event) []schema.EventSource {
	seen := map[schema.EventSource]struct{}{}
	for _, ev := range events {
		if ev.Source != "" {
			seen[ev.Source] = struct{}{}
		}
	}
	out := make([]schema.EventSource, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	return out
}
