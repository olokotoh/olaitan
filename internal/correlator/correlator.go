// Package correlator wires Ring-2 event correlation over NATS.
package correlator

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	corev1 "k8s.io/api/core/v1"
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
	c := &Correlator{
		nc:        cfg.NATS,
		kube:      cfg.Kube,
		assembler: cfg.Assembler,
		window:    window.NewStore(cfg.WindowDuration),
		log:       cfg.Log.With("component", "correlator"),
	}
	c.minSources.Store(int64(cfg.MultiSignalMinSources))
	return c, nil
}

// UpdateConfig hot-reloads safe correlator knobs.
func (c *Correlator) UpdateConfig(windowDuration time.Duration, minSources int) {
	if windowDuration > 0 {
		c.window.SetWindowDuration(windowDuration)
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
			continue
		}
		var ev schema.Event
		if err := json.Unmarshal(msg.Data(), &ev); err != nil {
			c.log.Warn("correlator: dropping malformed event", "err", err)
			_ = msg.Ack()
			continue
		}
		if _, err := c.AddEvent(ctx, ev); err != nil {
			return err
		}
		_ = msg.Ack()
	}
}

// AddEvent inserts ev and publishes a package if multi-signal convergence fires.
func (c *Correlator) AddEvent(ctx context.Context, ev schema.Event) (*schema.EvidencePackage, error) {
	workloadID, err := c.workloadIDForEvent(ctx, ev)
	if err != nil {
		return nil, err
	}
	snap, err := c.window.Add(workloadID, ev)
	if err != nil {
		return nil, err
	}
	tr, ok := trigger.EvaluateMultiSignal(snap, int(c.minSources.Load()), time.Now().UTC())
	if !ok {
		return nil, nil
	}
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
		return nil, fmt.Errorf("correlator: assemble evidence: %w", err)
	}
	if _, err := c.nc.PublishJS(ctx, subjects.EvidencePackages, pkg, jetstream.WithMsgID(pkg.PackageID)); err != nil {
		return nil, fmt.Errorf("correlator: publish evidence: %w", err)
	}
	return pkg, nil
}

func (c *Correlator) workloadIDForEvent(ctx context.Context, ev schema.Event) (string, error) {
	ref := ev.Pod
	if ref.Namespace == "" || ref.Name == "" {
		return "", fmt.Errorf("correlator: event %q missing pod namespace/name", ev.ID)
	}
	if c.kube == nil {
		return keys.PodFallbackID(ref.Namespace, ref.Name)
	}
	pod, err := c.kube.CoreV1().Pods(ref.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return keys.PodFallbackID(ref.Namespace, ref.Name)
		}
		return "", fmt.Errorf("correlator: resolve pod %s/%s: %w", ref.Namespace, ref.Name, err)
	}
	identity, err := posture.ResolveWorkloadIdentity(ctx, c.kube, pod)
	if err != nil {
		return keys.PodFallbackID(ref.Namespace, ref.Name)
	}
	if identity.OwnerKind == "Pod" {
		return keys.PodFallbackID(identity.Namespace, identity.OwnerName)
	}
	return keys.WorkloadID(identity.Namespace, identity.OwnerKind, identity.OwnerName)
}

var _ = corev1.Pod{}
