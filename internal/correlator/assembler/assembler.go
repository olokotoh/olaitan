// Package assembler builds and bounds Ring-2 EvidencePackage payloads.
package assembler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/olokotoh/olaitan/internal/collector/posture"
	"github.com/olokotoh/olaitan/internal/correlator/trigger"
	"github.com/olokotoh/olaitan/internal/correlator/window"
	"github.com/olokotoh/olaitan/internal/keys"
	"github.com/olokotoh/olaitan/internal/schema"
)

const (
	// DefaultMaxPackageBytes is the Story 1.14 on-wire cap.
	DefaultMaxPackageBytes = 128 * 1024
	// DefaultHighSeverityThreshold controls the event overflow priority.
	DefaultHighSeverityThreshold = 50
)

// PostureGetter is the narrow posture client contract used by the assembler.
type PostureGetter interface {
	Get(context.Context, *corev1.Pod, ...posture.Option) (*schema.WorkloadPosture, error)
}

// Config configures an Assembler.
type Config struct {
	Kube                  kubernetes.Interface
	Posture               PostureGetter
	MaxPackageBytes       int
	HighSeverityThreshold int
	Now                   func() time.Time
}

// Assembler converts a trigger plus workload window into an EvidencePackage.
type Assembler struct {
	kube                  kubernetes.Interface
	posture               PostureGetter
	maxPackageBytes       int
	highSeverityThreshold int
	now                   func() time.Time
}

// New constructs an Assembler with production defaults.
func New(cfg Config) *Assembler {
	if cfg.MaxPackageBytes <= 0 {
		cfg.MaxPackageBytes = DefaultMaxPackageBytes
	}
	if cfg.HighSeverityThreshold <= 0 {
		cfg.HighSeverityThreshold = DefaultHighSeverityThreshold
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Assembler{
		kube:                  cfg.Kube,
		posture:               cfg.Posture,
		maxPackageBytes:       cfg.MaxPackageBytes,
		highSeverityThreshold: cfg.HighSeverityThreshold,
		now:                   cfg.Now,
	}
}

// Assemble builds an EvidencePackage and applies the configured size cap.
func (a *Assembler) Assemble(ctx context.Context, tr trigger.Trigger, snap window.Snapshot) (*schema.EvidencePackage, error) {
	assembledAt := a.now()
	podRef := firstPodRef(snap.Events)
	pod, identity, workloadID, degraded := a.resolveWorkload(ctx, podRef)
	postureSnap, postureDegraded := a.resolvePosture(ctx, pod, identity)
	if postureDegraded {
		degraded = appendUnique(degraded, "posture")
	}

	pkg := &schema.EvidencePackage{
		SchemaVersion:    "evidence.v1",
		WorkloadID:       workloadID,
		WorkloadIdentity: identity,
		AssembledAt:      assembledAt,
		WindowStart:      snap.Start,
		WindowEnd:        snap.End,
		Trigger:          toSchemaTrigger(tr),
		Events:           append([]schema.Event(nil), snap.Events...),
		WorkloadPosture:  postureSnap,
		DegradedSources:  degraded,
	}
	if tr.RuleMatch != nil {
		pkg.RuleMatches = []schema.RuleMatch{*tr.RuleMatch}
	}
	if tr.BaselineDeviation != nil {
		pkg.BaselineDeviations = []schema.BaselineDeviation{*tr.BaselineDeviation}
	}
	pkg.PackageID = packageID(pkg)
	if err := enforceSizeCap(pkg, a.maxPackageBytes, a.highSeverityThreshold); err != nil {
		return nil, err
	}
	return pkg, nil
}

func (a *Assembler) resolveWorkload(ctx context.Context, ref schema.PodRef) (*corev1.Pod, schema.WorkloadIdentity, string, []string) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: ref.Name, Namespace: ref.Namespace, UID: typesUID(ref.UID)}}
	degraded := []string{}
	if a.kube != nil && ref.Name != "" && ref.Namespace != "" {
		got, err := a.kube.CoreV1().Pods(ref.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
		if err == nil {
			pod = got
		} else if !apierrors.IsNotFound(err) {
			degraded = append(degraded, "kubernetes")
		}
	}

	identity := schema.WorkloadIdentity{Namespace: ref.Namespace, OwnerKind: "Pod", OwnerName: ref.Name, PodName: ref.Name}
	if a.kube != nil && pod.Name != "" {
		if id, err := posture.ResolveWorkloadIdentity(ctx, a.kube, pod); err == nil {
			identity = id
		}
	}
	workloadID, err := workloadIDFor(identity)
	if err != nil {
		workloadID, _ = keys.PodFallbackID(ref.Namespace, ref.Name)
	}
	return pod, identity, workloadID, degraded
}

func (a *Assembler) resolvePosture(ctx context.Context, pod *corev1.Pod, identity schema.WorkloadIdentity) (*schema.WorkloadPosture, bool) {
	if a.posture == nil || pod == nil || pod.Name == "" || pod.Namespace == "" {
		return unavailablePosture(identity, a.now(), schema.PostureUnavailableTransient), true
	}
	got, err := a.posture.Get(ctx, pod)
	if err != nil || got == nil || got.Unavailable {
		reason := schema.PostureUnavailableTransient
		if got != nil && got.UnavailableReason != "" {
			reason = got.UnavailableReason
		}
		if got != nil {
			return got, true
		}
		return unavailablePosture(identity, a.now(), reason), true
	}
	return got, false
}

func unavailablePosture(identity schema.WorkloadIdentity, capturedAt time.Time, reason string) *schema.WorkloadPosture {
	return &schema.WorkloadPosture{
		Identity:          identity,
		OrphanPod:         identity.OwnerKind == "Pod",
		Unavailable:       true,
		UnavailableReason: reason,
		CapturedAt:        capturedAt,
	}
}

func toSchemaTrigger(tr trigger.Trigger) schema.EvidenceTrigger {
	return schema.EvidenceTrigger{
		Type:              tr.Type,
		EventID:           tr.EventID,
		RuleMatch:         tr.RuleMatch,
		BaselineDeviation: tr.BaselineDeviation,
		DistinctSources:   append([]schema.EventSource(nil), tr.DistinctSources...),
		FiredAt:           tr.FiredAt,
	}
}

// EnforceSizeCap deterministically reduces pkg.Events until its JSON
// encoding is within maxBytes. Trigger artifacts are preserved before
// event reduction, matching FR12's overflow priority.
func EnforceSizeCap(pkg *schema.EvidencePackage, maxBytes int) error {
	return enforceSizeCap(pkg, maxBytes, DefaultHighSeverityThreshold)
}

func enforceSizeCap(pkg *schema.EvidencePackage, maxBytes, highSeverityThreshold int) error {
	if pkg == nil {
		return fmt.Errorf("assembler: nil package")
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxPackageBytes
	}
	if size(pkg) <= maxBytes {
		return nil
	}

	original := append([]schema.Event(nil), pkg.Events...)
	summarised := summariseEvents(original, highSeverityThreshold)
	sortForOverflow(summarised)
	pkg.Overflow = &schema.EvidenceOverflow{
		OriginalEventCount: len(original),
		Counts:             countEvents(original),
	}

	for keep := len(summarised); keep >= 0; keep-- {
		pkg.Events = append([]schema.Event(nil), summarised[:keep]...)
		pkg.Overflow.IncludedEventCount = keep
		pkg.Overflow.DroppedEventCount = len(original) - keep
		if size(pkg) <= maxBytes {
			return nil
		}
	}
	return fmt.Errorf("assembler: evidence package cannot fit cap %d bytes without dropping trigger metadata", maxBytes)
}

func summariseEvents(events []schema.Event, highSeverityThreshold int) []schema.Event {
	out := make([]schema.Event, 0, len(events))
	for _, ev := range events {
		ev.Raw = nil
		if len(ev.Summary) > 160 {
			ev.Summary = ev.Summary[:160]
		}
		if severityScore(ev.Severity) >= highSeverityThreshold {
			out = append(out, ev)
		}
	}
	return out
}

func sortForOverflow(events []schema.Event) {
	sort.SliceStable(events, func(i, j int) bool {
		si, sj := severityScore(events[i].Severity), severityScore(events[j].Severity)
		if si != sj {
			return si > sj
		}
		if !events[i].Timestamp.Equal(events[j].Timestamp) {
			return events[i].Timestamp.Before(events[j].Timestamp)
		}
		return events[i].ID < events[j].ID
	})
}

func countEvents(events []schema.Event) []schema.EvidenceCount {
	counts := map[string]schema.EvidenceCount{}
	for _, ev := range events {
		key := string(ev.Source) + "\x00" + string(ev.Category)
		c := counts[key]
		c.Source = ev.Source
		c.Category = ev.Category
		c.Count++
		counts[key] = c
	}
	out := make([]schema.EvidenceCount, 0, len(counts))
	for _, c := range counts {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].Category < out[j].Category
	})
	return out
}

func severityScore(severity string) int {
	s := strings.ToLower(strings.TrimSpace(severity))
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	switch s {
	case "emergency", "fatal", "critical":
		return 100
	case "alert", "error", "err", "high":
		return 80
	case "warning", "warn", "medium":
		return 50
	case "notice", "low":
		return 30
	default:
		return 10
	}
}

func size(pkg *schema.EvidencePackage) int {
	data, err := json.Marshal(pkg)
	if err != nil {
		return 1 << 30
	}
	return len(data)
}

func packageID(pkg *schema.EvidencePackage) string {
	h := sha256.Sum256([]byte(pkg.WorkloadID + "|" + pkg.Trigger.Type + "|" + pkg.Trigger.EventID + "|" + pkg.AssembledAt.Format(time.RFC3339Nano)))
	return "epkg-" + hex.EncodeToString(h[:8])
}

func firstPodRef(events []schema.Event) schema.PodRef {
	if len(events) == 0 {
		return schema.PodRef{}
	}
	return events[0].Pod
}

func workloadIDFor(id schema.WorkloadIdentity) (string, error) {
	if id.OwnerKind == "Pod" {
		return keys.PodFallbackID(id.Namespace, id.OwnerName)
	}
	return keys.WorkloadID(id.Namespace, id.OwnerKind, id.OwnerName)
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func typesUID(uid string) types.UID {
	return types.UID(uid)
}
