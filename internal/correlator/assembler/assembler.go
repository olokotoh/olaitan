// Package assembler builds and bounds Ring-2 EvidencePackage payloads.
package assembler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"sync/atomic"
	"time"
	"unicode/utf8"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/olokotoh/olaitan/internal/collector/posture"
	"github.com/olokotoh/olaitan/internal/correlator/trigger"
	"github.com/olokotoh/olaitan/internal/correlator/window"
	"github.com/olokotoh/olaitan/internal/decision/severitybucket"
	"github.com/olokotoh/olaitan/internal/keys"
	"github.com/olokotoh/olaitan/internal/schema"
)

const (
	// DefaultMaxPackageBytes is the Story 1.14 on-wire cap.
	DefaultMaxPackageBytes = 128 * 1024
	// DefaultHighSeverityThreshold controls the event overflow priority.
	DefaultHighSeverityThreshold = 50
	// summaryByteCap bounds each event Summary on the overflow path.
	// 160 bytes is the historical limit; we now scan back to the
	// nearest rune boundary so a multi-byte UTF-8 character spanning
	// byte 160 is never sliced mid-codepoint.
	summaryByteCap = 160
)

// ErrSizeCapUnreachable is returned by Assemble when the trigger
// metadata alone exceeds the configured byte cap. The caller logs and
// skips the publish, matching the closure decision for P15 (do not
// tear down the correlator on a single un-publishable package).
var ErrSizeCapUnreachable = errors.New("assembler: evidence package cannot fit cap")

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
	Log                   *slog.Logger
}

// Assembler converts a trigger plus workload window into an EvidencePackage.
type Assembler struct {
	kube                  kubernetes.Interface
	posture               PostureGetter
	maxPackageBytes       int
	highSeverityThreshold int
	now                   func() time.Time
	log                   *slog.Logger
	seq                   atomic.Uint64
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
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Assembler{
		kube:                  cfg.Kube,
		posture:               cfg.Posture,
		maxPackageBytes:       cfg.MaxPackageBytes,
		highSeverityThreshold: cfg.HighSeverityThreshold,
		now:                   cfg.Now,
		log:                   cfg.Log.With("component", "correlator.assembler"),
	}
}

// Assemble builds an EvidencePackage and applies the configured size cap.
//
// When tr.ResolvedIdentity is non-nil the assembler reuses the
// supplied workload identity rather than re-fetching the pod from
// kube; this is the cache-warm path used by the correlator after a
// single Pods.Get per event. When the resolved identity is nil the
// assembler falls back to its own kube fetch, preserving the
// behaviour required by the external FireRuleMatch /
// FireBaselineDeviation entry points.
func (a *Assembler) Assemble(ctx context.Context, tr trigger.Trigger, snap window.Snapshot) (*schema.EvidencePackage, error) {
	assembledAt := a.now()
	podRef := firstPodRef(snap.Events)
	pod, identity, workloadID, resolutionSucceeded, degraded := a.resolveWorkload(ctx, tr, podRef)
	postureSnap, postureDegraded := a.resolvePosture(ctx, pod, identity, resolutionSucceeded)
	if postureDegraded {
		degraded = appendUnique(degraded, "posture")
	}

	// Fall back to the trigger's declared workload identity when pod
	// resolution produced nothing usable. External triggers
	// (FireRuleMatch / FireBaselineDeviation) and the multi-signal
	// constructor both populate tr.WorkloadID, so an empty buffer at
	// fire time does not produce an anonymous package.
	if workloadID == "" && tr.WorkloadID != "" {
		workloadID = tr.WorkloadID
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
	}
	if tr.RuleMatch != nil {
		pkg.RuleMatches = []schema.RuleMatch{*tr.RuleMatch}
	}
	if tr.BaselineDeviation != nil {
		pkg.BaselineDeviations = []schema.BaselineDeviation{*tr.BaselineDeviation}
	}

	// Package-level sampling indicators are computed BEFORE size-cap
	// pruning so the "this window's coverage was degraded" signal
	// persists even when the cap drops every sampled event.
	pkg.SamplingActive, pkg.SampledSources = computeSamplingIndicators(snap.Events)

	// Sort degraded sources for deterministic JSON output (NFR42).
	sort.Strings(degraded)
	pkg.DegradedSources = degraded

	pkg.PackageID = packageID(pkg, a.seq.Add(1))
	if err := enforceSizeCap(pkg, a.maxPackageBytes, a.highSeverityThreshold); err != nil {
		return nil, err
	}
	return pkg, nil
}

func (a *Assembler) resolveWorkload(ctx context.Context, tr trigger.Trigger, ref schema.PodRef) (*corev1.Pod, schema.WorkloadIdentity, string, bool, []string) {
	// Cache-warm path: the correlator already resolved this workload's
	// identity when it computed the per-event window key. Reusing the
	// supplied identity here skips a second Pods.Get per event and
	// closes P11 (k8s API storm under multi-signal).
	if tr.ResolvedIdentity != nil {
		identity := *tr.ResolvedIdentity
		pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: identity.PodName, Namespace: identity.Namespace, UID: typesUID(ref.UID)}}
		if pod.Name == "" {
			pod.Name = ref.Name
		}
		workloadID, err := workloadIDFor(identity)
		if err != nil {
			workloadID, _ = keys.PodFallbackID(ref.Namespace, ref.Name)
		}
		return pod, identity, workloadID, true, nil
	}

	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: ref.Name, Namespace: ref.Namespace, UID: typesUID(ref.UID)}}
	degraded := []string{}
	resolutionSucceeded := false
	if a.kube != nil && ref.Name != "" && ref.Namespace != "" {
		got, err := a.kube.CoreV1().Pods(ref.Namespace).Get(ctx, ref.Name, metav1.GetOptions{})
		switch {
		case err == nil:
			pod = got
			resolutionSucceeded = true
		case apierrors.IsNotFound(err):
			// Distinguish "pod genuinely missing" from "API transient";
			// downstream consumers can treat the two differently.
			degraded = append(degraded, "kubernetes:pod_not_found")
		default:
			a.log.Warn("resolveWorkload: kube fetch failed",
				"namespace", ref.Namespace, "pod", ref.Name, "err", err)
			degraded = append(degraded, "kubernetes")
		}
	}

	identity := schema.WorkloadIdentity{Namespace: ref.Namespace, OwnerKind: "Pod", OwnerName: ref.Name, PodName: ref.Name}
	if resolutionSucceeded && a.kube != nil && pod.Name != "" {
		if id, err := posture.ResolveWorkloadIdentity(ctx, a.kube, pod); err == nil {
			identity = id
		} else {
			a.log.Warn("resolveWorkload: identity resolution failed",
				"namespace", ref.Namespace, "pod", ref.Name, "err", err)
			resolutionSucceeded = false
		}
	}
	workloadID, err := workloadIDFor(identity)
	if err != nil {
		workloadID, _ = keys.PodFallbackID(ref.Namespace, ref.Name)
	}
	return pod, identity, workloadID, resolutionSucceeded, degraded
}

func (a *Assembler) resolvePosture(ctx context.Context, pod *corev1.Pod, identity schema.WorkloadIdentity, resolutionSucceeded bool) (*schema.WorkloadPosture, bool) {
	confirmedOrphan := resolutionSucceeded && identity.OwnerKind == "Pod" && a.kube != nil
	if a.posture == nil || pod == nil || pod.Name == "" || pod.Namespace == "" {
		return unavailablePosture(identity, a.now(), schema.PostureUnavailableTransient, confirmedOrphan), true
	}
	got, err := a.posture.Get(ctx, pod)
	if err != nil || got == nil || got.Unavailable {
		reason := schema.PostureUnavailableTransient
		if got != nil && got.UnavailableReason != "" {
			reason = got.UnavailableReason
		}
		if got != nil {
			return got.Clone(), true
		}
		return unavailablePosture(identity, a.now(), reason, confirmedOrphan), true
	}
	// Deep-copy the posture so a later refresh of the posture client's
	// cache cannot mutate the package between assembly and JSON
	// marshalling (P12 pointer aliasing race).
	return got.Clone(), false
}

func unavailablePosture(identity schema.WorkloadIdentity, capturedAt time.Time, reason string, confirmedOrphan bool) *schema.WorkloadPosture {
	return &schema.WorkloadPosture{
		Identity:          identity,
		OrphanPod:         confirmedOrphan,
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

func computeSamplingIndicators(events []schema.Event) (bool, []schema.EventSource) {
	active := false
	seen := map[schema.EventSource]struct{}{}
	for _, ev := range events {
		if !ev.Sampled {
			continue
		}
		active = true
		if ev.Source != "" {
			seen[ev.Source] = struct{}{}
		}
	}
	if !active {
		return false, nil
	}
	sources := make([]schema.EventSource, 0, len(seen))
	for s := range seen {
		sources = append(sources, s)
	}
	sort.Slice(sources, func(i, j int) bool { return sources[i] < sources[j] })
	return true, sources
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

	// Binary search the largest keep value (in [0, len(summarised)])
	// whose marshalled package still fits the cap. Worst case marshal
	// count is O(log N) instead of the prior O(N).
	lo, hi := 0, len(summarised)
	keep := -1
	for lo <= hi {
		mid := (lo + hi) / 2
		pkg.Events = append([]schema.Event(nil), summarised[:mid]...)
		pkg.Overflow.IncludedEventCount = mid
		pkg.Overflow.DroppedEventCount = len(original) - mid
		if size(pkg) <= maxBytes {
			keep = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	if keep >= 0 {
		pkg.Events = append([]schema.Event(nil), summarised[:keep]...)
		pkg.Overflow.IncludedEventCount = keep
		pkg.Overflow.DroppedEventCount = len(original) - keep
		return nil
	}

	// Graceful degrade: dropping events alone could not bring the
	// package under the cap. Try shedding the posture snapshot before
	// giving up; this preserves the trigger metadata, the package
	// identity, and the sampling indicators while signalling the
	// degradation via degraded_sources.
	if pkg.WorkloadPosture != nil {
		pkg.WorkloadPosture = nil
		pkg.DegradedSources = appendUnique(pkg.DegradedSources, "posture:size_cap")
		sort.Strings(pkg.DegradedSources)
		pkg.Events = nil
		pkg.Overflow.IncludedEventCount = 0
		pkg.Overflow.DroppedEventCount = len(original)
		if size(pkg) <= maxBytes {
			return nil
		}
	}
	return fmt.Errorf("%w of %d bytes without dropping trigger metadata", ErrSizeCapUnreachable, maxBytes)
}

func summariseEvents(events []schema.Event, highSeverityThreshold int) []schema.Event {
	out := make([]schema.Event, 0, len(events))
	for _, ev := range events {
		ev.Raw = nil
		ev.Summary = truncateSummaryUTF8(ev.Summary, summaryByteCap)
		if severitybucket.Score(ev.Severity) >= highSeverityThreshold {
			out = append(out, ev)
		}
	}
	return out
}

// truncateSummaryUTF8 returns s shortened to at most maxBytes bytes
// while preserving valid UTF-8: a multi-byte rune spanning the cut
// point is excluded entirely rather than sliced mid-codepoint.
func truncateSummaryUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	cut := maxBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func sortForOverflow(events []schema.Event) {
	sort.SliceStable(events, func(i, j int) bool {
		si, sj := severitybucket.Score(events[i].Severity), severitybucket.Score(events[j].Severity)
		if si != sj {
			return si > sj
		}
		// Story 1.13 honesty: at equal severity, full-fidelity events
		// outrank sampled ones. The cap-enforcement path drops the
		// tail first, so this puts sampled events at the bottom of
		// the same-severity bucket.
		if events[i].Sampled != events[j].Sampled {
			return !events[i].Sampled
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

// Story 1.18 moved the severityScore and syslogSeverityScore
// helpers into internal/decision/severitybucket so the rules engine
// emission path can share the same bucketisation as the overflow
// priority sort here. Call sites above use severitybucket.Score.

func size(pkg *schema.EvidencePackage) int {
	data, err := json.Marshal(pkg)
	if err != nil {
		return 1 << 30
	}
	return len(data)
}

func packageID(pkg *schema.EvidencePackage, seq uint64) string {
	// The per-Assembler sequence counter guarantees uniqueness even
	// when two assemblies land in the same nanosecond and share a
	// trigger EventID (e.g., deterministic-Now tests, or the
	// multi-signal path before P3's EventID fingerprint took effect).
	h := sha256.Sum256([]byte(pkg.WorkloadID + "|" + pkg.Trigger.Type + "|" + pkg.Trigger.EventID + "|" + pkg.AssembledAt.Format(time.RFC3339Nano) + "|" + strconv.FormatUint(seq, 16)))
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
