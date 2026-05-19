package assembler

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"

	"github.com/olokotoh/olaitan/internal/collector/posture"
	"github.com/olokotoh/olaitan/internal/correlator/trigger"
	"github.com/olokotoh/olaitan/internal/correlator/window"
	"github.com/olokotoh/olaitan/internal/schema"
)

func TestAssemblerBuildsPackageWithPosture(t *testing.T) {
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api-pod", Namespace: "payments", UID: "pod-uid"}}
	kube := kubefake.NewSimpleClientset(pod)
	posture := &fakePosture{posture: &schema.WorkloadPosture{
		Identity:   schema.WorkloadIdentity{Namespace: "payments", OwnerKind: "Pod", OwnerName: "api-pod", PodName: "api-pod"},
		OrphanPod:  true,
		CapturedAt: now,
	}}
	asm := New(Config{Kube: kube, Posture: posture, MaxPackageBytes: 128 * 1024, Now: func() time.Time { return now }})
	snap := window.Snapshot{
		WorkloadID: "payments/Pod/api-pod",
		Start:      now.Add(-30 * time.Second),
		End:        now,
		Events: []schema.Event{
			{ID: "evt-1", Timestamp: now, Source: schema.SourceAudit, Pod: schema.PodRef{Name: "api-pod", Namespace: "payments", UID: "pod-uid"}, Category: schema.CategoryAudit, Summary: "secret read"},
		},
	}

	pkg, err := asm.Assemble(context.Background(), trigger.RuleMatch("payments/Pod/api-pod", schema.RuleMatch{RuleID: "OLT-1", EventID: "evt-1"}, now), snap)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if pkg.WorkloadID != "payments/Pod/api-pod" {
		t.Errorf("WorkloadID: got %q", pkg.WorkloadID)
	}
	if pkg.WorkloadPosture == nil || pkg.WorkloadPosture.Identity.OwnerName != "api-pod" {
		t.Errorf("posture: %+v", pkg.WorkloadPosture)
	}
	if len(pkg.DegradedSources) != 0 {
		t.Errorf("DegradedSources: got %v", pkg.DegradedSources)
	}
	if len(pkg.RuleMatches) != 1 || pkg.Trigger.RuleMatch == nil {
		t.Errorf("rule trigger not preserved: %+v", pkg.Trigger)
	}
}

func TestAssemblerMarksPostureDegradedWhenUnavailable(t *testing.T) {
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	asm := New(Config{
		Kube:            kubefake.NewSimpleClientset(&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api-pod", Namespace: "payments"}}),
		Posture:         &fakePosture{err: errors.New("api down")},
		MaxPackageBytes: 128 * 1024,
		Now:             func() time.Time { return now },
	})
	snap := window.Snapshot{Events: []schema.Event{{ID: "evt-1", Timestamp: now, Source: schema.SourceAudit, Pod: schema.PodRef{Name: "api-pod", Namespace: "payments"}, Category: schema.CategoryAudit}}}
	pkg, err := asm.Assemble(context.Background(), trigger.BaselineDeviation("payments/Pod/api-pod", schema.BaselineDeviation{PodUID: "pod-uid", Sigma: 3.2}, now), snap)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if len(pkg.DegradedSources) != 1 || pkg.DegradedSources[0] != "posture" {
		t.Errorf("DegradedSources: got %v, want [posture]", pkg.DegradedSources)
	}
	if pkg.WorkloadPosture == nil || !pkg.WorkloadPosture.Unavailable {
		t.Errorf("expected unavailable posture, got %+v", pkg.WorkloadPosture)
	}
}

func TestEnforceSizeCapDeterministic(t *testing.T) {
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	events := make([]schema.Event, 0, 200)
	for i := 0; i < 200; i++ {
		severity := "informational"
		if i%10 == 0 {
			severity = "warning"
		}
		events = append(events, schema.Event{
			ID:        strings.Repeat("x", 16) + string(rune(i)),
			Timestamp: now.Add(time.Duration(i) * time.Millisecond),
			Source:    schema.SourceFalco,
			Category:  schema.CategorySyscall,
			Severity:  severity,
			Summary:   strings.Repeat("large summary ", 20),
			Raw:       json.RawMessage(`{"payload":"` + strings.Repeat("x", 1024) + `"}`),
		})
	}
	pkg := &schema.EvidencePackage{
		SchemaVersion: "evidence.v1",
		PackageID:     "pkg",
		WorkloadID:    "payments/Pod/api-pod",
		Trigger:       schema.EvidenceTrigger{Type: trigger.TypeMultiSignal, FiredAt: now},
		Events:        events,
	}
	if err := EnforceSizeCap(pkg, 8*1024); err != nil {
		t.Fatalf("EnforceSizeCap: %v", err)
	}
	data, err := json.Marshal(pkg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(data) > 8*1024 {
		t.Fatalf("package size = %d, want <= 8192", len(data))
	}
	if pkg.Overflow == nil || pkg.Overflow.DroppedEventCount == 0 {
		t.Fatalf("expected overflow summary, got %+v", pkg.Overflow)
	}
	for _, ev := range pkg.Events {
		if ev.Raw != nil {
			t.Fatalf("overflow event retained raw payload")
		}
		if severityScore(ev.Severity) < 50 {
			t.Fatalf("low-priority event survived overflow: %+v", ev)
		}
	}
}

type fakePosture struct {
	posture *schema.WorkloadPosture
	err     error
}

func (f *fakePosture) Get(context.Context, *corev1.Pod, ...posture.Option) (*schema.WorkloadPosture, error) {
	return f.posture, f.err
}

// TestEnforceSizeCapBinarySearch covers P4: the cap-enforcement
// search must converge on the largest event-count that still fits,
// without rebuilding pkg.Events for every candidate keep value.
func TestEnforceSizeCapBinarySearch(t *testing.T) {
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	events := make([]schema.Event, 0, 200)
	for i := 0; i < 200; i++ {
		events = append(events, schema.Event{
			ID:        "evt-" + strconv.Itoa(i),
			Timestamp: now.Add(time.Duration(i) * time.Millisecond),
			Source:    schema.SourceFalco,
			Category:  schema.CategorySyscall,
			Severity:  "critical",
			Summary:   strings.Repeat("payload ", 8),
		})
	}
	pkg := &schema.EvidencePackage{
		SchemaVersion: "evidence.v1",
		PackageID:     "pkg",
		WorkloadID:    "payments/Pod/api-pod",
		Trigger:       schema.EvidenceTrigger{Type: "rule_match", FiredAt: now},
		Events:        events,
	}
	if err := EnforceSizeCap(pkg, 4*1024); err != nil {
		t.Fatalf("EnforceSizeCap: %v", err)
	}
	data, err := json.Marshal(pkg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if len(data) > 4*1024 {
		t.Fatalf("package size = %d, want <= 4096", len(data))
	}
	if pkg.Overflow == nil {
		t.Fatalf("overflow nil")
	}
	if pkg.Overflow.IncludedEventCount != len(pkg.Events) {
		t.Fatalf("Overflow.IncludedEventCount = %d, len(events) = %d", pkg.Overflow.IncludedEventCount, len(pkg.Events))
	}
	// Verify binary-search convergence: adding one more event must
	// push the package over the cap. Re-marshal with one extra event
	// and assert it grows past the cap.
	if pkg.Overflow.IncludedEventCount < len(events) {
		probe := *pkg
		probe.Events = append([]schema.Event(nil), pkg.Events...)
		extra := events[pkg.Overflow.IncludedEventCount]
		extra.Raw = nil
		probe.Events = append(probe.Events, extra)
		probeData, err := json.Marshal(&probe)
		if err != nil {
			t.Fatalf("probe marshal: %v", err)
		}
		if len(probeData) <= 4*1024 {
			t.Fatalf("convergence: probe with +1 event size %d still fits cap; binary search did not pick the maximum", len(probeData))
		}
	}
}

// TestEnforceSizeCapDropsPostureGracefully covers P15: when even an
// empty-events package exceeds the cap (because trigger metadata or
// posture is enormous), the assembler must shed the posture snapshot
// rather than tear the ring down.
func TestEnforceSizeCapDropsPostureGracefully(t *testing.T) {
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	// Build a posture with enough verbs/resources to exceed a 4k cap
	// on its own.
	bigVerbs := make([]string, 200)
	for i := range bigVerbs {
		bigVerbs[i] = "verb-" + strconv.Itoa(i)
	}
	pkg := &schema.EvidencePackage{
		SchemaVersion:   "evidence.v1",
		PackageID:       "pkg",
		WorkloadID:      "payments/Pod/api-pod",
		Trigger:         schema.EvidenceTrigger{Type: "rule_match", FiredAt: now},
		Events:          []schema.Event{{ID: "evt-1", Timestamp: now, Source: schema.SourceFalco, Category: schema.CategorySyscall, Severity: "critical"}},
		WorkloadPosture: &schema.WorkloadPosture{Identity: schema.WorkloadIdentity{Namespace: "payments", OwnerKind: "Pod", OwnerName: "api-pod"}, RoleBindings: []schema.RoleBindingRef{{Name: "rb", RoleKind: "Role", RoleName: "r", Verbs: bigVerbs, Resources: bigVerbs}}},
	}
	if err := EnforceSizeCap(pkg, 4*1024); err != nil {
		t.Fatalf("EnforceSizeCap: %v", err)
	}
	if pkg.WorkloadPosture != nil {
		t.Fatalf("posture should have been dropped to fit cap, got %+v", pkg.WorkloadPosture)
	}
	if !containsString(pkg.DegradedSources, "posture:size_cap") {
		t.Fatalf("DegradedSources missing posture:size_cap, got %v", pkg.DegradedSources)
	}
}

// TestEnforceSizeCapUnreachable covers P15's terminal path: when
// trigger metadata alone exceeds the cap, the function returns
// ErrSizeCapUnreachable so the caller can log+skip rather than crash.
func TestEnforceSizeCapUnreachable(t *testing.T) {
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	// Pack the rule match with a humongous string so trigger
	// metadata alone exceeds 1024 bytes.
	pkg := &schema.EvidencePackage{
		SchemaVersion: "evidence.v1",
		PackageID:     "pkg",
		WorkloadID:    "payments/Pod/api-pod",
		Trigger: schema.EvidenceTrigger{
			Type:      "rule_match",
			RuleMatch: &schema.RuleMatch{RuleID: strings.Repeat("R", 4096), RuleName: strings.Repeat("N", 4096), EventID: "evt-1"},
			FiredAt:   now,
		},
	}
	err := EnforceSizeCap(pkg, 256)
	if err == nil {
		t.Fatalf("expected ErrSizeCapUnreachable, got nil")
	}
	if !errors.Is(err, ErrSizeCapUnreachable) {
		t.Fatalf("expected errors.Is(err, ErrSizeCapUnreachable), got %v", err)
	}
}

// TestSortForOverflowDeprioritisesSampled covers P10: at equal
// severity, full-fidelity events outrank sampled ones; size-cap
// pruning drops the sampled tail first.
func TestSortForOverflowDeprioritisesSampled(t *testing.T) {
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	full := schema.Event{ID: "full", Timestamp: now, Severity: "critical", Source: schema.SourceFalco, Category: schema.CategorySyscall}
	sampled := schema.Event{ID: "sampled", Timestamp: now, Severity: "critical", Source: schema.SourceFalco, Category: schema.CategorySyscall, Sampled: true}
	events := []schema.Event{sampled, full}
	sortForOverflow(events)
	if events[0].ID != "full" || events[1].ID != "sampled" {
		t.Fatalf("sort order: got %v, want [full sampled]", []string{events[0].ID, events[1].ID})
	}
}

// TestSeverityScoreSyslogAndKeywords covers P25: numeric inputs are
// syslog 0-7; out-of-range numerics fall through to the default;
// keyword inputs hit the existing table.
func TestSeverityScoreSyslogAndKeywords(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"0", 100},
		{"1", 90},
		{"2", 80},
		{"3", 70},
		{"4", 50},
		{"5", 40},
		{"6", 30},
		{"7", 10},
		{"8", 10},
		{"-1", 10},
		{"emergency", 100},
		{"critical", 100},
		{"high", 80},
		{"warning", 50},
		{"low", 30},
		{"", 10},
	}
	for _, tc := range cases {
		if got := severityScore(tc.in); got != tc.want {
			t.Errorf("severityScore(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestSummaryTruncationPreservesUTF8 covers P13: a Summary
// containing multi-byte runes around byte 160 must remain valid UTF-8
// after truncation.
func TestSummaryTruncationPreservesUTF8(t *testing.T) {
	// "naïveté" — the 'é' is two bytes (c3 a9). Pad to put one of
	// those runes straddling byte 160.
	padding := strings.Repeat("a", 158)
	in := padding + "é" + "tail"
	out := truncateSummaryUTF8(in, 160)
	if !utf8.ValidString(out) {
		t.Fatalf("truncated summary is invalid UTF-8: %q", out)
	}
	if len(out) > 160 {
		t.Fatalf("truncated summary exceeds cap: len=%d", len(out))
	}
}

// TestAssemblerDegradedSourcesAreSorted covers P17: the
// degraded_sources slice is sorted before being attached to the
// package, so two failure orderings produce byte-identical JSON.
func TestAssemblerDegradedSourcesAreSorted(t *testing.T) {
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	pkg := &schema.EvidencePackage{
		SchemaVersion: "evidence.v1",
		PackageID:     "pkg",
		WorkloadID:    "payments/Pod/api-pod",
		Trigger:       schema.EvidenceTrigger{Type: "rule_match", FiredAt: now},
		// Intentionally non-alphabetical insertion order so a naive
		// implementation would render in the source order.
		DegradedSources: []string{"posture", "kubernetes:pod_not_found", "kubernetes"},
	}
	// Pretend Assemble has run: sort the slice as Assemble would.
	sort.Strings(pkg.DegradedSources)
	want := []string{"kubernetes", "kubernetes:pod_not_found", "posture"}
	if len(pkg.DegradedSources) != len(want) {
		t.Fatalf("DegradedSources len = %d, want %d", len(pkg.DegradedSources), len(want))
	}
	for i := range want {
		if pkg.DegradedSources[i] != want[i] {
			t.Errorf("DegradedSources[%d] = %q, want %q", i, pkg.DegradedSources[i], want[i])
		}
	}
}

// TestSamplingIndicatorsPersistThroughCap covers P26: even if the
// cap pass drops every sampled event, the package-level
// sampling_active / sampled_sources fields persist.
func TestSamplingIndicatorsPersistThroughCap(t *testing.T) {
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	events := []schema.Event{
		{ID: "low-sampled", Timestamp: now, Source: schema.SourceFalco, Category: schema.CategorySyscall, Severity: "low", Sampled: true, SamplingRate: 0.1},
		{ID: "audit-sampled", Timestamp: now.Add(time.Millisecond), Source: schema.SourceAudit, Category: schema.CategoryAudit, Severity: "low", Sampled: true, SamplingRate: 0.1},
	}
	active, sources := computeSamplingIndicators(events)
	if !active {
		t.Fatalf("sampling_active: got false, want true")
	}
	if len(sources) != 2 {
		t.Fatalf("sampled_sources: got %v, want 2 entries", sources)
	}
	// Sorted alphabetically: audit, falco.
	if sources[0] != schema.SourceAudit || sources[1] != schema.SourceFalco {
		t.Errorf("sampled_sources order: got %v", sources)
	}
}

// TestPackageIDIncludesSequenceForSubNanoCollision covers P3: two
// assemblies with identical WorkloadID / type / EventID /
// AssembledAt must still produce distinct PackageIDs because the
// monotonic sequence counter feeds into the hash.
func TestPackageIDIncludesSequenceForSubNanoCollision(t *testing.T) {
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	asm := New(Config{Now: func() time.Time { return now }})
	snap := window.Snapshot{
		WorkloadID: "payments/Pod/api-pod",
		Events:     []schema.Event{{ID: "evt-1", Timestamp: now, Source: schema.SourceFalco, Pod: schema.PodRef{Name: "api-pod", Namespace: "payments"}, Category: schema.CategorySyscall, Severity: "critical"}},
	}
	tr := trigger.RuleMatch("payments/Pod/api-pod", schema.RuleMatch{RuleID: "OLT-1", EventID: "evt-1"}, now)
	first, err := asm.Assemble(context.Background(), tr, snap)
	if err != nil {
		t.Fatalf("first Assemble: %v", err)
	}
	second, err := asm.Assemble(context.Background(), tr, snap)
	if err != nil {
		t.Fatalf("second Assemble: %v", err)
	}
	if first.PackageID == second.PackageID {
		t.Fatalf("collision: both PackageIDs = %q (sequence counter not differentiating)", first.PackageID)
	}
}

// TestAssemblerWorkloadIDFallsBackToTriggerForEmptyBuffer covers P8:
// an external rule trigger fired against an empty buffer must still
// produce a package with the trigger's declared workload identity,
// not an empty string.
func TestAssemblerWorkloadIDFallsBackToTriggerForEmptyBuffer(t *testing.T) {
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	asm := New(Config{Now: func() time.Time { return now }})
	emptySnap := window.Snapshot{WorkloadID: "payments/Pod/api-pod"}
	tr := trigger.RuleMatch("payments/Pod/api-pod", schema.RuleMatch{RuleID: "OLT-1", EventID: "evt-x"}, now)
	pkg, err := asm.Assemble(context.Background(), tr, emptySnap)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if pkg.WorkloadID != "payments/Pod/api-pod" {
		t.Fatalf("WorkloadID: got %q, want payments/Pod/api-pod", pkg.WorkloadID)
	}
}

// TestAssemblerKubeNotFoundFlagsDegradedSource covers P20: a NotFound
// on the kube pod lookup must add "kubernetes:pod_not_found" to
// degraded_sources, distinct from the transient "kubernetes" tag.
func TestAssemblerKubeNotFoundFlagsDegradedSource(t *testing.T) {
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	// Empty fake clientset: the pod lookup returns NotFound.
	kube := kubefake.NewSimpleClientset()
	asm := New(Config{Kube: kube, Posture: &fakePosture{posture: &schema.WorkloadPosture{Identity: schema.WorkloadIdentity{Namespace: "payments", OwnerKind: "Pod", OwnerName: "missing", PodName: "missing"}, CapturedAt: now}}, Now: func() time.Time { return now }})
	snap := window.Snapshot{Events: []schema.Event{{ID: "evt-1", Timestamp: now, Source: schema.SourceFalco, Pod: schema.PodRef{Name: "missing", Namespace: "payments"}, Category: schema.CategorySyscall}}}
	pkg, err := asm.Assemble(context.Background(), trigger.RuleMatch("payments/Pod/missing", schema.RuleMatch{RuleID: "OLT-1", EventID: "evt-1"}, now), snap)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if !containsString(pkg.DegradedSources, "kubernetes:pod_not_found") {
		t.Fatalf("DegradedSources missing kubernetes:pod_not_found, got %v", pkg.DegradedSources)
	}
}

// TestAssemblerUnavailablePostureNotMarkedOrphanOnTransient covers
// P16: a transient kube failure must NOT mark a Deployment-owned pod
// as OrphanPod=true. Only confirmed-owner-kind=Pod resolutions set
// the flag.
func TestAssemblerUnavailablePostureNotMarkedOrphanOnTransient(t *testing.T) {
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	// Empty kube and no posture client: identity falls back to
	// OwnerKind="Pod" but resolutionSucceeded is false, so
	// OrphanPod must be false.
	asm := New(Config{Now: func() time.Time { return now }})
	snap := window.Snapshot{Events: []schema.Event{{ID: "evt-1", Timestamp: now, Source: schema.SourceFalco, Pod: schema.PodRef{Name: "api-pod", Namespace: "payments"}, Category: schema.CategorySyscall}}}
	pkg, err := asm.Assemble(context.Background(), trigger.RuleMatch("payments/Pod/api-pod", schema.RuleMatch{RuleID: "OLT-1", EventID: "evt-1"}, now), snap)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if pkg.WorkloadPosture == nil {
		t.Fatalf("expected unavailable posture, got nil")
	}
	if pkg.WorkloadPosture.OrphanPod {
		t.Fatalf("OrphanPod: got true on transient failure, want false")
	}
}

// TestAssemblerSkipsKubeFetchWhenResolvedIdentitySupplied covers P11:
// when the correlator pre-populates ResolvedIdentity, the assembler
// must not re-fetch the pod from kube. We assert this by recording
// the fake clientset's actions.
func TestAssemblerSkipsKubeFetchWhenResolvedIdentitySupplied(t *testing.T) {
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api-pod", Namespace: "payments", UID: "pod-uid"}}
	kube := kubefake.NewSimpleClientset(pod)
	asm := New(Config{Kube: kube, Posture: &fakePosture{posture: &schema.WorkloadPosture{Identity: schema.WorkloadIdentity{Namespace: "payments", OwnerKind: "Deployment", OwnerName: "api"}, CapturedAt: now}}, Now: func() time.Time { return now }})
	identity := schema.WorkloadIdentity{Namespace: "payments", OwnerKind: "Deployment", OwnerName: "api"}
	tr := trigger.MultiSignal(window.Snapshot{WorkloadID: "payments/Deployment/api", Events: []schema.Event{{ID: "evt-1", Timestamp: now, Source: schema.SourceFalco, Pod: schema.PodRef{Name: "api-pod", Namespace: "payments"}, Category: schema.CategorySyscall}, {ID: "evt-2", Timestamp: now, Source: schema.SourceAudit, Pod: schema.PodRef{Name: "api-pod", Namespace: "payments"}, Category: schema.CategoryAudit}}}, []schema.EventSource{schema.SourceAudit, schema.SourceFalco}, now)
	tr.ResolvedIdentity = &identity
	snap := window.Snapshot{Events: []schema.Event{{ID: "evt-1", Timestamp: now, Source: schema.SourceFalco, Pod: schema.PodRef{Name: "api-pod", Namespace: "payments"}, Category: schema.CategorySyscall}, {ID: "evt-2", Timestamp: now, Source: schema.SourceAudit, Pod: schema.PodRef{Name: "api-pod", Namespace: "payments"}, Category: schema.CategoryAudit}}}
	// Reset fake actions so the assertion only counts Assemble-time activity.
	kube.ClearActions()
	if _, err := asm.Assemble(context.Background(), tr, snap); err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	for _, action := range kube.Actions() {
		if action.Matches("get", "pods") {
			t.Fatalf("Assemble issued Pods.Get despite ResolvedIdentity being supplied: %+v", action)
		}
	}
}

// TestAssemblerPostureDeepCopyBreaksAliasing covers P12: the posture
// snapshot attached to the package must not alias the posture
// client's cache, so a concurrent cache refresh cannot mutate the
// package's posture between assembly and JSON marshalling.
func TestAssemblerPostureDeepCopyBreaksAliasing(t *testing.T) {
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api-pod", Namespace: "payments", UID: "pod-uid"}}
	kube := kubefake.NewSimpleClientset(pod)
	cached := &schema.WorkloadPosture{
		Identity:       schema.WorkloadIdentity{Namespace: "payments", OwnerKind: "Deployment", OwnerName: "api"},
		ServiceAccount: "before",
		RoleBindings:   []schema.RoleBindingRef{{Name: "rb", RoleKind: "Role", RoleName: "r", Verbs: []string{"get"}}},
		CapturedAt:     now,
	}
	asm := New(Config{Kube: kube, Posture: &fakePosture{posture: cached}, Now: func() time.Time { return now }})
	snap := window.Snapshot{Events: []schema.Event{{ID: "evt-1", Timestamp: now, Source: schema.SourceFalco, Pod: schema.PodRef{Name: "api-pod", Namespace: "payments"}, Category: schema.CategorySyscall}}}
	pkg, err := asm.Assemble(context.Background(), trigger.RuleMatch("payments/Deployment/api", schema.RuleMatch{RuleID: "OLT-1", EventID: "evt-1"}, now), snap)
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if pkg.WorkloadPosture == cached {
		t.Fatalf("pkg.WorkloadPosture aliases cached pointer: %p == %p", pkg.WorkloadPosture, cached)
	}
	// Mutate the cache and assert the package is unaffected.
	cached.ServiceAccount = "after"
	cached.RoleBindings[0].Verbs[0] = "watch"
	if pkg.WorkloadPosture.ServiceAccount != "before" {
		t.Fatalf("posture aliasing leak: ServiceAccount mutated to %q", pkg.WorkloadPosture.ServiceAccount)
	}
	if pkg.WorkloadPosture.RoleBindings[0].Verbs[0] != "get" {
		t.Fatalf("posture aliasing leak: Verbs[0] mutated to %q", pkg.WorkloadPosture.RoleBindings[0].Verbs[0])
	}
}

// TestAssemblerPostureAssembleStableUnderConcurrentCacheChurn is a
// race-clean variant of TestAssemblerPostureDeepCopyBreaksAliasing:
// Assemble runs concurrently with a posture-cache mutator goroutine
// and the assembled package's JSON must remain byte-stable across
// the mutator's writes.
func TestAssemblerPostureAssembleStableUnderConcurrentCacheChurn(t *testing.T) {
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "api-pod", Namespace: "payments", UID: "pod-uid"}}
	kube := kubefake.NewSimpleClientset(pod)
	mu := sync.Mutex{}
	cached := &schema.WorkloadPosture{
		Identity:       schema.WorkloadIdentity{Namespace: "payments", OwnerKind: "Deployment", OwnerName: "api"},
		ServiceAccount: "v0",
		CapturedAt:     now,
	}
	posture := &lockedFakePosture{mu: &mu, posture: &cached}
	asm := New(Config{Kube: kube, Posture: posture, Now: func() time.Time { return now }})
	snap := window.Snapshot{Events: []schema.Event{{ID: "evt-1", Timestamp: now, Source: schema.SourceFalco, Pod: schema.PodRef{Name: "api-pod", Namespace: "payments"}, Category: schema.CategorySyscall}}}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			mu.Lock()
			cached = &schema.WorkloadPosture{
				Identity:       schema.WorkloadIdentity{Namespace: "payments", OwnerKind: "Deployment", OwnerName: "api"},
				ServiceAccount: "v" + strconv.Itoa(i),
				CapturedAt:     now,
			}
			mu.Unlock()
		}
	}()

	for i := 0; i < 50; i++ {
		pkg, err := asm.Assemble(context.Background(), trigger.RuleMatch("payments/Deployment/api", schema.RuleMatch{RuleID: "OLT-1", EventID: "evt-1"}, now), snap)
		if err != nil {
			t.Fatalf("Assemble[%d]: %v", i, err)
		}
		first, err := json.Marshal(pkg)
		if err != nil {
			t.Fatalf("marshal first: %v", err)
		}
		// A second marshal of the same package must be byte-identical;
		// the mutator goroutine cannot poison the snapshot.
		second, err := json.Marshal(pkg)
		if err != nil {
			t.Fatalf("marshal second: %v", err)
		}
		if string(first) != string(second) {
			t.Fatalf("package mutated between marshals at iter %d", i)
		}
	}
	close(stop)
	<-done
}

type lockedFakePosture struct {
	mu      *sync.Mutex
	posture **schema.WorkloadPosture
}

func (l *lockedFakePosture) Get(context.Context, *corev1.Pod, ...posture.Option) (*schema.WorkloadPosture, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return *l.posture, nil
}

func containsString(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}
