package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/schema"
)

// realFixtures loads testdata/real-events-2026-10-19.json: events taken
// from the EVIDENCE and EVENTS_RAW dumps of the 2026-10-19 kind-full live
// run (Falco ON, five sources, real workloads), trimmed (request bodies,
// cmdlines, user agents and source IPs removed) and redacted (no tokens).
// Story 10.12 AC3: every metric is tested against these real shapes.
type realFixtures struct {
	FalcoTokenReadFlatExe  schema.Event   `json:"falco_token_read_flat_exe"`
	FalcoK8sAPIWget        schema.Event   `json:"falco_k8s_api_wget"`
	FalcoDropAndExec       schema.Event   `json:"falco_drop_and_exec"`
	AuditOperatorExec      schema.Event   `json:"audit_operator_exec"`
	AuditOlaitanSelfLookup schema.Event   `json:"audit_olaitan_self_lookup"`
	CRIContainerCreated    schema.Event   `json:"cri_container_created"`
	CNIFlowsS4             []schema.Event `json:"cni_flows_s4"`
}

func loadReal(t *testing.T) realFixtures {
	t.Helper()
	b, err := os.ReadFile("testdata/real-events-2026-10-19.json")
	if err != nil {
		t.Fatalf("read fixtures: %v", err)
	}
	var fx realFixtures
	if err := json.Unmarshal(b, &fx); err != nil {
		t.Fatalf("decode fixtures: %v", err)
	}
	if len(fx.CNIFlowsS4) != 4 {
		t.Fatalf("fixture has %d S4 flows, want 4", len(fx.CNIFlowsS4))
	}
	return fx
}

// withRaw returns a copy of ev whose raw map has been edited by fn.
func withRaw(t *testing.T, ev schema.Event, fn func(map[string]any)) schema.Event {
	t.Helper()
	var raw map[string]any
	if err := json.Unmarshal(ev.Raw, &raw); err != nil {
		t.Fatalf("decode raw: %v", err)
	}
	fn(raw)
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("encode raw: %v", err)
	}
	out := ev
	out.Raw = b
	out.Tags = append([]string(nil), ev.Tags...)
	return out
}

// mainShapeFlow strips the Story 11.2b flat "network.*" projection,
// leaving the shape origin/main's CNI adapter publishes (protojson of the
// FlowResult under "flow").
func mainShapeFlow(t *testing.T, ev schema.Event) schema.Event {
	return withRaw(t, ev, func(raw map[string]any) {
		for k := range raw {
			if strings.HasPrefix(k, "network.") {
				delete(raw, k)
			}
		}
	})
}

func newTestTracker() *tracker {
	return &tracker{namespace: "tenant-acme", key: "Deployment-web", cur: newBucket(time.Unix(0, 0)), restarts: map[string]time.Time{}}
}

func noSelf(string) bool { return false }

func allLive(schema.EventSource) bool { return true }

func TestExecPath_RealFalcoShapes(t *testing.T) {
	fx := loadReal(t)
	cases := []struct {
		name string
		ev   schema.Event
		want string
	}{
		// 42 of 44 real Falco events: flat canonical key projected by
		// the adapter from proc.exepath. The pre-10.12 lookup split it
		// on "." and never found it.
		{"flat process.exe (token read)", fx.FalcoTokenReadFlatExe, "/bin/cat"},
		{"flat process.exe (k8s api)", fx.FalcoK8sAPIWget, "/bin/wget"},
		{"flat process.exe (drop and exec)", fx.FalcoDropAndExec, "/tmp/xmrig"},
		// An adapter without the projection: only output_fields, and
		// most rules print proc.exepath, not proc.exe.
		{"output_fields proc.exepath only", withRaw(t, fx.FalcoTokenReadFlatExe, func(r map[string]any) { delete(r, "process.exe") }), "/bin/cat"},
		{"output_fields proc.exe only", withRaw(t, fx.FalcoDropAndExec, func(r map[string]any) {
			delete(r, "process.exe")
			r["output_fields"] = [][2]string{{"proc.exe", "/tmp/xmrig"}}
		}), "/tmp/xmrig"},
		{"<NA> falls through to the next candidate", withRaw(t, fx.FalcoTokenReadFlatExe, func(r map[string]any) { r["process.exe"] = "<NA>" }), "/bin/cat"},
		// proc.name is a comm, not a path: never used.
		{"proc.name only is not an exec path", withRaw(t, fx.FalcoK8sAPIWget, func(r map[string]any) {
			delete(r, "process.exe")
			r["output_fields"] = [][2]string{{"proc.name", "wget"}}
		}), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := execPath(decodeRaw(&tc.ev)); got != tc.want {
				t.Fatalf("execPath = %q, want %q", got, tc.want)
			}
		})
	}
}

// The four real S4 flows: two Goldmane intervals, each reported by the
// source (Src) and by the destination (Dst) with bytes swapped. Only the
// Src reports are the workload's outbound traffic: 275 + 1323 bytes.
func TestFlows_RealShapes_BothAdapterVersions(t *testing.T) {
	fx := loadReal(t)
	for _, shape := range []struct {
		name string
		conv func(schema.Event) schema.Event
	}{
		{"11.2b flat network.* projection", func(e schema.Event) schema.Event { return e }},
		{"main nested flow.* protojson", func(e schema.Event) schema.Event { return mainShapeFlow(t, e) }},
	} {
		t.Run(shape.name, func(t *testing.T) {
			tr := newTestTracker()
			for _, f := range fx.CNIFlowsS4 {
				ev := shape.conv(f)
				tr.add(&ev, time.Unix(0, 0), noSelf)
			}
			s := tr.close(tr.cur, allLive)
			if got := s.values[MetricOutboundBytes]; got != 275+1323 {
				t.Errorf("outbound_bytes = %v, want %v (Src reports only)", got, 275+1323)
			}
			if got := s.values[MetricOutboundUniqueDst]; got != 1 {
				t.Errorf("outbound_unique_dst_ips = %v, want 1 (one destination endpoint)", got)
			}
		})
	}
}

func TestFlowDestination_RealShape(t *testing.T) {
	fx := loadReal(t)
	ev := fx.CNIFlowsS4[1] // Src report
	flat := flowDestination(decodeRaw(&ev))
	main := flowDestination(decodeRaw(func() *schema.Event { e := mainShapeFlow(t, ev); return &e }()))
	if flat == "" || main == "" {
		t.Fatalf("destination not found: flat=%q main=%q", flat, main)
	}
	for _, want := range []string{"s4-c2-sink-65cbd8c966-*", ":8443"} {
		if !strings.Contains(flat, want) || !strings.Contains(main, want) {
			t.Fatalf("destination flat=%q main=%q lacks %q", flat, main, want)
		}
	}
	// Different ports are different destinations.
	other := withRaw(t, ev, func(r map[string]any) { r["network.dst_port"] = "9999" })
	if flowDestination(decodeRaw(&other)) == flat {
		t.Fatal("a different destination port produced the same destination identity")
	}
}

func TestAudit_SelfActorIsNotWorkloadBehaviour(t *testing.T) {
	fx := loadReal(t)
	own := func(u string) bool { return serviceAccountNamespace(u) == "default" } // the release namespace on that run
	tr := newTestTracker()
	tr.add(&fx.AuditOperatorExec, time.Unix(0, 0), own)
	tr.add(&fx.AuditOlaitanSelfLookup, time.Unix(0, 0), own)
	if got := tr.close(tr.cur, allLive).values[MetricAuditEventsPerMin]; got != 1 {
		t.Fatalf("audit_events_per_min = %v, want 1 (the aggregator's own lookup is excluded)", got)
	}
	if ns := serviceAccountNamespace(auditActor(decodeRaw(&fx.AuditOlaitanSelfLookup))); ns != "default" {
		t.Fatalf("self-lookup actor namespace = %q, want default", ns)
	}
	if ns := serviceAccountNamespace("kubernetes-admin"); ns != "" {
		t.Fatalf("a user is not a ServiceAccount, got namespace %q", ns)
	}
}

// Redelivery of the same event (JetStream at-least-once) counts once.
func TestBucket_DedupesByEventID(t *testing.T) {
	fx := loadReal(t)
	tr := newTestTracker()
	for i := 0; i < 3; i++ {
		ev := fx.AuditOperatorExec
		tr.add(&ev, time.Unix(0, 0), noSelf)
		f := fx.CNIFlowsS4[1]
		tr.add(&f, time.Unix(0, 0), noSelf)
	}
	s := tr.close(tr.cur, allLive)
	if s.values[MetricAuditEventsPerMin] != 1 || s.values[MetricOutboundBytes] != 275 {
		t.Fatalf("redelivered events counted more than once: %+v", s.values)
	}
}

func TestRestarts_RealCRIShape(t *testing.T) {
	fx := loadReal(t)
	tr := newTestTracker()
	created := fx.CRIContainerCreated
	tr.add(&created, time.Unix(0, 0), noSelf)
	if s := tr.close(tr.cur, allLive); s.restart || s.values[MetricRestartsPerHour] != 0 {
		t.Fatalf("a first container creation (no attempt tag, as on the live run) is not a restart: %+v", s)
	}
	restarted := created
	restarted.ID = "restart-1"
	restarted.Tags = append(append([]string(nil), created.Tags...), "container_attempt:1")
	tr.cur = newBucket(time.Unix(60, 0))
	tr.add(&restarted, time.Unix(60, 0), noSelf)
	// The same restart reported again (created then started) counts once.
	again := restarted
	again.ID = "restart-1-started"
	tr.add(&again, time.Unix(61, 0), noSelf)
	s := tr.close(tr.cur, allLive)
	if !s.restart || s.values[MetricRestartsPerHour] != 1 {
		t.Fatalf("in-place restart: restart=%v restarts/h=%v, want true and 1", s.restart, s.values[MetricRestartsPerHour])
	}
	// The STOPPED event of the restarted container (it carries the same
	// tag) and a DELETED one an hour later are not new restarts.
	tr.cur = newBucket(time.Unix(3960, 0))
	for i, ty := range []string{"event_type:stopped", "event_type:deleted"} {
		ev := restarted
		ev.ID = fmt.Sprintf("later-%d", i)
		ev.Tags = []string{ty, "container_attempt:1"}
		tr.add(&ev, time.Unix(4000, 0), noSelf)
	}
	if tr.cur.restart {
		t.Fatal("a stopped or deleted event counted as a restart")
	}
	// One hour later the restart has left the trailing window.
	b := newBucket(time.Unix(60+3600, 0))
	if got := tr.close(b, allLive).values[MetricRestartsPerHour]; got != 0 {
		t.Fatalf("restarts/h an hour later = %v, want 0", got)
	}
}

func TestClose_OnlyLiveSourcesAreSampled(t *testing.T) {
	tr := newTestTracker()
	s := tr.close(tr.cur, func(src schema.EventSource) bool { return src == schema.SourceAudit })
	if len(s.values) != 1 {
		t.Fatalf("sampled %v, want only audit_events_per_min", s.values)
	}
	if v, ok := s.values[MetricAuditEventsPerMin]; !ok || v != 0 {
		t.Fatalf("an idle minute of a live source is a real zero, got %v present=%v", v, ok)
	}
}

func TestEffectiveStdDev_Floors(t *testing.T) {
	cases := []struct {
		metric          string
		std, mean, want float64
	}{
		{MetricAuditEventsPerMin, 0, 0.67, 2},
		{MetricAuditEventsPerMin, 2.5, 0.67, 2.5},
		{MetricOutboundUniqueDst, 0, 0.67, 1},
		{MetricAuditEventsPerMin, 0.2, 50, 5},
		{MetricOutboundBytes, 10, 100, 1024},
		{MetricDistinctExecPaths, 0, 1, 1},
	}
	for _, c := range cases {
		if got := effectiveStdDev(c.metric, c.std, c.mean); got != c.want {
			t.Errorf("effectiveStdDev(%s, %v, %v) = %v, want %v", c.metric, c.std, c.mean, got, c.want)
		}
	}
}

func TestMetricNames_IsStableSet(t *testing.T) {
	want := []string{"outbound_unique_dst_ips", "distinct_exec_paths", "outbound_bytes", "audit_events_per_min", "container_restarts_per_hour"}
	got := MetricNames()
	if len(got) != len(want) {
		t.Fatalf("MetricNames = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("MetricNames = %v, want %v", got, want)
		}
		if _, ok := metricSource[want[i]]; !ok {
			t.Errorf("no source for %q", want[i])
		}
		if _, ok := stdFloor[want[i]]; !ok {
			t.Errorf("no std floor for %q", want[i])
		}
	}
}

func TestHasRestartAttemptTag(t *testing.T) {
	cases := []struct {
		tags []string
		want bool
	}{
		{[]string{"attempt:1"}, true},
		{[]string{"attempt:0"}, false},
		{[]string{"attempt:42"}, true},
		{[]string{"attempt:abc"}, false},
		{[]string{"foo:bar", "attempt:2"}, true},
		{[]string{"container_attempt:3"}, true},
		{[]string{"container_attempt:0"}, false},
		{[]string{"container_attempt:"}, false},
		// Story 1.17 C3/E2: a malformed tag must not short-circuit.
		{[]string{"attempt:abc", "attempt:1"}, true},
		{[]string{"attempt:abc", "container_attempt:1"}, true},
		{[]string{"attempt:abc", "attempt:0"}, false},
		{nil, false},
	}
	for _, c := range cases {
		if got := hasRestartAttemptTag(c.tags); got != c.want {
			t.Errorf("hasRestartAttemptTag(%v) = %v want %v", c.tags, got, c.want)
		}
	}
}

func TestNumberOf_RejectsNonFinite(t *testing.T) {
	for _, v := range []any{"NaN", "Inf", "-Inf", "abc", true, nil} {
		if _, ok := numberOf(v); ok {
			t.Errorf("numberOf(%v) accepted", v)
		}
	}
	if n, ok := numberOf("1323"); !ok || n != 1323 {
		t.Errorf("numberOf(\"1323\") = %v, %v", n, ok)
	}
}

// A recreated sandbox tags every event of the pod with attempt:N; the
// sandbox and each of its containers are one restart, not several.
func TestRestarts_SandboxRecreateCountsOnce(t *testing.T) {
	fx := loadReal(t)
	tr := newTestTracker()
	for i, cid := range []string{"c-app", "c-sidecar", "c-init"} {
		ev := withRaw(t, fx.CRIContainerCreated, func(r map[string]any) { r["container_id"] = cid })
		ev.ID = fmt.Sprintf("sb-%d", i)
		ev.Tags = []string{"event_type:created", "attempt:1"}
		tr.add(&ev, time.Unix(0, 0), noSelf)
	}
	if got := tr.close(tr.cur, allLive).values[MetricRestartsPerHour]; got != 1 {
		t.Fatalf("restarts/h after one sandbox recreate = %v, want 1", got)
	}
}
