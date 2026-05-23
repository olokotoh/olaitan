package baseline

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/schema"
)

func mustRaw(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal raw: %v", err)
	}
	return json.RawMessage(b)
}

func flowEvent(t *testing.T, dstIP string, bytesOut float64) schema.Event {
	t.Helper()
	raw := map[string]any{}
	if dstIP != "" {
		raw["dst_ip"] = dstIP
	}
	if bytesOut >= 0 {
		raw["bytes_out"] = bytesOut
	}
	return schema.Event{
		ID:       "evt-flow-" + dstIP,
		Source:   schema.SourceNetwork,
		Category: schema.CategoryFlow,
		Raw:      mustRaw(t, raw),
	}
}

func falcoEvent(t *testing.T, procExe string) schema.Event {
	t.Helper()
	raw := map[string]any{
		"output_fields": [][2]string{
			{"proc.exe", procExe},
			{"evt.uuid", "uid-" + procExe},
		},
	}
	return schema.Event{
		ID:       "evt-falco-" + procExe,
		Source:   schema.SourceFalco,
		Category: schema.CategorySyscall,
		Raw:      mustRaw(t, raw),
	}
}

func auditEvent(t *testing.T) schema.Event {
	t.Helper()
	return schema.Event{
		ID:       "evt-audit",
		Source:   schema.SourceAudit,
		Category: schema.CategoryAudit,
		Raw:      mustRaw(t, map[string]any{"verb": "list"}),
	}
}

func lifecycleEvent(t *testing.T, attempt int) schema.Event {
	t.Helper()
	tag := "attempt:0"
	if attempt > 0 {
		tag = "attempt:" + itoa(attempt)
	}
	return schema.Event{
		ID:       "evt-lifecycle",
		Source:   schema.SourceRuntime,
		Category: schema.CategoryLifecycle,
		Tags:     []string{tag},
		Raw:      mustRaw(t, map[string]any{}),
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	digits := []byte{}
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	return string(digits)
}

func windowed(events []schema.Event, mins float64) *schema.EvidencePackage {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Duration(mins) * time.Minute)
	return &schema.EvidencePackage{
		WindowStart: start,
		WindowEnd:   end,
		Events:      events,
	}
}

func TestExtract_OutboundUniqueDstIPs(t *testing.T) {
	tests := []struct {
		name        string
		events      []schema.Event
		wantValue   float64
		wantPresent bool
	}{
		{"no network events", []schema.Event{auditEvent(t)}, 0, false},
		{"single dst", []schema.Event{flowEvent(t, "10.0.0.1", -1)}, 1, true},
		{"three unique dsts", []schema.Event{flowEvent(t, "10.0.0.1", -1), flowEvent(t, "10.0.0.2", -1), flowEvent(t, "10.0.0.3", -1)}, 3, true},
		{"three events but two unique", []schema.Event{flowEvent(t, "10.0.0.1", -1), flowEvent(t, "10.0.0.2", -1), flowEvent(t, "10.0.0.1", -1)}, 2, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg := windowed(tt.events, 1)
			got, present := extractOutboundUniqueDstIPs(pkg)
			if present != tt.wantPresent {
				t.Errorf("present=%v want %v", present, tt.wantPresent)
			}
			if got != tt.wantValue {
				t.Errorf("value=%v want %v", got, tt.wantValue)
			}
		})
	}
}

func TestExtract_DistinctExecPaths(t *testing.T) {
	tests := []struct {
		name        string
		events      []schema.Event
		wantValue   float64
		wantPresent bool
	}{
		{"no falco events", []schema.Event{flowEvent(t, "10.0.0.1", -1)}, 0, false},
		{"one falco event one exe", []schema.Event{falcoEvent(t, "/bin/sh")}, 1, true},
		{"three falco events three exe", []schema.Event{falcoEvent(t, "/bin/sh"), falcoEvent(t, "/usr/bin/curl"), falcoEvent(t, "/usr/bin/wget")}, 3, true},
		{"three events two unique", []schema.Event{falcoEvent(t, "/bin/sh"), falcoEvent(t, "/usr/bin/curl"), falcoEvent(t, "/bin/sh")}, 2, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg := windowed(tt.events, 1)
			got, present := extractDistinctExecPaths(pkg)
			if present != tt.wantPresent {
				t.Errorf("present=%v want %v", present, tt.wantPresent)
			}
			if got != tt.wantValue {
				t.Errorf("value=%v want %v", got, tt.wantValue)
			}
		})
	}
}

func TestExtract_OutboundBytes(t *testing.T) {
	tests := []struct {
		name        string
		events      []schema.Event
		wantValue   float64
		wantPresent bool
	}{
		{"no network events", []schema.Event{auditEvent(t)}, 0, false},
		{"network event without bytes_out", []schema.Event{flowEvent(t, "10.0.0.1", -1)}, 0, false},
		{"single flow with 1024 bytes", []schema.Event{flowEvent(t, "10.0.0.1", 1024)}, 1024, true},
		{"two flows sum", []schema.Event{flowEvent(t, "10.0.0.1", 100), flowEvent(t, "10.0.0.2", 50)}, 150, true},
		{"zero-byte flow still present", []schema.Event{flowEvent(t, "10.0.0.1", 0)}, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg := windowed(tt.events, 1)
			got, present := extractOutboundBytes(pkg)
			if present != tt.wantPresent {
				t.Errorf("present=%v want %v", present, tt.wantPresent)
			}
			if got != tt.wantValue {
				t.Errorf("value=%v want %v", got, tt.wantValue)
			}
		})
	}
}

func TestExtract_AuditEventsPerMin(t *testing.T) {
	tests := []struct {
		name        string
		events      []schema.Event
		mins        float64
		wantValue   float64
		wantPresent bool
	}{
		{"no audit events", []schema.Event{flowEvent(t, "10.0.0.1", -1)}, 1, 0, false},
		{"two audit events over 1 minute", []schema.Event{auditEvent(t), auditEvent(t)}, 1, 2, true},
		{"four audit events over 2 minutes", []schema.Event{auditEvent(t), auditEvent(t), auditEvent(t), auditEvent(t)}, 2, 2, true},
		{"zero-length window is not present", []schema.Event{auditEvent(t)}, 0, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg := windowed(tt.events, tt.mins)
			got, present := extractAuditEventsPerMin(pkg)
			if present != tt.wantPresent {
				t.Errorf("present=%v want %v", present, tt.wantPresent)
			}
			if got != tt.wantValue {
				t.Errorf("value=%v want %v", got, tt.wantValue)
			}
		})
	}
}

func TestExtract_ContainerRestartsPerHour(t *testing.T) {
	tests := []struct {
		name        string
		events      []schema.Event
		mins        float64
		wantValue   float64
		wantPresent bool
	}{
		{"no lifecycle events", []schema.Event{flowEvent(t, "10.0.0.1", -1)}, 60, 0, false},
		{"single restart over 60 mins", []schema.Event{lifecycleEvent(t, 1)}, 60, 1, true},
		{"three restarts over 60 mins", []schema.Event{lifecycleEvent(t, 1), lifecycleEvent(t, 2), lifecycleEvent(t, 3)}, 60, 3, true},
		{"attempt:0 not a restart", []schema.Event{lifecycleEvent(t, 0)}, 60, 0, false},
		{"zero-length window is not present", []schema.Event{lifecycleEvent(t, 1)}, 0, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg := windowed(tt.events, tt.mins)
			got, present := extractContainerRestartsPerHour(pkg)
			if present != tt.wantPresent {
				t.Errorf("present=%v want %v", present, tt.wantPresent)
			}
			if got != tt.wantValue {
				t.Errorf("value=%v want %v", got, tt.wantValue)
			}
		})
	}
}

func TestMetricNames_IsStableSet(t *testing.T) {
	names := MetricNames()
	if len(names) != 5 {
		t.Errorf("MetricNames len=%d want 5", len(names))
	}
	wantSet := map[string]bool{
		"outbound_unique_dst_ips":     true,
		"distinct_exec_paths":         true,
		"outbound_bytes":              true,
		"audit_events_per_min":        true,
		"container_restarts_per_hour": true,
	}
	for _, n := range names {
		if !wantSet[n] {
			t.Errorf("unexpected metric %q", n)
		}
	}
}

func TestDefaultExtractors_AllPresent(t *testing.T) {
	reg := DefaultExtractors()
	for _, n := range MetricNames() {
		if reg[n] == nil {
			t.Errorf("missing extractor for %q", n)
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
		{nil, false},
	}
	for _, c := range cases {
		if got := hasRestartAttemptTag(c.tags); got != c.want {
			t.Errorf("hasRestartAttemptTag(%v) = %v want %v", c.tags, got, c.want)
		}
	}
}
