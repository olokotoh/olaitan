package redact

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/olokotoh/olaitan/internal/schema"
)

// schemaDir is the committed JSON-Schema home, relative to this package.
const schemaDir = "../../../docs/schemas/audit"

// captureSink is a capturing AuditRedactionPublisher fake (no real NATS).
type captureSink struct {
	mu       sync.Mutex
	captured []AuditRedaction
	failNext bool
}

func (c *captureSink) PublishAuditRedaction(_ context.Context, evt AuditRedaction) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failNext {
		return context.DeadlineExceeded
	}
	c.captured = append(c.captured, evt)
	return nil
}

func (c *captureSink) events() []AuditRedaction {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]AuditRedaction, len(c.captured))
	copy(out, c.captured)
	return out
}

func TestAuditRedaction_RoundTrip(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	evt := RedactionEvent{FieldPath: "events[0].raw.API_KEY", Reason: ReasonSecretPattern, WorkloadID: "ns/Deployment/web", RedactedAt: now}
	ar := auditFromEvent(evt, "pkg-1", now.Add(time.Second))
	b, err := json.Marshal(ar)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := map[string]struct{}{
		"schema_version": {}, "package_id": {}, "field_path": {}, "reason": {},
		"workload_id": {}, "redacted_at": {}, "published_at": {},
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected field on wire: %q", k)
		}
	}
	if got["schema_version"] != SchemaVersionRedactions {
		t.Errorf("schema_version = %v", got["schema_version"])
	}
	// NFR18: no value/before field of any kind.
	for _, forbidden := range []string{"value", "before", "secret", "redacted_value"} {
		if _, ok := got[forbidden]; ok {
			t.Errorf("forbidden secret-bearing field %q on wire (NFR18)", forbidden)
		}
	}
}

func TestAuditRedaction_OmitsZeroWorkloadID(t *testing.T) {
	now := time.Now().UTC()
	evt := RedactionEvent{FieldPath: "events[0].raw.x", Reason: ReasonRawPayload, RedactedAt: now}
	b, err := json.Marshal(auditFromEvent(evt, "pkg-1", now))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	_ = json.Unmarshal(b, &got)
	if _, ok := got["workload_id"]; ok {
		t.Errorf("zero workload_id should be omitted, got %v", got["workload_id"])
	}
}

// TestRedactionsSchema_JSONYAMLAgreement asserts the .json and .yaml field sets
// agree (the Story 2.8 BI-6.4 precedent), so the human mirror cannot drift from
// the authoritative .json.
func TestRedactionsSchema_JSONYAMLAgreement(t *testing.T) {
	jb, err := os.ReadFile(filepath.Join(schemaDir, "redactions.json"))
	if err != nil {
		t.Fatalf("read json: %v", err)
	}
	var jsonDoc struct {
		Required   []string                  `json:"required"`
		Properties map[string]map[string]any `json:"properties"`
	}
	if err := json.Unmarshal(jb, &jsonDoc); err != nil {
		t.Fatalf("unmarshal json schema: %v", err)
	}
	yb, err := os.ReadFile(filepath.Join(schemaDir, "redactions.yaml"))
	if err != nil {
		t.Fatalf("read yaml: %v", err)
	}
	var yamlDoc struct {
		Fields map[string]struct {
			Required bool     `yaml:"required"`
			Enum     []string `yaml:"enum"`
		} `yaml:"fields"`
	}
	if err := yaml.Unmarshal(yb, &yamlDoc); err != nil {
		t.Fatalf("unmarshal yaml schema: %v", err)
	}
	// Field name sets must match.
	for k := range jsonDoc.Properties {
		if _, ok := yamlDoc.Fields[k]; !ok {
			t.Errorf("field %q in .json but not .yaml", k)
		}
	}
	for k := range yamlDoc.Fields {
		if _, ok := jsonDoc.Properties[k]; !ok {
			t.Errorf("field %q in .yaml but not .json", k)
		}
	}
	// Required sets must match.
	reqJSON := map[string]struct{}{}
	for _, r := range jsonDoc.Required {
		reqJSON[r] = struct{}{}
	}
	for k, f := range yamlDoc.Fields {
		_, inJSON := reqJSON[k]
		if f.Required != inJSON {
			t.Errorf("field %q required mismatch: yaml=%v json=%v", k, f.Required, inJSON)
		}
	}
}

func TestRedactionAuditSink_EnqueueDrains(t *testing.T) {
	cap := &captureSink{}
	sink, err := NewRedactionAuditSink(cap, nil, RedactionAuditSinkConfig{DrainEvery: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sink.Run(ctx) }()

	events := []RedactionEvent{
		{FieldPath: "events[0].raw.api_key", Reason: ReasonSecretPattern, WorkloadID: "w", RedactedAt: time.Now()},
		{FieldPath: "events[0].raw.payload", Reason: ReasonRawPayload, WorkloadID: "w", RedactedAt: time.Now()},
	}
	sink.Enqueue(events, "pkg-1")

	deadline := time.After(2 * time.Second)
	for len(cap.events()) < 2 {
		select {
		case <-deadline:
			t.Fatalf("drain timed out, got %d events", len(cap.events()))
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done

	got := cap.events()
	for _, e := range got {
		if e.PackageID != "pkg-1" {
			t.Errorf("package_id = %q", e.PackageID)
		}
		if e.FieldPath == "" || e.Reason == "" {
			t.Errorf("incomplete event: %+v", e)
		}
		if e.PublishedAt.IsZero() {
			t.Errorf("published_at not stamped")
		}
	}
}

func TestRedactionAuditSink_FullBufferDropsAndNeverBlocks(t *testing.T) {
	cap := &captureSink{failNext: true} // never accepts, so the buffer fills
	sink, err := NewRedactionAuditSink(cap, nil, RedactionAuditSinkConfig{BufferCap: 4, DrainEvery: time.Hour})
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	// Enqueue far more than the cap; must never block.
	for i := 0; i < 100; i++ {
		sink.Enqueue([]RedactionEvent{{FieldPath: "f", Reason: ReasonSecretPattern, RedactedAt: time.Now()}}, "pkg")
	}
	if sink.Dropped() == 0 {
		t.Error("expected drops on a full buffer, got 0")
	}
	if len(cap.events()) != 0 {
		t.Errorf("publisher saw events despite failNext: %d", len(cap.events()))
	}
}

func TestRedactAndAudit_NilSinkEmitsNothing(t *testing.T) {
	pkg := pkgWithRaw(t, map[string]any{"api_key": "secret"})
	_, events := RedactAndAudit(pkg, nil)
	if len(events) != 1 {
		t.Fatalf("expected redaction events even with nil sink, got %d", len(events))
	}
	// No panic, no publish: nil-sink path is the off-by-default behaviour.
}

func TestRedactAndAudit_EnqueuesNoSecretValue(t *testing.T) {
	cap := &captureSink{}
	sink, err := NewRedactionAuditSink(cap, nil, RedactionAuditSinkConfig{DrainEvery: 10 * time.Millisecond})
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- sink.Run(ctx) }()

	secret := "sk-top-secret-value"
	b64 := base64.StdEncoding.EncodeToString([]byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e})
	pkg := schema.EvidencePackage{
		PackageID:  "pkg-1",
		WorkloadID: "w",
		Events: []schema.Event{{ID: "e1", Raw: mustRaw(t, map[string]any{
			"api_key": secret,
			"payload": b64,
		})}},
	}
	_, events := RedactAndAudit(pkg, sink)
	if len(events) != 2 {
		t.Fatalf("expected 2 redactions, got %d", len(events))
	}

	deadline := time.After(2 * time.Second)
	for len(cap.events()) < 2 {
		select {
		case <-deadline:
			t.Fatalf("drain timed out")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done

	// NFR18: no captured audit event may carry the secret value anywhere.
	for _, e := range cap.events() {
		blob, _ := json.Marshal(e)
		if strings.Contains(string(blob), secret) {
			t.Fatalf("secret value leaked into AUDIT.redactions payload: %s", blob)
		}
	}
}

func mustRaw(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal raw: %v", err)
	}
	return b
}

func TestNewRedactionAuditSink_NilPublisher(t *testing.T) {
	if _, err := NewRedactionAuditSink(nil, nil, RedactionAuditSinkConfig{}); err == nil {
		t.Error("expected error for nil publisher")
	}
}

func TestNewNATSRedactionPublisher_NilClient(t *testing.T) {
	if _, err := NewNATSRedactionPublisher(nil); err == nil {
		t.Error("expected error for nil nats client")
	}
}

func TestRedactionMsgID_StableAndDistinct(t *testing.T) {
	now := time.Date(2026, 6, 9, 12, 0, 0, 0, time.UTC)
	a := AuditRedaction{PackageID: "pkg-1", FieldPath: "events[0].raw.api_key", RedactedAt: now}
	// Stable across a re-publish of the same redaction (drainer retry dedup):
	// re-deriving from an independent copy yields the same id.
	aCopy := a
	if redactionMsgID(a) != redactionMsgID(aCopy) {
		t.Error("msgID not stable for the same event")
	}
	// Distinct per field path.
	b := a
	b.FieldPath = "events[0].raw.token"
	if redactionMsgID(a) == redactionMsgID(b) {
		t.Error("msgID collided across distinct field paths")
	}
	// Distinct per package.
	c := a
	c.PackageID = "pkg-2"
	if redactionMsgID(a) == redactionMsgID(c) {
		t.Error("msgID collided across distinct packages")
	}
	// Distinct per decision time.
	d := a
	d.RedactedAt = now.Add(time.Nanosecond)
	if redactionMsgID(a) == redactionMsgID(d) {
		t.Error("msgID collided across distinct redaction times")
	}
}
