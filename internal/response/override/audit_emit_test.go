package override

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/olokotoh/olaitan/internal/response/fsm"
)

// overridesSchemaPath is the committed AUDIT.overrides JSON-Schema, relative to
// this package.
const overridesSchemaPath = "../../../docs/schemas/audit/overrides.json"

func validateOverrideSchema(t *testing.T, payload []byte) error {
	t.Helper()
	sb, err := os.ReadFile(overridesSchemaPath)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(sb))
	if err != nil {
		t.Fatalf("unmarshal schema: %v", err)
	}
	cmp := jsonschema.NewCompiler()
	if err := cmp.AddResource(overridesSchemaPath, doc); err != nil {
		t.Fatalf("add resource: %v", err)
	}
	sch, err := cmp.Compile(overridesSchemaPath)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return sch.Validate(inst)
}

func TestNewNATSAuditPublisher_NilClient(t *testing.T) {
	if _, err := NewNATSAuditPublisher(nil); err == nil {
		t.Error("NewNATSAuditPublisher(nil) should error")
	}
}

func TestPrepareAuditOverride_DefaultsAndDedup(t *testing.T) {
	now := time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
	// Applied: defaults schema_version + published_at; msgID keys on applied_at.
	got, msgID := prepareAuditOverride(AuditOverride{WorkloadID: "w", AppliedAtNs: 99}, now)
	if got.SchemaVersion != SchemaVersionAuditOverride {
		t.Errorf("schema_version not defaulted: %q", got.SchemaVersion)
	}
	if !got.PublishedAt.Equal(now) {
		t.Errorf("published_at not defaulted to now: %v", got.PublishedAt)
	}
	if msgID != "w:99" {
		t.Errorf("applied msgID = %q, want w:99", msgID)
	}
	// Rejected: msgID keys on reason+requested (matches the operational form).
	_, rmsg := prepareAuditOverride(AuditOverride{WorkloadID: "w", Rejected: true, Reason: ReasonInvalidState, RequestedState: "BOGUS"}, now)
	if rmsg != "w:rejected:"+ReasonInvalidState+":BOGUS" {
		t.Errorf("rejected msgID = %q", rmsg)
	}
	// An explicit published_at survives.
	pre := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	keep, _ := prepareAuditOverride(AuditOverride{WorkloadID: "w", PublishedAt: pre}, now)
	if !keep.PublishedAt.Equal(pre) {
		t.Errorf("explicit published_at overwritten: %v", keep.PublishedAt)
	}
}

// TestAuditOverride_ValidatesAgainstSchema confirms the AuditOverride wire
// shape (applied and rejected) matches the committed schema (BI-6/AC6).
func TestAuditOverride_ValidatesAgainstSchema(t *testing.T) {
	applied := auditOverrideFromApplied(OverrideApplied{
		SchemaVersion: SchemaVersionAuditOverride, WorkloadID: "ns/Deployment/web",
		RequestedState: "RESTRICTED", BeforeState: "CLEAN", TTLSeconds: 1800,
		OperatorID: "alice", Source: "pod", Rejected: false,
		PublishedAt: time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC), AppliedAtNs: 123,
	})
	b, _ := json.Marshal(applied)
	if err := validateOverrideSchema(t, b); err != nil {
		t.Fatalf("applied audit override failed schema: %v", err)
	}

	rejected := auditOverrideFromApplied(OverrideApplied{
		WorkloadID: "ns/Deployment/web", RequestedState: "BOGUS", BeforeState: "CLEAN",
		Source: "pod", Rejected: true, Reason: ReasonInvalidState,
		PublishedAt: time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC),
	})
	rb, _ := json.Marshal(rejected)
	if err := validateOverrideSchema(t, rb); err != nil {
		t.Fatalf("rejected audit override failed schema: %v", err)
	}
}

// captureAuditPublisher is a capturing AuditOverridePublisher (Story 2.8 BI-2).
type captureAuditPublisher struct {
	mu  sync.Mutex
	got []AuditOverride
}

func (c *captureAuditPublisher) PublishAuditOverride(_ context.Context, evt AuditOverride) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.got = append(c.got, evt)
	return nil
}

func (c *captureAuditPublisher) all() []AuditOverride {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]AuditOverride(nil), c.got...)
}

func newControllerWithAudit(t *testing.T, objs []runtime.Object, store *Store, machine *fsm.Machine, pub OverridePublisher) (*Controller, *captureAuditPublisher) {
	t.Helper()
	c := newController(t, objs, store, machine, pub, nil)
	ap := &captureAuditPublisher{}
	c.SetAuditPublisher(ap)
	return c, ap
}

func TestAuditOverride_AppliedEmitsSecondPublish(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	store, _ := newRedisStore(t, mr)
	machine := newMachine(t)
	pub := &fakePublisher{}

	_, objs := deploymentPod("default", "web", map[string]string{
		AnnotationState: "RESTRICTED",
		AnnotationTTL:   "30m",
	})
	c, ap := newControllerWithAudit(t, objs, store, machine, pub)
	c.reconcile(ctx)

	// Operational publish AND the SIEM audit copy.
	if len(pub.all()) != 1 {
		t.Fatalf("want 1 operational event, got %d", len(pub.all()))
	}
	audits := ap.all()
	if len(audits) != 1 {
		t.Fatalf("want 1 AUDIT.overrides event, got %d", len(audits))
	}
	a := audits[0]
	if a.SchemaVersion != SchemaVersionAuditOverride || a.Rejected || a.RequestedState != "RESTRICTED" || a.TTLSeconds != 1800 {
		t.Errorf("unexpected applied audit event: %+v", a)
	}
}

func TestAuditOverride_NilPublisherEmitsNothing(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	store, _ := newRedisStore(t, mr)
	machine := newMachine(t)
	pub := &fakePublisher{}

	_, objs := deploymentPod("default", "web", map[string]string{
		AnnotationState: "RESTRICTED",
	})
	// No SetAuditPublisher -> auditPublisher nil -> off by default.
	c := newController(t, objs, store, machine, pub, nil)
	c.reconcile(ctx)
	if len(pub.all()) != 1 {
		t.Fatalf("operational publish still expected, got %d", len(pub.all()))
	}
	// Nothing to assert on audit (nil); the test passes if no panic occurs.
}

func TestAuditOverride_RejectionEmitsAuditOnce(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	store, _ := newRedisStore(t, mr)
	machine := newMachine(t)
	pub := &fakePublisher{}

	_, objs := deploymentPod("default", "web", map[string]string{
		AnnotationState: "BOGUS_STATE",
	})
	c, ap := newControllerWithAudit(t, objs, store, machine, pub)

	c.reconcile(ctx)
	c.reconcile(ctx) // standing invalid annotation: must NOT re-emit (dedup gate)

	audits := ap.all()
	if len(audits) != 1 {
		t.Fatalf("want exactly 1 rejection audit across two ticks (dedup gate), got %d", len(audits))
	}
	if !audits[0].Rejected || audits[0].Reason != ReasonInvalidState {
		t.Errorf("unexpected rejection audit: %+v", audits[0])
	}
}
