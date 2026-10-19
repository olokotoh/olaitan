package rules

import (
	"bufio"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/olokotoh/olaitan/internal/collector/cni"
	"github.com/olokotoh/olaitan/internal/collector/cni/goldmanepb"
	"github.com/olokotoh/olaitan/internal/decision/rules/loader"
	"github.com/olokotoh/olaitan/internal/schema"
)

// Story 11.2b live gate, 2026-10-19 (kind-full on AWS, Falco ON). The real S4
// Goldmane flows reached EVENTS_RAW but the correlator dropped them at
// identity resolution, so no package ever carried one and OLT-NET-002 never
// fired. The correlator now attributes them to tenant-acme/Deployment/web
// (internal/correlator/goldmane_aggregate.go). These tests close the other
// half of the claim: once a correctly attributed flow is inside a multi_signal
// package of that Deployment, the production corpus matches it.
//
// liveFlowFixture is the S4 flows exactly as they reached EVENTS_RAW on the
// live run (shared with the correlator tests).
const liveFlowFixture = "../../correlator/testdata/goldmane-s4-flows-live-2026-10-19.jsonl"

func loadLiveFlows(t *testing.T) []schema.Event {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed")
	}
	f, err := os.Open(filepath.Join(filepath.Dir(thisFile), liveFlowFixture))
	if err != nil {
		t.Fatalf("open live flow fixture: %v", err)
	}
	defer func() { _ = f.Close() }()
	var out []schema.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev schema.Event
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("decode live flow: %v", err)
		}
		out = append(out, ev)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("live flow fixture is empty")
	}
	return out
}

// webDeploymentPackage is the multi_signal package the correlator now
// assembles when a Falco alert and a Goldmane flow of tenant-acme/web meet in
// one window: the Deployment identity, and the events of the window.
func webDeploymentPackage(events ...schema.Event) schema.EvidencePackage {
	id := schema.WorkloadIdentity{Namespace: "tenant-acme", OwnerKind: "Deployment", OwnerName: "web"}
	now := time.Date(2026, 10, 19, 20, 53, 0, 0, time.UTC)
	return schema.EvidencePackage{
		SchemaVersion:    "evidence.v1",
		PackageID:        "epkg-live-s4",
		WorkloadID:       "tenant-acme/Deployment/web",
		WorkloadIdentity: id,
		AssembledAt:      now,
		Trigger:          schema.EvidenceTrigger{Type: "multi_signal", FiredAt: now},
		WorkloadPosture:  &schema.WorkloadPosture{Identity: id, CapturedAt: now, ServiceAccount: "default"},
		Events:           events,
	}
}

func liveCorpus(t *testing.T) *loader.Corpus {
	t.Helper()
	l := loader.New(corpusRoot(t), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := l.Load(); err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	return l.Get()
}

func matchedRules(matches []schema.RuleMatch, eventID string) map[string]bool {
	out := map[string]bool{}
	for _, m := range matches {
		if eventID == "" || m.EventID == eventID {
			out[m.RuleID] = true
		}
	}
	return out
}

// S4: every real beacon flow (both the Src and the Dst reporter record) trips
// OLT-NET-002 once it sits in the Deployment's package.
func TestLiveS4GoldmaneFlowsMatchOLTNet002(t *testing.T) {
	corpus := liveCorpus(t)
	engine := &Engine{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	flows := loadLiveFlows(t)
	pkg := webDeploymentPackage(flows...)
	matches := engine.evaluatePackage(&pkg, corpus)
	for _, fl := range flows {
		got := matchedRules(matches, fl.ID)
		if !got["OLT-NET-002"] {
			t.Errorf("live S4 flow %s (dst_port %s) did not match OLT-NET-002; matched %v", fl.ID, rawField(t, fl, "network.dst_port"), sortedRuleIDs(got))
		}
		if got["OLT-NET-001"] {
			t.Errorf("live S4 flow %s matched OLT-NET-001; the in-cluster sink is not public egress", fl.ID)
		}
	}
}

// S5: no S5 pool flow was captured on the live run (the correlator dropped
// them before anything recorded them), so the S5 flow is rebuilt from the
// REAL S4 FlowResult with only the destination swapped to the S5 stratum pool
// (s5-stratum-pool:3333), then run through the real CNI Translate so the
// projection is the adapter's, not hand-written.
func TestLiveShapeS5PoolFlowMatchesOLTImpact006(t *testing.T) {
	corpus := liveCorpus(t)
	engine := &Engine{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	live := loadLiveFlows(t)[1] // the Src-reported record: the pod opened it

	var raw struct {
		ID   json.Number     `json:"id"`
		Flow json.RawMessage `json:"flow"`
	}
	if err := json.Unmarshal(live.Raw, &raw); err != nil {
		t.Fatalf("decode live raw: %v", err)
	}
	flow := &goldmanepb.Flow{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(raw.Flow, flow); err != nil {
		t.Fatalf("decode live FlowResult.flow: %v", err)
	}
	key := flow.GetKey()
	if key.GetSourceName() != "web-bd846c7f-*" || key.GetDestPort() != 8443 {
		t.Fatalf("live flow key = %s:%d, not the S4 beacon", key.GetSourceName(), key.GetDestPort())
	}
	key.DestName = "s5-stratum-pool-9c8c7876-*"
	key.DestServiceName = "s5-stratum-pool"
	key.DestPort = 3333
	key.DestServicePort = 3333
	resultID, err := raw.ID.Int64()
	if err != nil {
		t.Fatalf("live FlowResult id %q: %v", raw.ID, err)
	}
	ev, err := cni.Translate(&goldmanepb.FlowResult{Id: resultID, Flow: flow}, "olaitan-full-worker2", 0)
	if err != nil {
		t.Fatalf("translate S5 flow: %v", err)
	}
	if ev.Pod.Name != "web-bd846c7f-*" || ev.Pod.Namespace != "tenant-acme" {
		t.Fatalf("translated pod = %s/%s", ev.Pod.Namespace, ev.Pod.Name)
	}
	pkg := webDeploymentPackage(ev)
	got := matchedRules(engine.evaluatePackage(&pkg, corpus), "")
	if !got["OLT-IMPACT-006"] {
		t.Fatalf("S5 pool flow did not match OLT-IMPACT-006; matched %v", sortedRuleIDs(got))
	}
}

func rawField(t *testing.T, ev schema.Event, field string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(ev.Raw, &m); err != nil {
		return "?"
	}
	if v, ok := m[field].(string); ok {
		return v
	}
	return "?"
}
