package checkpoint_test

import (
	"context"
	"sync"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/olokotoh/olaitan/internal/agent/provider"
	"github.com/olokotoh/olaitan/internal/decision/analyst"
	"github.com/olokotoh/olaitan/internal/decision/analyst/checkpoint"
	"github.com/olokotoh/olaitan/internal/metrics"
	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/schema"
)

func startNATS(t *testing.T) *natsclient.Client {
	t.Helper()
	srv, err := natsserver.NewServer(&natsserver.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(), NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatalf("nats server: %v", err)
	}
	srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats not ready")
	}
	t.Cleanup(srv.Shutdown)
	c, err := natsclient.NewClient(natsclient.ClientConfig{URL: srv.ClientURL(), Name: "checkpoint-test", ReconnectWait: time.Second, ReconnectBufSize: 1 << 20})
	if err != nil {
		t.Fatalf("nats client: %v", err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Ensure only the INVESTIGATIONS stream: the full production stream set
	// carries large MaxBytes that exceed the embedded server's temp storage
	// (the kind/CI limit the streams.go OLT_NATS_STREAM_MAXBYTES_OVERRIDE
	// escape hatch addresses); INVESTIGATIONS has no MaxBytes.
	var inv []jetstream.StreamConfig
	for _, cfg := range natsclient.StreamConfigs() {
		if cfg.Name == "INVESTIGATIONS" {
			inv = append(inv, cfg)
		}
	}
	if len(inv) != 1 {
		t.Fatalf("INVESTIGATIONS stream config not found (got %d)", len(inv))
	}
	if err := natsclient.EnsureStreams(ctx, c.JetStream(), inv); err != nil {
		t.Fatalf("ensure streams: %v", err)
	}
	return c
}

func TestStoreRoundTrip(t *testing.T) {
	c := startNATS(t)
	store, err := checkpoint.New(c)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	// Miss before any save.
	if _, ok, err := store.LoadL1(ctx, "pkg-1"); err != nil || ok {
		t.Errorf("LoadL1 before save: ok=%v err=%v, want false/nil", ok, err)
	}
	h := schema.L1Hypothesis{Hypothesis: "miner", CitedEvidence: []schema.EvidenceCitation{{EventID: "evt-1"}}, Confidence: 70}
	if err := store.SaveL1(ctx, "pkg-1", h); err != nil {
		t.Fatalf("SaveL1: %v", err)
	}
	got, ok, err := store.LoadL1(ctx, "pkg-1")
	if err != nil || !ok {
		t.Fatalf("LoadL1 after save: ok=%v err=%v", ok, err)
	}
	if got.Hypothesis != "miner" || got.Confidence != 70 {
		t.Errorf("LoadL1 = %+v", got)
	}
	// A different package is still a miss.
	if _, ok, _ := store.LoadL1(ctx, "pkg-other"); ok {
		t.Error("LoadL1(pkg-other) should miss")
	}
	v := schema.L2Verification{Verdict: schema.VerdictConfirmed, VerifiedEvidence: []schema.EvidenceVerification{{EventID: "evt-1", Finding: "ok"}}, Confidence: 66}
	if err := store.SaveL2(ctx, "pkg-1", v); err != nil {
		t.Fatalf("SaveL2: %v", err)
	}
	gotV, ok, err := store.LoadL2(ctx, "pkg-1")
	if err != nil || !ok || gotV.Verdict != schema.VerdictConfirmed {
		t.Errorf("LoadL2 = %+v ok=%v err=%v", gotV, ok, err)
	}
}

// stepProvider replies per role and counts calls per role so a resume test
// can assert a checkpointed step's runner was NOT invoked.
type stepProvider struct {
	mu    sync.Mutex
	byRl  map[provider.Role]string
	calls map[provider.Role]int
}

func (s *stepProvider) Name() string                 { return "step" }
func (s *stepProvider) Model() string                { return "m" }
func (s *stepProvider) MaxContextTokens() int        { return 200000 }
func (s *stepProvider) ScoreCap() int                { return 35 }
func (s *stepProvider) SupportsStreaming() bool      { return false }
func (s *stepProvider) Health(context.Context) error { return nil }
func (s *stepProvider) Analyse(_ context.Context, req provider.Request) (provider.Response, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.calls == nil {
		s.calls = map[provider.Role]int{}
	}
	s.calls[req.Role]++
	return provider.Response{Raw: s.byRl[req.Role]}, nil
}
func (s *stepProvider) callCount(r provider.Role) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[r]
}

func newChain(t *testing.T, store analyst.CheckpointStore) (*analyst.Chain, *stepProvider) {
	t.Helper()
	sp := &stepProvider{byRl: map[provider.Role]string{
		provider.RoleL1:     `{"hypothesis":"crypto miner","cited_evidence":[{"event_id":"evt-1"}],"confidence":70}`,
		provider.RoleL2:     `{"verdict":"confirmed","verified_evidence":[{"event_id":"evt-1","finding":"ok"}],"confidence":66}`,
		provider.RoleSenior: `{"threat_type":"cryptomining","reasoning":"miner confirmed","confidence":80}`,
	}}
	reg := metrics.NewRegistry()
	l1, _ := analyst.NewL1(sp, analyst.PromptSpec{System: "s", Version: "v"}, reg, nil)
	l2, _ := analyst.NewL2(sp, analyst.PromptSpec{System: "s", Version: "v"}, reg, nil)
	sr, _ := analyst.NewSenior(sp, analyst.PromptSpec{System: "s", Version: "v"}, reg, nil)
	chain, err := analyst.NewChain(l1, l2, sr, reg, nil)
	if err != nil {
		t.Fatalf("NewChain: %v", err)
	}
	chain.WithCheckpoints(store)
	return chain, sp
}

func resumePackage() schema.EvidencePackage {
	return schema.EvidencePackage{PackageID: "pkg-resume", WorkloadID: "wl", Events: []schema.Event{{ID: "evt-1"}}}
}

// TestResumeAcrossRestart is the AC5 scenario: a first chain run checkpoints
// L1+L2; a FRESH chain + FRESH store on the SAME NATS (simulating a
// controller restart) re-runs the same package and does NOT re-invoke L1/L2
// (they resume from the checkpoints), only the Senior runs, and the
// assessment is reproduced idempotently.
func TestResumeAcrossRestart(t *testing.T) {
	c := startNATS(t)
	store, _ := checkpoint.New(c)
	ctx := context.Background()

	chain1, sp1 := newChain(t, store)
	res1, err := chain1.Run(ctx, resumePackage())
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	if sp1.callCount(provider.RoleL1) != 1 || sp1.callCount(provider.RoleL2) != 1 {
		t.Fatalf("first run l1/l2 calls = %d/%d, want 1/1", sp1.callCount(provider.RoleL1), sp1.callCount(provider.RoleL2))
	}

	// "Restart": a brand-new chain + store over the same JetStream.
	store2, _ := checkpoint.New(c)
	chain2, sp2 := newChain(t, store2)
	res2, err := chain2.Run(ctx, resumePackage())
	if err != nil {
		t.Fatalf("resume run: %v", err)
	}
	if sp2.callCount(provider.RoleL1) != 0 || sp2.callCount(provider.RoleL2) != 0 {
		t.Errorf("resume re-invoked l1/l2 (calls %d/%d), want 0/0 (resumed from checkpoints)", sp2.callCount(provider.RoleL1), sp2.callCount(provider.RoleL2))
	}
	if sp2.callCount(provider.RoleSenior) != 1 {
		t.Errorf("resume senior calls = %d, want 1", sp2.callCount(provider.RoleSenior))
	}
	// Idempotent: same assessment reproduced.
	if res1.Assessment.ThreatType != res2.Assessment.ThreatType || res2.Assessment.ThreatType != "cryptomining" {
		t.Errorf("assessment not reproduced: %q vs %q", res1.Assessment.ThreatType, res2.Assessment.ThreatType)
	}
}

// TestResumeFromL1Checkpoint is the BI-8 boundary (b) over REAL NATS: a
// post-L1 crash leaves only the L1 checkpoint, so a restart resumes L1 from
// the checkpoint (call count 0, marked resumed) but re-runs L2 (call count 1)
// and the Senior. The fake-store TestChainCheckpointResumesL1 proves the
// orchestrator branch; this proves the real natsCheckpointStore over the
// embedded JetStream server.
func TestResumeFromL1Checkpoint(t *testing.T) {
	c := startNATS(t)
	store, _ := checkpoint.New(c)
	ctx := context.Background()

	// Pre-seed ONLY the L1 checkpoint (the post-L1 boundary).
	if err := store.SaveL1(ctx, resumePackage().PackageID, schema.L1Hypothesis{
		Hypothesis:    "crypto miner",
		CitedEvidence: []schema.EvidenceCitation{{EventID: "evt-1"}},
		Confidence:    70,
	}); err != nil {
		t.Fatalf("seed L1 checkpoint: %v", err)
	}

	chain, sp := newChain(t, store)
	res, err := chain.Run(ctx, resumePackage())
	if err != nil {
		t.Fatalf("resume run: %v", err)
	}
	if sp.callCount(provider.RoleL1) != 0 {
		t.Errorf("L1 re-invoked (calls %d), want 0 (resumed from checkpoint)", sp.callCount(provider.RoleL1))
	}
	if sp.callCount(provider.RoleL2) != 1 || sp.callCount(provider.RoleSenior) != 1 {
		t.Errorf("l2/senior calls = %d/%d, want 1/1", sp.callCount(provider.RoleL2), sp.callCount(provider.RoleSenior))
	}
	// BI-4: the resumed L1 is marked resumed; the re-run L2 is not.
	if res.L1 == nil || !res.L1.Resumed {
		t.Errorf("resumed L1 not marked: %+v", res.L1)
	}
	if res.L2 == nil || res.L2.Resumed {
		t.Errorf("re-run L2 must not be marked resumed: %+v", res.L2)
	}
}
