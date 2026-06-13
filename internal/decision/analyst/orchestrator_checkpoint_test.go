package analyst

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/olokotoh/olaitan/internal/agent/provider"
	"github.com/olokotoh/olaitan/internal/schema"
)

const seniorAssessment = `{"threat_type":"cryptomining","reasoning":"miner confirmed","confidence":80}`

// fakeCheckpointStore is an in-memory CheckpointStore for orchestrator tests.
type fakeCheckpointStore struct {
	l1               map[string]schema.L1Hypothesis
	l2               map[string]schema.L2Verification
	saveL1Err        error
	loadL1Err        error
	saveL2Err        error
	loadL2Err        error
	savedL1, savedL2 int
}

func newFakeStore() *fakeCheckpointStore {
	return &fakeCheckpointStore{l1: map[string]schema.L1Hypothesis{}, l2: map[string]schema.L2Verification{}}
}
func (f *fakeCheckpointStore) SaveL1(_ context.Context, id string, h schema.L1Hypothesis) error {
	if f.saveL1Err != nil {
		return f.saveL1Err
	}
	f.l1[id] = h
	f.savedL1++
	return nil
}
func (f *fakeCheckpointStore) SaveL2(_ context.Context, id string, v schema.L2Verification) error {
	if f.saveL2Err != nil {
		return f.saveL2Err
	}
	f.l2[id] = v
	f.savedL2++
	return nil
}
func (f *fakeCheckpointStore) LoadL1(_ context.Context, id string) (schema.L1Hypothesis, bool, error) {
	if f.loadL1Err != nil {
		return schema.L1Hypothesis{}, false, f.loadL1Err
	}
	h, ok := f.l1[id]
	return h, ok, nil
}
func (f *fakeCheckpointStore) LoadL2(_ context.Context, id string) (schema.L2Verification, bool, error) {
	if f.loadL2Err != nil {
		return schema.L2Verification{}, false, f.loadL2Err
	}
	v, ok := f.l2[id]
	return v, ok, nil
}

func checkpointChain(t *testing.T) (*Chain, *fakeProvider, *fakeProvider, *fakeProvider) {
	t.Helper()
	l1fp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: validVerdict}}
	l2fp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: validL2Verdict}}
	srfp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: seniorAssessment}}
	chain, _ := newTestChain(t, l1fp, l2fp, srfp)
	return chain, l1fp, l2fp, srfp
}

// TestChainCheckpointSavesOnSuccess: a full run with an empty store
// checkpoints both L1 and L2.
func TestChainCheckpointSavesOnSuccess(t *testing.T) {
	chain, _, _, _ := checkpointChain(t)
	store := newFakeStore()
	chain.WithCheckpoints(store)
	res, err := chain.Run(context.Background(), testPackage())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if store.savedL1 != 1 || store.savedL2 != 1 {
		t.Errorf("saved l1/l2 = %d/%d, want 1/1", store.savedL1, store.savedL2)
	}
	// Freshly-run steps are NOT marked resumed (BI-4 mutation-killer: a
	// blanket Resumed=true would fail here).
	if res.L1 == nil || res.L1.Resumed || res.L2 == nil || res.L2.Resumed {
		t.Errorf("fresh run marked resumed: l1=%+v l2=%+v", res.L1, res.L2)
	}
}

// TestChainCheckpointResumesL1: a pre-existing L1 checkpoint skips the L1
// runner entirely (the resume invariant) but still runs L2 + Senior.
func TestChainCheckpointResumesL1(t *testing.T) {
	chain, l1fp, l2fp, srfp := checkpointChain(t)
	store := newFakeStore()
	store.l1[testPackage().PackageID] = schema.L1Hypothesis{
		Hypothesis:    "resumed miner",
		CitedEvidence: []schema.EvidenceCitation{{EventID: "evt-1"}},
		Confidence:    70,
	}
	chain.WithCheckpoints(store)
	res, err := chain.Run(context.Background(), testPackage())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if l1fp.calls != 0 {
		t.Errorf("L1 runner called %d times, want 0 (resumed from checkpoint)", l1fp.calls)
	}
	if l2fp.calls != 1 || srfp.calls != 1 {
		t.Errorf("l2/senior calls = %d/%d, want 1/1", l2fp.calls, srfp.calls)
	}
	if store.savedL1 != 0 {
		t.Errorf("resumed L1 must not be re-saved, savedL1 = %d", store.savedL1)
	}
	// BI-4: the resumed L1 is marked resumed; the freshly-run L2 is not.
	if res.L1 == nil || !res.L1.Resumed {
		t.Errorf("resumed L1 not marked: %+v", res.L1)
	}
	if res.L2 == nil || res.L2.Resumed {
		t.Errorf("freshly-run L2 must not be marked resumed: %+v", res.L2)
	}
}

// TestChainCheckpointResumesL1AndL2: both checkpoints present -> only the
// Senior runs (the post-L2-restart case).
func TestChainCheckpointResumesL1AndL2(t *testing.T) {
	chain, l1fp, l2fp, srfp := checkpointChain(t)
	store := newFakeStore()
	id := testPackage().PackageID
	store.l1[id] = schema.L1Hypothesis{Hypothesis: "resumed", CitedEvidence: []schema.EvidenceCitation{{EventID: "evt-1"}}, Confidence: 70}
	store.l2[id] = schema.L2Verification{Verdict: schema.VerdictConfirmed, VerifiedEvidence: []schema.EvidenceVerification{{EventID: "evt-1", Finding: "ok"}}, Confidence: 66}
	chain.WithCheckpoints(store)
	res, err := chain.Run(context.Background(), testPackage())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if l1fp.calls != 0 || l2fp.calls != 0 {
		t.Errorf("l1/l2 calls = %d/%d, want 0/0 (both resumed)", l1fp.calls, l2fp.calls)
	}
	if srfp.calls != 1 {
		t.Errorf("senior calls = %d, want 1", srfp.calls)
	}
	// BI-4: both resumed steps are marked resumed in the ChainResult.
	if res.L1 == nil || !res.L1.Resumed || res.L2 == nil || !res.L2.Resumed {
		t.Errorf("both steps should be marked resumed: l1=%+v l2=%+v", res.L1, res.L2)
	}
}

// TestChainCheckpointSaveFailureNonFatal: a SaveL1 failure must NOT abort
// the chain (best-effort durability).
func TestChainCheckpointSaveFailureNonFatal(t *testing.T) {
	chain, _, _, _ := checkpointChain(t)
	store := newFakeStore()
	store.saveL1Err = errors.New("nats down")
	chain.WithCheckpoints(store)
	res, err := chain.Run(context.Background(), testPackage())
	if err != nil {
		t.Fatalf("a checkpoint save failure must not abort the chain: %v", err)
	}
	if res.Assessment.ThreatType != "cryptomining" {
		t.Errorf("assessment not produced despite save failure: %+v", res.Assessment)
	}
}

// TestChainCheckpointLoadErrorReruns: a LoadL1 error (not a miss) re-runs L1
// rather than aborting.
func TestChainCheckpointLoadErrorReruns(t *testing.T) {
	chain, l1fp, _, _ := checkpointChain(t)
	store := newFakeStore()
	store.loadL1Err = errors.New("get last msg failed")
	chain.WithCheckpoints(store)
	if _, err := chain.Run(context.Background(), testPackage()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if l1fp.calls != 1 {
		t.Errorf("L1 runner called %d times, want 1 (re-run on load error)", l1fp.calls)
	}
}

// TestChainCheckpointSaveL2FailureNonFatal mirrors the L1 best-effort
// guarantee for L2: a SaveL2 failure must NOT abort the chain.
func TestChainCheckpointSaveL2FailureNonFatal(t *testing.T) {
	chain, _, _, _ := checkpointChain(t)
	store := newFakeStore()
	store.saveL2Err = errors.New("nats down")
	chain.WithCheckpoints(store)
	res, err := chain.Run(context.Background(), testPackage())
	if err != nil {
		t.Fatalf("an L2 checkpoint save failure must not abort the chain: %v", err)
	}
	if res.Assessment.ThreatType != "cryptomining" {
		t.Errorf("assessment not produced despite L2 save failure: %+v", res.Assessment)
	}
	// Teeth: a SaveL2 error must be swallowed INSIDE l2Step, not propagated as
	// an l2 error. If it propagated, runFull would degrade to hypothesis-only
	// (ver==nil) and drop "l2" from AgentsAvailable. So the save failure being
	// non-fatal is observable as "l2" surviving in the available set. (Full
	// mode swallows genuine l2 errors too, so asserting ThreatType alone is
	// toothless — round-2 Regression Hunter finding.)
	if !slices.Contains(res.Assessment.AgentsAvailable, "l2") {
		t.Errorf("SaveL2 error degraded L2 (agents_available=%v); the save must be non-fatal, not propagated", res.Assessment.AgentsAvailable)
	}
}

// TestChainCheckpointLoadL2ErrorReruns mirrors the L1 path: a LoadL2 error
// (not a miss) re-runs L2 rather than aborting.
func TestChainCheckpointLoadL2ErrorReruns(t *testing.T) {
	chain, _, l2fp, _ := checkpointChain(t)
	store := newFakeStore()
	store.loadL2Err = errors.New("get last msg failed")
	chain.WithCheckpoints(store)
	if _, err := chain.Run(context.Background(), testPackage()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if l2fp.calls != 1 {
		t.Errorf("L2 runner called %d times, want 1 (re-run on load error)", l2fp.calls)
	}
}
