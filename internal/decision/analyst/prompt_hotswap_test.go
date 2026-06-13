package analyst

import (
	"context"
	"sync"
	"testing"

	"github.com/olokotoh/olaitan/internal/agent/provider"
	"github.com/olokotoh/olaitan/internal/metrics"
)

// TestL1SetPromptSwapsSystemAndVersion proves SetPrompt atomically swaps
// the system prompt that reaches the provider AND the version recorded on
// the L1Result (the field Story 3.14 publishes to AUDIT.assessments), with
// the swap observed on the NEXT Run (Story 3.13 AC2/AC3).
func TestL1SetPromptSwapsSystemAndVersion(t *testing.T) {
	fp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: validVerdict}}
	l1, err := NewL1(fp, PromptSpec{System: "system-A", Version: "hash-A"}, metrics.NewRegistry(), nil)
	if err != nil {
		t.Fatalf("NewL1: %v", err)
	}

	res, err := l1.Run(context.Background(), testPackage())
	if err != nil {
		t.Fatalf("Run A: %v", err)
	}
	if fp.got.Prompt.System != "system-A" || res.PromptVersion != "hash-A" {
		t.Fatalf("pre-swap: system=%q version=%q, want system-A/hash-A", fp.got.Prompt.System, res.PromptVersion)
	}

	l1.SetPrompt(PromptSpec{System: "system-B", Version: "hash-B"})

	res, err = l1.Run(context.Background(), testPackage())
	if err != nil {
		t.Fatalf("Run B: %v", err)
	}
	if fp.got.Prompt.System != "system-B" || res.PromptVersion != "hash-B" {
		t.Errorf("post-swap: system=%q version=%q, want system-B/hash-B", fp.got.Prompt.System, res.PromptVersion)
	}
}

// TestL2SetPromptSwaps mirrors the L1 proof for the L2 runner.
func TestL2SetPromptSwaps(t *testing.T) {
	fp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: validL2Verdict}}
	l2, err := NewL2(fp, PromptSpec{System: "l2-A", Version: "l2hash-A"}, metrics.NewRegistry(), nil)
	if err != nil {
		t.Fatalf("NewL2: %v", err)
	}
	l2.SetPrompt(PromptSpec{System: "l2-B", Version: "l2hash-B"})
	res, err := l2.Run(context.Background(), testPackage(), testL1Hypothesis())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if fp.got.Prompt.System != "l2-B" || res.PromptVersion != "l2hash-B" {
		t.Errorf("post-swap: system=%q version=%q, want l2-B/l2hash-B", fp.got.Prompt.System, res.PromptVersion)
	}
}

// TestSeniorSetPromptSwaps mirrors the proof for the Senior runner.
func TestSeniorSetPromptSwaps(t *testing.T) {
	fp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: validSeniorVerdict}}
	sr, err := NewSenior(fp, PromptSpec{System: "sr-A", Version: "srhash-A"}, metrics.NewRegistry(), nil)
	if err != nil {
		t.Fatalf("NewSenior: %v", err)
	}
	sr.SetPrompt(PromptSpec{System: "sr-B", Version: "srhash-B"})
	res, err := sr.Run(context.Background(), testPackage(), nil, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if fp.got.Prompt.System != "sr-B" || res.PromptVersion != "srhash-B" {
		t.Errorf("post-swap: system=%q version=%q, want sr-B/srhash-B", fp.got.Prompt.System, res.PromptVersion)
	}
}

// TestSetPromptConcurrentWithRun is the -race guard: SetPrompt must be
// safe against a concurrent Run (the atomic.Pointer claim).
func TestSetPromptConcurrentWithRun(t *testing.T) {
	fp := &fakeProvider{name: "fake", model: "m", resp: provider.Response{Raw: validVerdict}}
	l1, err := NewL1(fp, PromptSpec{System: "s0", Version: "v0"}, metrics.NewRegistry(), nil)
	if err != nil {
		t.Fatalf("NewL1: %v", err)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
				i++
				l1.SetPrompt(PromptSpec{System: "s", Version: "v"})
			}
		}
	}()
	for i := 0; i < 200; i++ {
		_, _ = l1.Run(context.Background(), testPackage())
	}
	close(stop)
	wg.Wait()
}
