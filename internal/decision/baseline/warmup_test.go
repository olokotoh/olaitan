package baseline_test

import (
	"context"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/decision/baseline"
)

func newWarmup(t *testing.T) (*baseline.Warmup, func(time.Time)) {
	t.Helper()
	mr := startMiniredis(t)
	cli := newClient(t, mr.Addr())
	store, err := baseline.NewStore(cli)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	w, err := baseline.NewWarmup(store, baseline.WarmupConfig{Duration: 30 * time.Minute})
	if err != nil {
		t.Fatalf("NewWarmup: %v", err)
	}
	current := time.Now().UTC()
	setNow := func(t time.Time) { current = t }
	w.SetNow(func() time.Time { return current })
	return w, setNow
}

func TestWarmup_BeginActivates(t *testing.T) {
	w, _ := newWarmup(t)
	ctx := context.Background()
	if err := w.Begin(ctx, "default", "web-0"); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	active, err := w.IsActive(ctx, "default", "web-0")
	if err != nil {
		t.Fatalf("IsActive: %v", err)
	}
	if !active {
		t.Errorf("expected active immediately after Begin")
	}
}

func TestWarmup_ExpiresAfterDuration(t *testing.T) {
	w, setNow := newWarmup(t)
	ctx := context.Background()
	if err := w.Begin(ctx, "default", "web-0"); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	setNow(time.Now().UTC().Add(31 * time.Minute))
	active, err := w.IsActive(ctx, "default", "web-0")
	if err != nil {
		t.Fatalf("IsActive: %v", err)
	}
	if active {
		t.Errorf("expected expired after 31 minutes")
	}
}

func TestWarmup_AbsentReturnsInactive(t *testing.T) {
	w, _ := newWarmup(t)
	active, err := w.IsActive(context.Background(), "default", "never-seen")
	if err != nil {
		t.Fatalf("IsActive: %v", err)
	}
	if active {
		t.Errorf("expected inactive for never-seen workload")
	}
}

// TestWarmup_SurvivesRestart locks AC4: a controller restart (fresh
// Warmup against the same Store) preserves an in-flight warm-up.
func TestWarmup_SurvivesRestart(t *testing.T) {
	mr := startMiniredis(t)
	cli := newClient(t, mr.Addr())
	store, _ := baseline.NewStore(cli)
	w1, _ := baseline.NewWarmup(store, baseline.WarmupConfig{Duration: 30 * time.Minute})
	current := time.Now().UTC()
	w1.SetNow(func() time.Time { return current })
	ctx := context.Background()
	if err := w1.Begin(ctx, "default", "web-0"); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	// Simulate restart: construct fresh Warmup against same store.
	w2, _ := baseline.NewWarmup(store, baseline.WarmupConfig{Duration: 30 * time.Minute})
	w2.SetNow(func() time.Time { return current.Add(5 * time.Minute) })
	active, err := w2.IsActive(ctx, "default", "web-0")
	if err != nil {
		t.Fatalf("IsActive: %v", err)
	}
	if !active {
		t.Errorf("expected active after restart within window")
	}
}

func TestWarmup_NewWarmupRejectsNilStore(t *testing.T) {
	if _, err := baseline.NewWarmup(nil, baseline.WarmupConfig{Duration: 30 * time.Minute}); err == nil {
		t.Errorf("NewWarmup(nil, ...) should error")
	}
}

func TestWarmup_ActiveWorkloads_ReapsExpired(t *testing.T) {
	w, setNow := newWarmup(t)
	ctx := context.Background()
	if err := w.Begin(ctx, "default", "web-0"); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := w.Begin(ctx, "default", "web-1"); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	got := w.ActiveWorkloads()
	if len(got) != 2 {
		t.Errorf("ActiveWorkloads len=%d want 2", len(got))
	}
	setNow(time.Now().UTC().Add(31 * time.Minute))
	got = w.ActiveWorkloads()
	if len(got) != 0 {
		t.Errorf("ActiveWorkloads after expiry: len=%d want 0", len(got))
	}
}
