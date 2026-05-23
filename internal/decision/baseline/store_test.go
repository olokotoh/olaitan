package baseline_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"github.com/olokotoh/olaitan/internal/decision/baseline"
	redisclient "github.com/olokotoh/olaitan/internal/redis"
)

func startMiniredis(t *testing.T) *miniredis.Miniredis {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("start miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	return mr
}

func newClient(t *testing.T, addr string) *redisclient.Client {
	t.Helper()
	cfg := redisclient.DefaultConfig()
	cfg.Addr = addr
	c, err := redisclient.NewClient(cfg)
	if err != nil {
		t.Fatalf("new redis client: %v", err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

func TestStore_LoadEmptyWorkloadReturnsZeroWelfords(t *testing.T) {
	mr := startMiniredis(t)
	cli := newClient(t, mr.Addr())
	s, err := baseline.NewStore(cli)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	metrics := []string{"outbound_unique_dst_ips", "distinct_exec_paths", "outbound_bytes", "audit_events_per_min", "container_restarts_per_hour"}
	got, err := s.Load(context.Background(), "default", "web-0", metrics)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("len(got) = %d, want 5", len(got))
	}
	for _, m := range metrics {
		if got[m] == nil {
			t.Errorf("metric %q missing", m)
			continue
		}
		if got[m].Count != 0 || got[m].Mean != 0 || got[m].M2 != 0 {
			t.Errorf("metric %q not zero: %+v", m, got[m])
		}
	}
}

func TestStore_SaveLoadRoundTripsAllFive(t *testing.T) {
	mr := startMiniredis(t)
	cli := newClient(t, mr.Addr())
	s, err := baseline.NewStore(cli)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	metrics := []string{"outbound_unique_dst_ips", "distinct_exec_paths", "outbound_bytes", "audit_events_per_min", "container_restarts_per_hour"}
	want := map[string]*baseline.Welford{}
	for i, m := range metrics {
		w := &baseline.Welford{}
		for j := 1; j <= 10; j++ {
			w.Update(float64(j * (i + 1)))
		}
		want[m] = w
	}
	if err := s.Save(context.Background(), "default", "web-0", want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := s.Load(context.Background(), "default", "web-0", metrics)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, m := range metrics {
		if got[m].Count != want[m].Count {
			t.Errorf("metric %q Count: got %d want %d", m, got[m].Count, want[m].Count)
		}
		if got[m].Mean != want[m].Mean {
			t.Errorf("metric %q Mean: got %v want %v", m, got[m].Mean, want[m].Mean)
		}
		if got[m].M2 != want[m].M2 {
			t.Errorf("metric %q M2: got %v want %v", m, got[m].M2, want[m].M2)
		}
	}
}

func TestStore_SaveLoadWarmup(t *testing.T) {
	mr := startMiniredis(t)
	cli := newClient(t, mr.Addr())
	s, err := baseline.NewStore(cli)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	started := time.Now().UTC().Truncate(time.Second)
	if err := s.SaveWarmup(context.Background(), "default", "web-0", started, 30*time.Minute); err != nil {
		t.Fatalf("SaveWarmup: %v", err)
	}
	gotStart, gotDur, present, err := s.LoadWarmup(context.Background(), "default", "web-0")
	if err != nil {
		t.Fatalf("LoadWarmup: %v", err)
	}
	if !present {
		t.Fatalf("warmup not present after Save")
	}
	if !gotStart.Equal(started) {
		t.Errorf("startedAt: got %v want %v", gotStart, started)
	}
	if gotDur != 30*time.Minute {
		t.Errorf("duration: got %s want 30m", gotDur)
	}
}

func TestStore_LoadWarmupAbsentReturnsNotPresent(t *testing.T) {
	mr := startMiniredis(t)
	cli := newClient(t, mr.Addr())
	s, err := baseline.NewStore(cli)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	_, _, present, err := s.LoadWarmup(context.Background(), "default", "never-seen")
	if err != nil {
		t.Fatalf("LoadWarmup: %v", err)
	}
	if present {
		t.Errorf("expected present=false for never-seen workload")
	}
}

// TestStore_RestartSimulation locks AC4: after a simulated controller
// restart (close+reopen the client against the same miniredis
// instance), both Welford state and warm-up state survive.
func TestStore_RestartSimulation(t *testing.T) {
	mr := startMiniredis(t)
	cli := newClient(t, mr.Addr())
	s, err := baseline.NewStore(cli)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	metrics := []string{"outbound_unique_dst_ips", "container_restarts_per_hour"}
	want := map[string]*baseline.Welford{}
	for _, m := range metrics {
		w := &baseline.Welford{}
		for _, x := range []float64{1, 2, 3, 4, 5, 6, 7, 8} {
			w.Update(x)
		}
		want[m] = w
	}
	if err := s.Save(context.Background(), "default", "web-0", want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	started := time.Now().UTC().Truncate(time.Second)
	if err := s.SaveWarmup(context.Background(), "default", "web-0", started, 30*time.Minute); err != nil {
		t.Fatalf("SaveWarmup: %v", err)
	}

	// Simulate controller restart: close the client and build a fresh
	// one against the same miniredis instance.
	_ = cli.Close(context.Background())
	cli2 := newClient(t, mr.Addr())
	s2, err := baseline.NewStore(cli2)
	if err != nil {
		t.Fatalf("NewStore (restart): %v", err)
	}

	gotMetrics, err := s2.Load(context.Background(), "default", "web-0", metrics)
	if err != nil {
		t.Fatalf("Load (restart): %v", err)
	}
	for _, m := range metrics {
		if gotMetrics[m].Count != want[m].Count {
			t.Errorf("metric %q Count: got %d want %d", m, gotMetrics[m].Count, want[m].Count)
		}
		if gotMetrics[m].Mean != want[m].Mean {
			t.Errorf("metric %q Mean: got %v want %v", m, gotMetrics[m].Mean, want[m].Mean)
		}
	}
	gotStart, gotDur, present, err := s2.LoadWarmup(context.Background(), "default", "web-0")
	if err != nil {
		t.Fatalf("LoadWarmup (restart): %v", err)
	}
	if !present {
		t.Fatalf("warmup lost across restart")
	}
	if !gotStart.Equal(started) {
		t.Errorf("warmup startedAt drifted across restart: got %v want %v", gotStart, started)
	}
	if gotDur != 30*time.Minute {
		t.Errorf("warmup duration drifted across restart: got %s want 30m", gotDur)
	}
}

func TestStore_NewStoreRejectsNilClient(t *testing.T) {
	if _, err := baseline.NewStore(nil); err == nil {
		t.Errorf("NewStore(nil) should error")
	}
}
