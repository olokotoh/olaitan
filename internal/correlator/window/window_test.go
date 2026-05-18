package window

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/olokotoh/olaitan/internal/schema"
)

func TestStoreAddEvictsByWindowPerWorkload(t *testing.T) {
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	store := NewStore(60 * time.Second)

	old := event("old", now.Add(-61*time.Second), schema.SourceFalco)
	kept := event("kept", now.Add(-30*time.Second), schema.SourceAudit)
	latest := event("latest", now, schema.SourceRuntime)

	if _, err := store.Add("payments/Deployment/api", old); err != nil {
		t.Fatalf("add old: %v", err)
	}
	if _, err := store.Add("payments/Deployment/api", kept); err != nil {
		t.Fatalf("add kept: %v", err)
	}
	got, err := store.Add("payments/Deployment/api", latest)
	if err != nil {
		t.Fatalf("add latest: %v", err)
	}

	if len(got.Events) != 2 {
		t.Fatalf("events after eviction: got %d, want 2 (%+v)", len(got.Events), got.Events)
	}
	if got.Events[0].ID != "kept" || got.Events[1].ID != "latest" {
		t.Errorf("order/events: got %v", ids(got.Events))
	}
}

func TestStoreSetWindowDurationAffectsFutureAdds(t *testing.T) {
	now := time.Date(2026, 5, 18, 10, 0, 0, 0, time.UTC)
	store := NewStore(60 * time.Second)
	_, _ = store.Add("ns/Deployment/app", event("stale", now.Add(-20*time.Second), schema.SourceFalco))
	store.SetWindowDuration(10 * time.Second)

	got, err := store.Add("ns/Deployment/app", event("fresh", now, schema.SourceAudit))
	if err != nil {
		t.Fatalf("add fresh: %v", err)
	}
	if len(got.Events) != 1 || got.Events[0].ID != "fresh" {
		t.Errorf("window update did not evict stale event: %v", ids(got.Events))
	}
}

func TestStoreConcurrentAdds(t *testing.T) {
	store := NewStore(time.Hour)
	var wg sync.WaitGroup
	for i := 0; i < 128; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := store.Add("ns/Deployment/app", event(fmt.Sprintf("evt-%03d", i), time.Unix(int64(i), 0), schema.SourceFalco))
			if err != nil {
				t.Errorf("add %d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()
	got := store.Snapshot("ns/Deployment/app")
	if len(got.Events) != 128 {
		t.Fatalf("events: got %d, want 128", len(got.Events))
	}
}

func event(id string, ts time.Time, source schema.EventSource) schema.Event {
	return schema.Event{
		ID:        id,
		Timestamp: ts,
		Source:    source,
		Pod:       schema.PodRef{Name: "api-pod", Namespace: "payments", UID: "pod-uid"},
		Category:  schema.CategorySyscall,
		Summary:   id,
	}
}

func ids(events []schema.Event) []string {
	out := make([]string, len(events))
	for i := range events {
		out[i] = events[i].ID
	}
	return out
}
