package redis_test

import (
	"context"
	"errors"
	"testing"
	"time"

	redisclient "github.com/olokotoh/olaitan/internal/redis"
)

const overrideTestKey = "override:default/Deployment/web"

func overrideFields(state string) map[string]any {
	return map[string]any{
		"schema_version":  "override.v1",
		"requested_state": state,
		"ttl_seconds":     "1800",
		"source":          "pod",
	}
}

// TestSetOverride_WritesNativeTTL pins AC3: the override key carries a
// native Redis TTL matching the requested override duration (not a fixed
// family constant).
func TestSetOverride_WritesNativeTTL(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	cli := newTestClient(t, mr)

	if err := cli.SetOverride(ctx, overrideTestKey, overrideFields("RESTRICTED"), 30*time.Minute); err != nil {
		t.Fatalf("SetOverride: %v", err)
	}
	ttl := mr.TTL(overrideTestKey)
	if ttl <= 0 {
		t.Fatalf("override key TTL = %s, want a positive native TTL", ttl)
	}
	// miniredis stores the exact EXPIRE; assert it equals the requested duration.
	if ttl != 30*time.Minute {
		t.Errorf("override key TTL = %s, want 30m (the requested override duration)", ttl)
	}
}

// TestSetOverride_TTLExpiry pins the FR39 release mechanism: after the
// native TTL elapses Redis drops the key, so a subsequent Get returns
// ErrKeyMissing (the controller's release signal, BI-4).
func TestSetOverride_TTLExpiry(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	cli := newTestClient(t, mr)

	if err := cli.SetOverride(ctx, overrideTestKey, overrideFields("QUARANTINED"), 30*time.Minute); err != nil {
		t.Fatalf("SetOverride: %v", err)
	}
	mr.FastForward(30*time.Minute + time.Second)
	if _, err := cli.GetOverride(ctx, overrideTestKey); !errors.Is(err, redisclient.ErrKeyMissing) {
		t.Fatalf("GetOverride after TTL expiry = %v, want ErrKeyMissing", err)
	}
}

func TestSetOverride_RejectsNonPositiveTTL(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	cli := newTestClient(t, mr)
	if err := cli.SetOverride(ctx, overrideTestKey, overrideFields("RESTRICTED"), 0); err == nil {
		t.Fatal("SetOverride with zero TTL: want error, got nil")
	}
}

func TestSetOverride_RejectsNonOverrideKey(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	cli := newTestClient(t, mr)
	if err := cli.SetOverride(ctx, "fsm:default/Deployment/web", overrideFields("RESTRICTED"), time.Hour); err == nil {
		t.Fatal("expected family-guard rejection for a non-override key")
	}
}

func TestGetOverride_RoundTrip(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	cli := newTestClient(t, mr)
	if err := cli.SetOverride(ctx, overrideTestKey, overrideFields("RESTRICTED"), time.Hour); err != nil {
		t.Fatalf("SetOverride: %v", err)
	}
	got, err := cli.GetOverride(ctx, overrideTestKey)
	if err != nil {
		t.Fatalf("GetOverride: %v", err)
	}
	if got["requested_state"] != "RESTRICTED" || got["schema_version"] != "override.v1" {
		t.Errorf("GetOverride round-trip = %v, want requested_state=RESTRICTED schema_version=override.v1", got)
	}
}

func TestGetOverride_MissingReturnsErrKeyMissing(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	cli := newTestClient(t, mr)
	if _, err := cli.GetOverride(ctx, overrideTestKey); !errors.Is(err, redisclient.ErrKeyMissing) {
		t.Fatalf("GetOverride missing = %v, want ErrKeyMissing", err)
	}
}

func TestDeleteOverride_RemovesKey(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	cli := newTestClient(t, mr)
	if err := cli.SetOverride(ctx, overrideTestKey, overrideFields("RESTRICTED"), time.Hour); err != nil {
		t.Fatalf("SetOverride: %v", err)
	}
	if err := cli.DeleteOverride(ctx, overrideTestKey); err != nil {
		t.Fatalf("DeleteOverride: %v", err)
	}
	if _, err := cli.GetOverride(ctx, overrideTestKey); !errors.Is(err, redisclient.ErrKeyMissing) {
		t.Fatalf("GetOverride after delete = %v, want ErrKeyMissing", err)
	}
	// Deleting an absent key is a no-op, not an error.
	if err := cli.DeleteOverride(ctx, overrideTestKey); err != nil {
		t.Fatalf("DeleteOverride (absent) = %v, want nil", err)
	}
}

func TestScanOverrideKeys_FindsActive(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	cli := newTestClient(t, mr)
	keysToWrite := []string{
		"override:default/Deployment/web",
		"override:default/Deployment/api",
		"override:prod/StatefulSet/db",
	}
	for _, k := range keysToWrite {
		if err := cli.SetOverride(ctx, k, overrideFields("RESTRICTED"), time.Hour); err != nil {
			t.Fatalf("SetOverride %q: %v", k, err)
		}
	}
	// A non-override key must not be returned by the scan.
	if _, err := cli.SetFSMStateCAS(ctx, "fsm:default/Deployment/web", "current_state", "CLEAN", fsmFields("SUSPICIOUS"), "", nil, 0); err != nil {
		t.Fatalf("seed fsm key: %v", err)
	}
	got, err := cli.ScanOverrideKeys(ctx)
	if err != nil {
		t.Fatalf("ScanOverrideKeys: %v", err)
	}
	if len(got) != len(keysToWrite) {
		t.Fatalf("ScanOverrideKeys returned %d keys, want %d: %v", len(got), len(keysToWrite), got)
	}
	for _, want := range keysToWrite {
		found := false
		for _, g := range got {
			if g == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ScanOverrideKeys missing %q (got %v)", want, got)
		}
	}
}
