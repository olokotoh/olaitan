package redis_test

import (
	"context"
	"errors"
	"testing"

	redisclient "github.com/olokotoh/olaitan/internal/redis"
)

const fsmTestKey = "fsm:default/Deployment/web"

func fsmFields(state string) map[string]any {
	return map[string]any{"schema_version": "fsm_state.v1", "current_state": state}
}

func TestSetFSMStateCAS_FirstWriteAndMismatch(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	cli := newTestClient(t, mr)

	// First write: absent key always swaps.
	ok, err := cli.SetFSMStateCAS(ctx, fsmTestKey, "current_state", "CLEAN", fsmFields("SUSPICIOUS"))
	if err != nil {
		t.Fatalf("CAS first: %v", err)
	}
	if !ok {
		t.Fatal("first write should swap")
	}
	// Mismatched expectedPrior must not swap.
	ok, err = cli.SetFSMStateCAS(ctx, fsmTestKey, "current_state", "CLEAN", fsmFields("RESTRICTED"))
	if err != nil {
		t.Fatalf("CAS mismatch: %v", err)
	}
	if ok {
		t.Fatal("mismatched expectedPrior should not swap")
	}
	// Matching expectedPrior swaps.
	ok, err = cli.SetFSMStateCAS(ctx, fsmTestKey, "current_state", "SUSPICIOUS", fsmFields("RESTRICTED"))
	if err != nil {
		t.Fatalf("CAS match: %v", err)
	}
	if !ok {
		t.Fatal("matching expectedPrior should swap")
	}
}

func TestSetFSMStateCAS_RejectsNonFSMKey(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	cli := newTestClient(t, mr)
	if _, err := cli.SetFSMStateCAS(ctx, "state:default:web", "current_state", "", fsmFields("CLEAN")); err == nil {
		t.Fatal("expected family-guard rejection for a non-fsm key")
	}
}

func TestGetFSMState_MissingReturnsErrKeyMissing(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	cli := newTestClient(t, mr)
	if _, err := cli.GetFSMState(ctx, fsmTestKey); !errors.Is(err, redisclient.ErrKeyMissing) {
		t.Fatalf("GetFSMState missing = %v, want ErrKeyMissing", err)
	}
}

func TestAppendFSMHistory_AppendsAndTrims(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	cli := newTestClient(t, mr)
	histKey := fsmTestKey + ":history"
	// Append 5 entries with a cap of 3; only the last 3 must remain.
	for i := 0; i < 5; i++ {
		if err := cli.AppendFSMHistory(ctx, histKey, []byte{byte('a' + i)}, 3); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	n, err := cli.Raw().LLen(ctx, histKey).Result()
	if err != nil {
		t.Fatalf("LLen: %v", err)
	}
	if n != 3 {
		t.Errorf("history length = %d, want 3 (LTRIM cap)", n)
	}
}

func TestScanFSMStateKeys_ExcludesHistory(t *testing.T) {
	ctx := context.Background()
	mr := startMiniredis(t)
	cli := newTestClient(t, mr)
	if _, err := cli.SetFSMStateCAS(ctx, fsmTestKey, "current_state", "CLEAN", fsmFields("SUSPICIOUS")); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	if err := cli.AppendFSMHistory(ctx, fsmTestKey+":history", []byte("x"), 10); err != nil {
		t.Fatalf("seed history: %v", err)
	}
	got, err := cli.ScanFSMStateKeys(ctx)
	if err != nil {
		t.Fatalf("ScanFSMStateKeys: %v", err)
	}
	if len(got) != 1 || got[0] != fsmTestKey {
		t.Fatalf("ScanFSMStateKeys = %v, want exactly [%s] (history excluded)", got, fsmTestKey)
	}
}
