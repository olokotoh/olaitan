package fsm

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/olokotoh/olaitan/internal/keys"
	redisclient "github.com/olokotoh/olaitan/internal/redis"
	"github.com/olokotoh/olaitan/internal/schema"
)

// SchemaVersionFSMState is stamped on every persisted FSM-state hash so a
// future format change is detectable on load (the B6 schema-versioning
// ADR; docs/schema-versioning.md).
const SchemaVersionFSMState = "fsm_state.v1"

// Persisted hash field names. current_state is the compare-and-swap
// field (Story 2.3 AC1). Timestamps are nanosecond Unix int64 strings,
// mirroring the Story 1.17 baseline warm-up serialisation.
const (
	fieldSchemaVersion    = "schema_version"
	fieldCurrentState     = "current_state"
	fieldStateEnteredAtNs = "state_entered_at_ns"
	fieldCooldownAnchorNs = "cooldown_anchor_ns"
	fieldUpdatedAtNs      = "updated_at_ns"
)

// historyCap bounds the fsm:{workload_id}:history list. This is
// operational state (the 90-day SIEM audit trail is the Story 2.8 NATS
// AUDIT.transitions subject, not this list).
const historyCap = 1000

// persistedState is the durable projection of a workloadState.
type persistedState struct {
	current          schema.PodSecurityState
	stateEnteredAt   time.Time
	cooldownAnchorAt time.Time
	updatedAt        time.Time
}

// restoredWorkload is one workload recovered from Redis on restart.
type restoredWorkload struct {
	workloadID string
	state      persistedState
}

// Store persists FSM state to Redis and recovers it on restart. It
// mirrors the Story 1.17 baseline Store: a thin typed wrapper over the
// shared redis client that builds keys via internal/keys and writes
// through the family-guarded setters (never Raw).
type Store struct {
	client *redisclient.Client
}

// NewStore returns a Store bound to client. A nil client is a
// construction error so the failure surfaces at startup, not on the
// first transition (baseline/store.go precedent).
func NewStore(client *redisclient.Client) (*Store, error) {
	if client == nil {
		return nil, errors.New("fsm: nil redis client")
	}
	return &Store{client: client}, nil
}

// Save persists a transition durable-first: it compare-and-swaps the
// current-state hash (expectedPrior is the FromState the caller believes
// is persisted) and, only when the swap lands, appends historyEntry to
// the bounded history list. A dropped CAS (a newer state already won, or
// a concurrent modification) returns (false, nil); the caller treats that
// as a benign no-op (BI-7 idempotency). historyEntry may be nil to skip
// the append.
func (s *Store) Save(ctx context.Context, workloadID, expectedPrior string, st persistedState, historyEntry []byte) (bool, error) {
	stateKey, err := keys.FSMState(workloadID)
	if err != nil {
		return false, fmt.Errorf("fsm: store save key: %w", err)
	}
	fields := map[string]any{
		fieldSchemaVersion:    SchemaVersionFSMState,
		fieldCurrentState:     string(st.current),
		fieldStateEnteredAtNs: strconv.FormatInt(st.stateEnteredAt.UTC().UnixNano(), 10),
		fieldCooldownAnchorNs: strconv.FormatInt(st.cooldownAnchorAt.UTC().UnixNano(), 10),
		fieldUpdatedAtNs:      strconv.FormatInt(st.updatedAt.UTC().UnixNano(), 10),
	}
	swapped, err := s.client.SetFSMStateCAS(ctx, stateKey, fieldCurrentState, expectedPrior, fields)
	if err != nil {
		return false, fmt.Errorf("fsm: store save cas: %w", err)
	}
	if !swapped {
		return false, nil
	}
	if len(historyEntry) > 0 {
		histKey, herr := keys.FSMHistory(workloadID)
		if herr != nil {
			return true, fmt.Errorf("fsm: store history key: %w", herr)
		}
		if aerr := s.client.AppendFSMHistory(ctx, histKey, historyEntry, historyCap); aerr != nil {
			return true, fmt.Errorf("fsm: store history append: %w", aerr)
		}
	}
	return true, nil
}

// LoadAll scans every durable FSM-state key and parses it into a
// restoredWorkload. A key that races deletion (HGETALL empty), or whose
// hash is malformed or carries an unknown schema_version, is skipped
// rather than aborting recovery of the rest. The skipped count is
// returned so the caller can surface it.
func (s *Store) LoadAll(ctx context.Context) (recovered []restoredWorkload, skipped int, err error) {
	stateKeys, err := s.client.ScanFSMStateKeys(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("fsm: store loadall scan: %w", err)
	}
	recovered = make([]restoredWorkload, 0, len(stateKeys))
	for _, k := range stateKeys {
		h, gerr := s.client.GetFSMState(ctx, k)
		if errors.Is(gerr, redisclient.ErrKeyMissing) {
			continue
		}
		if gerr != nil {
			return nil, skipped, fmt.Errorf("fsm: store loadall get %q: %w", k, gerr)
		}
		ps, perr := parsePersisted(h)
		if perr != nil {
			skipped++
			continue
		}
		recovered = append(recovered, restoredWorkload{
			workloadID: strings.TrimPrefix(k, keys.FSMStatePrefix),
			state:      ps,
		})
	}
	return recovered, skipped, nil
}

// parsePersisted decodes a persisted FSM-state hash, validating the
// schema version and the state enum.
func parsePersisted(h map[string]string) (persistedState, error) {
	if v := h[fieldSchemaVersion]; v != SchemaVersionFSMState {
		return persistedState{}, fmt.Errorf("unknown schema_version %q", v)
	}
	cur := schema.PodSecurityState(h[fieldCurrentState])
	if !validPersistedState(cur) {
		return persistedState{}, fmt.Errorf("invalid current_state %q", h[fieldCurrentState])
	}
	enteredNs, err := strconv.ParseInt(h[fieldStateEnteredAtNs], 10, 64)
	if err != nil {
		return persistedState{}, fmt.Errorf("state_entered_at_ns: %w", err)
	}
	anchorNs, err := strconv.ParseInt(h[fieldCooldownAnchorNs], 10, 64)
	if err != nil {
		return persistedState{}, fmt.Errorf("cooldown_anchor_ns: %w", err)
	}
	return persistedState{
		current:          cur,
		stateEnteredAt:   time.Unix(0, enteredNs).UTC(),
		cooldownAnchorAt: time.Unix(0, anchorNs).UTC(),
	}, nil
}

// validPersistedState reports whether s is a known PodSecurityState.
func validPersistedState(s schema.PodSecurityState) bool {
	switch s {
	case schema.StateClean, schema.StateSuspicious, schema.StateRestricted,
		schema.StateQuarantined, schema.StatePreservedKilled:
		return true
	default:
		return false
	}
}
