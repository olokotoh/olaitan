package fsm

import (
	"context"
	"encoding/json"
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
	var histKey string
	if len(historyEntry) > 0 {
		var herr error
		histKey, herr = keys.FSMHistory(workloadID)
		if herr != nil {
			return false, fmt.Errorf("fsm: store history key: %w", herr)
		}
	}
	// State write and history append commit in one transaction so they can
	// never diverge (round-3 review): a separate append could fail after
	// the CAS landed, and the replay path would then skip it (the CAS now
	// sees the target already persisted), permanently losing the row.
	swapped, err := s.client.SetFSMStateCAS(ctx, stateKey, fieldCurrentState, expectedPrior, fields, histKey, historyEntry, historyCap)
	if err != nil {
		return false, fmt.Errorf("fsm: store save: %w", err)
	}
	return swapped, nil
}

// LoadHistory reads the persisted FSM transition history for a workload from
// the Redis fsm:{workload_id}:history list, oldest-to-newest (Story 4.3). Each
// list entry is a JSON-marshalled schema.StateTransition (the same encoding the
// RedisSink.persist path appends). It is restart-safe: the settling controller
// reads the durable history at finalisation rather than relying on transitions
// observed in-process, so a controller restart mid-incident still publishes the
// full history. A malformed entry is skipped (best-effort) rather than failing
// the whole read, mirroring LoadAll's per-key skip discipline; a missing key
// yields an empty slice with no error.
func (s *Store) LoadHistory(ctx context.Context, workloadID string) ([]schema.StateTransition, error) {
	histKey, err := keys.FSMHistory(workloadID)
	if err != nil {
		return nil, fmt.Errorf("fsm: store load-history key: %w", err)
	}
	raw, err := s.client.GetFSMHistory(ctx, histKey)
	if err != nil {
		return nil, fmt.Errorf("fsm: store load-history: %w", err)
	}
	out := make([]schema.StateTransition, 0, len(raw))
	for _, b := range raw {
		var st schema.StateTransition
		if uerr := json.Unmarshal(b, &st); uerr != nil {
			// A malformed history entry must not poison the whole read; skip it.
			continue
		}
		out = append(out, st)
	}
	return out, nil
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
			// Key raced a deletion between SCAN and GET; nothing to recover.
			continue
		}
		if gerr != nil {
			// A transient per-key read error must not abort recovery of the
			// other workloads (NFR24 60s budget); skip and count it. A
			// fundamentally unreachable Redis would already have failed the
			// SCAN above.
			skipped++
			continue
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
	// updated_at_ns is optional on read (older rows without it are still
	// valid); a parse failure leaves updatedAt zero.
	updatedNs, _ := strconv.ParseInt(h[fieldUpdatedAtNs], 10, 64)
	return persistedState{
		current:          cur,
		stateEnteredAt:   time.Unix(0, enteredNs).UTC(),
		cooldownAnchorAt: time.Unix(0, anchorNs).UTC(),
		updatedAt:        time.Unix(0, updatedNs).UTC(),
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
