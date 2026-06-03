// Package override implements the Story 2.7 operator-override controller
// (FR38/FR39). It is Ring 4 (architecture.md:803/956).
//
// An SRE pins a workload's FSM state by annotating its pod or owner with
// olaitan.io/state-override (and an optional olaitan.io/state-override-ttl).
// A controller goroutine polls (LISTs) pods on a ticker, resolves each
// annotated pod to its canonical workload_id via a Ring-clean owner walk
// (identity.go, NOT internal/collector/posture - a Ring-1 import that would
// violate the ring rule, BI-12), and reconciles the desired override set
// against Redis and the FSM:
//
//   - annotation present + valid target  -> Machine.Pin + Redis SetOverride
//     (native TTL). The reconcile is EDGE-TRIGGERED: the native TTL is a HARD
//     DEADLINE measured from first application and is NEVER refreshed for an
//     unchanged annotation (it counts down and auto-releases the override even
//     while the annotation remains, honouring AC2/FR39). An operator EDIT of
//     the annotation (state/ttl change) re-applies with a fresh native TTL.
//   - Redis key gone while the annotation remains (hard-deadline expiry) ->
//     Machine.ReleasePin and the workload+signature is marked "consumed" so
//     the still-present annotation does not re-pin (FR39).
//   - annotation gone, Redis key present (manual removal) -> ReleasePin +
//     DeleteOverride (AC4).
//   - target PRESERVED_KILLED -> reject with reason state_unavailable; an
//     unknown state -> reason invalid_state (BI-5). A rejection emits an
//     OVERRIDES.applied event with rejected:true and increments the
//     olaitan_response_override_rejected_total{reason} counter; it pins
//     nothing and writes no Redis key.
//
// The pin transition routes through the FSM's existing sink, so a pinned
// RESTRICTED/QUARANTINED drives the Story 2.4/2.5 NetworkPolicy enforcement
// and a pinned CLEAN drives the Story 2.6 removal with NO new enforcement
// code (BI-7).
//
// Dependency-ring direction (BI-12): this package imports only substrate
// (internal/schema, internal/keys, internal/config, internal/metrics,
// internal/redis, internal/nats, internal/subjects) and same-ring
// internal/response/fsm (for *fsm.Machine / PodState). It does NOT import
// internal/collector/* or internal/decision/*.
package override

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/olokotoh/olaitan/internal/keys"
	redisclient "github.com/olokotoh/olaitan/internal/redis"
	"github.com/olokotoh/olaitan/internal/schema"
)

// SchemaVersionOverride is stamped on every persisted override hash so a
// future format change is detectable on read (docs/schema-versioning.md).
const SchemaVersionOverride = "override.v1"

// Source labels where the operative annotation was read from (BI-9).
const (
	SourcePod   = "pod"
	SourceOwner = "owner"
)

// Persisted override-hash field names. Timestamps are nanosecond Unix int64
// strings, mirroring the fsm: store serialisation.
const (
	fieldSchemaVersion  = "schema_version"
	fieldRequestedState = "requested_state"
	fieldTTLSeconds     = "ttl_seconds"
	fieldOperatorID     = "operator_id"
	fieldAppliedAtNs    = "applied_at_ns"
	fieldSource         = "source"
)

// OverrideRecord is the durable projection of an active operator override.
type OverrideRecord struct {
	RequestedState schema.PodSecurityState
	TTLSeconds     int
	OperatorID     string
	AppliedAt      time.Time
	Source         string
}

// Store persists operator overrides to Redis and lists active ones for the
// reconcile loop. It mirrors fsm.Store: a thin typed wrapper over the shared
// redis client that builds keys via internal/keys and writes through the
// family-guarded SetOverride/GetOverride/DeleteOverride/ScanOverrideKeys
// setters (never Raw). Unlike fsm.Store, the override key carries a NATIVE
// Redis TTL equal to the requested duration (BI-3).
type Store struct {
	client *redisclient.Client
}

// NewStore returns a Store bound to client. A nil client is a construction
// error so the failure surfaces at startup, not on the first override.
func NewStore(client *redisclient.Client) (*Store, error) {
	if client == nil {
		return nil, errors.New("override: nil redis client")
	}
	return &Store{client: client}, nil
}

// Put writes the override record for workloadID with a native Redis TTL. The
// native TTL is a HARD DEADLINE: the controller writes the key only on a NEW
// override or an operator EDIT (a signature change), never on an unchanged
// re-apply, so the TTL counts down from first application and the override
// auto-releases on expiry even while the annotation remains (AC2/FR39).
func (s *Store) Put(ctx context.Context, workloadID string, rec OverrideRecord, ttl time.Duration) error {
	key, err := keys.Override(workloadID)
	if err != nil {
		return fmt.Errorf("override: put key: %w", err)
	}
	fields := map[string]any{
		fieldSchemaVersion:  SchemaVersionOverride,
		fieldRequestedState: string(rec.RequestedState),
		fieldTTLSeconds:     strconv.Itoa(rec.TTLSeconds),
		fieldOperatorID:     rec.OperatorID,
		fieldAppliedAtNs:    strconv.FormatInt(rec.AppliedAt.UTC().UnixNano(), 10),
		fieldSource:         rec.Source,
	}
	if err := s.client.SetOverride(ctx, key, fields, ttl); err != nil {
		return fmt.Errorf("override: put: %w", err)
	}
	return nil
}

// Get returns the override record for workloadID, present=false when the key
// is absent (native-TTL expiry or never set).
func (s *Store) Get(ctx context.Context, workloadID string) (OverrideRecord, bool, error) {
	key, err := keys.Override(workloadID)
	if err != nil {
		return OverrideRecord{}, false, fmt.Errorf("override: get key: %w", err)
	}
	h, err := s.client.GetOverride(ctx, key)
	if errors.Is(err, redisclient.ErrKeyMissing) {
		return OverrideRecord{}, false, nil
	}
	if err != nil {
		return OverrideRecord{}, false, fmt.Errorf("override: get: %w", err)
	}
	rec, perr := parseOverride(h)
	if perr != nil {
		return OverrideRecord{}, false, fmt.Errorf("override: parse %s: %w", workloadID, perr)
	}
	return rec, true, nil
}

// Delete removes the override key for workloadID (the AC4 manual-removal
// path). Deleting an absent key is a no-op.
func (s *Store) Delete(ctx context.Context, workloadID string) error {
	key, err := keys.Override(workloadID)
	if err != nil {
		return fmt.Errorf("override: delete key: %w", err)
	}
	if err := s.client.DeleteOverride(ctx, key); err != nil {
		return fmt.Errorf("override: delete: %w", err)
	}
	return nil
}

// ListActive scans the override: family and returns every active override
// keyed by workload_id, so the reconcile loop can compute the CURRENT set and
// detect releases (BI-4). A key that races deletion or whose hash is malformed
// is skipped rather than aborting the scan.
func (s *Store) ListActive(ctx context.Context) (map[string]OverrideRecord, error) {
	keysFound, err := s.client.ScanOverrideKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("override: list scan: %w", err)
	}
	out := make(map[string]OverrideRecord, len(keysFound))
	for _, k := range keysFound {
		workloadID, ok := workloadIDFromKey(k)
		if !ok {
			continue
		}
		h, gerr := s.client.GetOverride(ctx, k)
		if errors.Is(gerr, redisclient.ErrKeyMissing) {
			// Raced a native-TTL expiry between SCAN and GET; nothing active.
			continue
		}
		if gerr != nil {
			// Skip a transient per-key error rather than aborting the others.
			continue
		}
		rec, perr := parseOverride(h)
		if perr != nil {
			continue
		}
		out[workloadID] = rec
	}
	return out, nil
}

// workloadIDFromKey strips the override: prefix to recover the workload_id.
func workloadIDFromKey(key string) (string, bool) {
	if len(key) <= len(keys.OverridePrefix) {
		return "", false
	}
	if key[:len(keys.OverridePrefix)] != keys.OverridePrefix {
		return "", false
	}
	return key[len(keys.OverridePrefix):], true
}

// parseOverride decodes a persisted override hash, validating the schema
// version and the requested-state enum.
func parseOverride(h map[string]string) (OverrideRecord, error) {
	if v := h[fieldSchemaVersion]; v != SchemaVersionOverride {
		return OverrideRecord{}, fmt.Errorf("unknown schema_version %q", v)
	}
	state := schema.PodSecurityState(h[fieldRequestedState])
	ttl, _ := strconv.Atoi(h[fieldTTLSeconds])
	appliedNs, _ := strconv.ParseInt(h[fieldAppliedAtNs], 10, 64)
	return OverrideRecord{
		RequestedState: state,
		TTLSeconds:     ttl,
		OperatorID:     h[fieldOperatorID],
		AppliedAt:      time.Unix(0, appliedNs).UTC(),
		Source:         h[fieldSource],
	}, nil
}
