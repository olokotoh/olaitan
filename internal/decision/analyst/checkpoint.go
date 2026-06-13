package analyst

import (
	"context"

	"github.com/olokotoh/olaitan/internal/schema"
)

// CheckpointStore is the durability seam the Chain uses to checkpoint and
// resume an in-flight investigation (Story 3.9 FR29). The orchestrator
// depends only on this interface; the NATS-backed implementation lives in
// internal/decision/analyst/checkpoint and is wired in by the composition
// root, so the analyst package stays free of the transport layer.
//
// Semantics (BI-4): SaveL1/SaveL2 persist a completed step's validated
// output; LoadL1/LoadL2 return the last checkpointed output for a
// package_id, with a (zero, false, nil) MISS when none exists. A Save
// failure or a Load error is best-effort: the chain logs it and re-runs
// the step rather than aborting, so checkpointing is a durability
// optimisation and never a correctness dependency.
type CheckpointStore interface {
	SaveL1(ctx context.Context, packageID string, h schema.L1Hypothesis) error
	SaveL2(ctx context.Context, packageID string, v schema.L2Verification) error
	LoadL1(ctx context.Context, packageID string) (schema.L1Hypothesis, bool, error)
	LoadL2(ctx context.Context, packageID string) (schema.L2Verification, bool, error)
}
