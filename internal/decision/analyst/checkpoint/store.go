// Package checkpoint provides the NATS-backed analyst.CheckpointStore that
// persists L1/L2 investigation outputs to the INVESTIGATIONS.* subjects so a
// controller restart can resume an in-flight chain (Story 3.9 FR29). It is
// the composition-root wiring of NATS to the orchestrator's CheckpointStore
// seam; the orchestrator depends only on the interface, keeping the analyst
// package free of the transport layer.
package checkpoint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nats-io/nats.go/jetstream"

	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/schema"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// streamName is the JetStream stream that backs the INVESTIGATIONS.* subjects
// (internal/nats/streams.go). LoadL1/LoadL2 read the last message per subject.
const streamName = "INVESTIGATIONS"

// Store is the NATS-backed analyst.CheckpointStore. SaveL1/SaveL2 publish the
// validated step output to INVESTIGATIONS.{package_id}.{l1,l2} with a
// per-step WithMsgID so a re-publish is idempotent; LoadL1/LoadL2 fetch the
// last message per subject (a not-found is a clean miss).
type Store struct {
	nc *natsclient.Client
}

// New builds a Store over the shared NATS client. A nil client is an error.
func New(nc *natsclient.Client) (*Store, error) {
	if nc == nil {
		return nil, errors.New("checkpoint: nil nats client")
	}
	return &Store{nc: nc}, nil
}

// SaveL1 publishes the L1 hypothesis checkpoint for packageID.
func (s *Store) SaveL1(ctx context.Context, packageID string, h schema.L1Hypothesis) error {
	subj, err := subjects.InvestigationL1(packageID)
	if err != nil {
		return fmt.Errorf("checkpoint: l1 subject: %w", err)
	}
	if _, err := s.nc.PublishJS(ctx, subj, h, jetstream.WithMsgID(packageID+":l1")); err != nil {
		return fmt.Errorf("checkpoint: publish l1: %w", err)
	}
	return nil
}

// SaveL2 publishes the L2 verification checkpoint for packageID.
func (s *Store) SaveL2(ctx context.Context, packageID string, v schema.L2Verification) error {
	subj, err := subjects.InvestigationL2(packageID)
	if err != nil {
		return fmt.Errorf("checkpoint: l2 subject: %w", err)
	}
	if _, err := s.nc.PublishJS(ctx, subj, v, jetstream.WithMsgID(packageID+":l2")); err != nil {
		return fmt.Errorf("checkpoint: publish l2: %w", err)
	}
	return nil
}

// LoadL1 returns the last L1 checkpoint for packageID, or a (zero, false, nil)
// miss when none exists.
func (s *Store) LoadL1(ctx context.Context, packageID string) (schema.L1Hypothesis, bool, error) {
	subj, err := subjects.InvestigationL1(packageID)
	if err != nil {
		return schema.L1Hypothesis{}, false, fmt.Errorf("checkpoint: l1 subject: %w", err)
	}
	var h schema.L1Hypothesis
	ok, err := s.loadInto(ctx, subj, &h)
	return h, ok, err
}

// LoadL2 returns the last L2 checkpoint for packageID, or a miss.
func (s *Store) LoadL2(ctx context.Context, packageID string) (schema.L2Verification, bool, error) {
	subj, err := subjects.InvestigationL2(packageID)
	if err != nil {
		return schema.L2Verification{}, false, fmt.Errorf("checkpoint: l2 subject: %w", err)
	}
	var v schema.L2Verification
	ok, err := s.loadInto(ctx, subj, &v)
	return v, ok, err
}

// loadInto fetches the last message on subj and decodes it into `into`. A
// not-found is a clean miss (false, nil); a decode failure is an error.
func (s *Store) loadInto(ctx context.Context, subj string, into any) (bool, error) {
	stream, err := s.nc.JetStream().Stream(ctx, streamName)
	if err != nil {
		return false, fmt.Errorf("checkpoint: stream %s: %w", streamName, err)
	}
	msg, err := stream.GetLastMsgForSubject(ctx, subj)
	if err != nil {
		if errors.Is(err, jetstream.ErrMsgNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("checkpoint: get last msg %s: %w", subj, err)
	}
	if err := json.Unmarshal(msg.Data, into); err != nil {
		return false, fmt.Errorf("checkpoint: decode %s: %w", subj, err)
	}
	return true, nil
}
