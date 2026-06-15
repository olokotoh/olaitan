package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/olokotoh/olaitan/internal/eval/capture"
	natsclient "github.com/olokotoh/olaitan/internal/nats"
)

// richCapturer is the thin cmd/olaitan-eval adapter that fills the FROZEN
// Capturer seam (runner.go) by delegating to the importable
// internal/eval/capture package (BI-12). The Capturer interface signature is
// UNCHANGED (the Story 5.1 freeze): Capture(ctx, runDir) error. The adapter
// keeps the rich logic out of package main so the always-on embedded-NATS
// in-process integration test can drive internal/eval/capture directly.
//
// It accumulates the LAST trial's CaptureResult so the harness finalise path
// (writeMetadataFinalised in main.go) can derive the measured metadata fields
// against the scenario target (BI-9) without reshaping the frozen interface.
type richCapturer struct {
	cap    *capture.Capturer
	logger *slog.Logger

	// lastResult holds the most recent trial's drained payloads (the
	// measure-vs-target inputs). For the AC5 single-trial run this is the
	// run's result; multi-trial aggregation is a Story 5.5 concern (OQ2,
	// run-level artefacts recommended).
	lastResult capture.CaptureResult
}

// newRichCapturer builds the rich Capturer adapter. client may be nil (the
// no-NATS path): the underlying Capturer then writes honest empty artefacts so
// all six still exist (AC5) without fabricating traffic.
func newRichCapturer(client *natsclient.Client, logger *slog.Logger) *richCapturer {
	if logger == nil {
		logger = slog.Default()
	}
	return &richCapturer{
		cap: capture.New(capture.Config{
			Client: client,
			Logger: logger,
		}),
		logger: logger,
	}
}

// Capture drains the run's subjects into runDir and assembles the five
// non-metadata artefacts (events/evidence/assessments/fsm/report). The
// run-level metadata.yaml is finalised by the harness (main.go) so it is
// produced on success OR failure (BI-6). It satisfies the frozen Capturer
// interface.
func (c *richCapturer) Capture(ctx context.Context, runDir string) error {
	res, err := c.cap.Capture(ctx, runDir)
	if err != nil {
		return fmt.Errorf("capture artefacts into %q: %w", runDir, err)
	}
	c.lastResult = res
	c.logger.Info("capture: artefacts written",
		"run_dir", runDir,
		"events", res.Counts.Events,
		"evidence", res.Counts.Evidence,
		"assessments", res.Counts.Assessments,
		"fsm", res.Counts.FSM,
		"reports", res.Counts.Reports)
	return nil
}
