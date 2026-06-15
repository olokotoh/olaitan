// Package capture fills the Story-5.1 Capturer seam (frozen in
// cmd/olaitan-eval/runner.go). It SUBSCRIBES to the run's NATS subjects and
// SERIALISES what it observes into the uniform six-artefact set under
// runs/<run_id>/: events.jsonl, evidence.jsonl, assessments.jsonl, fsm.jsonl,
// report.md, and metadata.yaml (FR54). It calls NO provider, writes NO prompt,
// and changes NO internal/ production behaviour: it only drains subjects that
// already exist and carry published payloads.
//
// The logic lives in this importable (non-main) package so the always-on
// embedded-NATS in-process integration test can drive it directly, mirroring
// the internal/eval/scenario single-source-of-truth extraction (Story 5.4
// BI-12). A thin cmd/olaitan-eval adapter delegates to it behind the frozen
// Capturer interface (the signature is unchanged, the 5.1 freeze).
package capture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	natsclient "github.com/olokotoh/olaitan/internal/nats"
	"github.com/olokotoh/olaitan/internal/subjects"
)

// EnvelopeSchemaVersion is the schema_version of the self-describing JSONL
// envelope contract itself (AC2/BI-4). Each line is one Envelope wrapping a
// verbatim source payload; the per-line schema_version field below identifies
// the SOURCE contract, while this constant names the wrapper contract recorded
// in docs/schema-versioning.md.
const EnvelopeSchemaVersion = "olaitan.eval.capture.envelope.v1"

// DefaultMaxRunSizeBytes is the per-run artefact size cap (AC4/BI-10): 500
// MiB. A typical single-trial run produces well under 50 MB; the cap is a
// fail-LOUD SIGNAL ("this run is anomalously large, investigate"), not a
// quota, so the artefacts are never deleted or truncated when it is exceeded.
const DefaultMaxRunSizeBytes int64 = 500 * 1024 * 1024

// Source-contract schema_version labels stamped on each artefact's envelope
// lines (AC2/BI-4). They identify the SOURCE payload contract; the payload's
// own schema_version (where it carries one) is preserved verbatim INSIDE the
// payload. These mirror the committed producer schema versions
// (internal/schema, internal/response/audit, internal/report/dfir).
const (
	schemaVersionEvent       = "event.v1"
	schemaVersionEvidence    = "evidence_package.v1"
	schemaVersionAssessment  = "audit.assessments.v1"
	schemaVersionTransition  = "audit.transitions.v1"
	schemaVersionReportEvent = "reports.generated.v1"
)

// Artefact file names (FR54). These stay EXACTLY as the epic + FR54 name them;
// only the SOURCE-subject names are reconciled to the real internal/subjects/
// constants (BI-1).
const (
	EventsArtefact      = "events.jsonl"
	EvidenceArtefact    = "evidence.jsonl"
	AssessmentsArtefact = "assessments.jsonl"
	FSMArtefact         = "fsm.jsonl"
	ReportArtefact      = "report.md"
	MetadataArtefact    = "metadata.yaml"
)

// Envelope is the self-describing JSONL line (AC2/BI-4). One Envelope per line
// wraps the verbatim decoded source payload so Story 5.5's pandas pipeline
// reads ONE shape across all 400 runs. SchemaVersion identifies the SOURCE
// contract; PublishedAt is the message publish/observation time; Subject is
// the real source subject; Payload is the raw decoded body, preserved
// verbatim (5.4 does NOT re-shape or re-validate it, that is the producer's
// contract).
type Envelope struct {
	SchemaVersion string          `json:"schema_version"`
	PublishedAt   string          `json:"published_at"`
	Subject       string          `json:"subject"`
	Payload       json.RawMessage `json:"payload"`
}

// jsonlSpec maps an artefact .jsonl file to the JetStream stream + filter
// subject it drains and the source-contract schema_version stamped on its
// envelopes (BI-1, the LOAD-BEARING subject-name reconciliation). NEVER
// hard-code the subject strings: they are taken from internal/subjects so a
// future subject rename flows through.
type jsonlSpec struct {
	artefact      string
	stream        string
	filterSubject string
	schemaVersion string
}

// jsonlSpecs is the four-artefact .jsonl drain table (BI-1/BI-2). assessments
// sources ONLY AUDIT.assessments: there is NO ASSESSMENTS.completed subject in
// the codebase, so the epic's "ASSESSMENTS.completed AND AUDIT.assessments"
// collapses to the single real subject and dedup is moot (BI-2).
func jsonlSpecs() []jsonlSpec {
	return []jsonlSpec{
		{
			artefact:      EventsArtefact,
			stream:        "EVENTS_RAW",
			filterSubject: subjects.RawPrefix + ">",
			schemaVersion: schemaVersionEvent,
		},
		{
			artefact:      EvidenceArtefact,
			stream:        "EVIDENCE",
			filterSubject: subjects.EvidencePackages,
			schemaVersion: schemaVersionEvidence,
		},
		{
			artefact:      AssessmentsArtefact,
			stream:        "AUDIT_ASSESSMENTS",
			filterSubject: subjects.AuditAssessments,
			schemaVersion: schemaVersionAssessment,
		},
		{
			artefact:      FSMArtefact,
			stream:        "AUDIT_TRANSITIONS",
			filterSubject: subjects.AuditTransitions,
			schemaVersion: schemaVersionTransition,
		},
	}
}

// reportSpec is the REPORTS.generated drain spec for the report.md assembler
// (BI-5). REPORTS.generated carries the report SHA256 + content-addressed URL,
// NOT the body, so report.md is assembled from the announcement header plus an
// honest no-S3 fallback (the body fetch is OQ3 / Story 4.6 territory).
func reportSpec() jsonlSpec {
	return jsonlSpec{
		artefact:      ReportArtefact,
		stream:        "REPORTS",
		filterSubject: subjects.ReportsGenerated,
		schemaVersion: schemaVersionReportEvent,
	}
}

// Config configures a Capturer.
type Config struct {
	// Client is the connected NATS/JetStream client whose streams carry the
	// run's subject traffic. A nil Client means NO subjects can be drained
	// (the no-NATS path, e.g. the cmd unit-test dispatch with no --nats-url):
	// the Capturer then writes honest EMPTY .jsonl files and a no-report
	// report.md so all six artefacts still exist (AC5) without pretending
	// traffic was observed.
	Client *natsclient.Client
	// Logger receives the size-cap alert and per-artefact drain logs.
	Logger *slog.Logger
	// DrainWindow bounds how long each subject drain waits for the next
	// message before concluding the subject is fully drained. It is small
	// (the scenario has already published by Capture time, BI-3); a too-long
	// window only slows an empty drain.
	DrainWindow time.Duration
}

// Capturer drains the run's subjects into the per-run artefact set behind the
// frozen Capturer seam (BI-3, BI-12). It opens ephemeral JetStream consumers
// at Capture time and DRAINS what the streams already hold (the scenario has
// published by then), writing one Envelope per line into each .jsonl writer
// and assembling report.md.
type Capturer struct {
	client      *natsclient.Client
	log         *slog.Logger
	drainWindow time.Duration
}

// defaultDrainWindow is the per-subject "no more messages" idle window. The
// streams are already populated by Capture time (BI-3), so a short window is
// enough to drain a fully-published subject without slowing an empty one.
const defaultDrainWindow = 750 * time.Millisecond

// New builds a Capturer. A nil Logger defaults to slog.Default; a
// non-positive DrainWindow defaults to defaultDrainWindow.
func New(cfg Config) *Capturer {
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	win := cfg.DrainWindow
	if win <= 0 {
		win = defaultDrainWindow
	}
	return &Capturer{client: cfg.Client, log: log, drainWindow: win}
}

// DrainCounts records how many envelopes each artefact captured, returned by
// Capture so the metadata writer can derive the measured fields and the
// integration test can assert the six-artefact shape.
type DrainCounts struct {
	Events      int
	Evidence    int
	Assessments int
	FSM         int
	Reports     int
}

// CaptureResult is the outcome of a Capture: the per-artefact envelope counts,
// the decoded FSM transitions + evidence packages (the measure-vs-target
// inputs, BI-9), and the report announcements.
type CaptureResult struct {
	Counts      DrainCounts
	Transitions []json.RawMessage
	Evidence    []json.RawMessage
	Reports     []json.RawMessage
}

// Capture drains the four .jsonl subjects + the report subject into runDir and
// assembles report.md (AC1). It returns the decoded transition/evidence/report
// payloads so the harness can compute the measured metadata fields against the
// scenario target (BI-9). metadata.yaml is written by the harness finalise path
// (Metadata.Write), NOT here, so it is produced on success OR failure (BI-6).
//
// On the no-NATS path (nil client) Capture writes honest EMPTY .jsonl files and
// a no-report report.md so all six non-metadata artefacts still exist (AC5)
// without fabricating traffic.
func (c *Capturer) Capture(ctx context.Context, runDir string) (CaptureResult, error) {
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		return CaptureResult{}, fmt.Errorf("create run dir %q: %w", runDir, err)
	}

	var res CaptureResult
	specs := jsonlSpecs()
	for _, spec := range specs {
		envs, raws, err := c.drainSubject(ctx, spec)
		if err != nil {
			return CaptureResult{}, fmt.Errorf("drain %s: %w", spec.artefact, err)
		}
		if err := writeJSONL(filepath.Join(runDir, spec.artefact), envs); err != nil {
			return CaptureResult{}, err
		}
		switch spec.artefact {
		case EventsArtefact:
			res.Counts.Events = len(envs)
		case EvidenceArtefact:
			res.Counts.Evidence = len(envs)
			res.Evidence = raws
		case AssessmentsArtefact:
			res.Counts.Assessments = len(envs)
		case FSMArtefact:
			res.Counts.FSM = len(envs)
			res.Transitions = raws
		}
	}

	// report.md from REPORTS.generated + the honest no-S3 fallback (BI-5).
	rspec := reportSpec()
	reportEnvs, reportRaws, err := c.drainSubject(ctx, rspec)
	if err != nil {
		return CaptureResult{}, fmt.Errorf("drain %s: %w", rspec.artefact, err)
	}
	res.Counts.Reports = len(reportEnvs)
	res.Reports = reportRaws
	if err := writeReport(filepath.Join(runDir, ReportArtefact), reportEnvs); err != nil {
		return CaptureResult{}, err
	}

	return res, nil
}

// drainSubject opens an ephemeral JetStream consumer on the spec's stream
// (filtered to the spec subject) and pulls every message the stream holds,
// wrapping each in an Envelope. The drain stops after drainWindow elapses with
// no new message (the stream is already fully published by Capture time, BI-3).
// A nil client (the no-NATS path) yields zero envelopes with no error so the
// artefact file is written empty rather than omitted (AC5).
func (c *Capturer) drainSubject(ctx context.Context, spec jsonlSpec) ([]Envelope, []json.RawMessage, error) {
	if c.client == nil {
		return nil, nil, nil
	}
	js := c.client.JetStream()
	if js == nil {
		return nil, nil, nil
	}

	stream, err := js.Stream(ctx, spec.stream)
	if err != nil {
		// A stream the run never provisioned (e.g. the RS arm produces no
		// REPORTS traffic at all) is an EMPTY drain, not an error: the
		// artefact file is written empty and report.md takes the no-report
		// fallback. Any other error is surfaced.
		if errors.Is(err, jetstream.ErrStreamNotFound) {
			c.log.Info("capture: stream absent, artefact captured empty",
				"artefact", spec.artefact, "stream", spec.stream)
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("open stream %s: %w", spec.stream, err)
	}

	cons, err := stream.CreateConsumer(ctx, jetstream.ConsumerConfig{
		AckPolicy:     jetstream.AckExplicitPolicy,
		DeliverPolicy: jetstream.DeliverAllPolicy,
		FilterSubject: spec.filterSubject,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("create consumer on %s: %w", spec.stream, err)
	}
	// Ephemeral consumers self-expire, but delete eagerly so a multi-arm run
	// does not accumulate idle consumers on a shared server.
	defer func() {
		dctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = stream.DeleteConsumer(dctx, cons.CachedInfo().Name)
	}()

	var envs []Envelope
	var raws []json.RawMessage
	for {
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		msg, ferr := cons.Next(jetstream.FetchMaxWait(c.drainWindow))
		if ferr != nil {
			// No more messages within the idle window: the subject is drained.
			break
		}
		env := Envelope{
			SchemaVersion: spec.schemaVersion,
			PublishedAt:   publishedAt(msg),
			Subject:       msg.Subject(),
			Payload:       json.RawMessage(append([]byte(nil), msg.Data()...)),
		}
		envs = append(envs, env)
		raws = append(raws, env.Payload)
		_ = msg.Ack()
	}
	return envs, raws, nil
}

// publishedAt returns the message's JetStream publish time as RFC3339Nano, or
// the empty-stamped zero time when the metadata is unavailable. This is the
// observation time the Envelope records (BI-4).
func publishedAt(msg jetstream.Msg) string {
	md, err := msg.Metadata()
	if err != nil || md == nil {
		return time.Time{}.UTC().Format(time.RFC3339Nano)
	}
	return md.Timestamp.UTC().Format(time.RFC3339Nano)
}

// writeJSONL writes one Envelope per line to path (creating an empty file when
// there are no envelopes, so the artefact still exists, AC5).
func writeJSONL(path string, envs []Envelope) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("create %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()
	enc := json.NewEncoder(f)
	for i := range envs {
		if err := enc.Encode(&envs[i]); err != nil {
			return fmt.Errorf("encode envelope into %q: %w", path, err)
		}
	}
	return nil
}

// DirSize sums the byte size of every regular file under dir (AC4/BI-10). It is
// the per-run artefact total the size cap is checked against at finalise.
func DirSize(dir string) (int64, error) {
	var total int64
	err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		total += info.Size()
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("sum dir size %q: %w", dir, err)
	}
	return total, nil
}
