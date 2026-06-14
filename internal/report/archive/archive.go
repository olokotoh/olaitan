// Package archive hosts the Story 4.6 durable report writer (FR45), the Ring-5
// leaf that PUTs the ALREADY-GENERATED, ALREADY-REDACTED (Story 4.5)
// ForensicReport bytes to an S3-compatible object store under the
// content-addressed key Story 4.4 computed (reports/{yyyy}/{mm}/{dd}/{sha256}.md),
// KMS-encrypted, with S3 object lock applied for a Helm-tunable retention period
// (default 90 days), and content-addressed deduplication (HEAD-then-skip).
//
// # Backend-neutral interface (BI-1, PO ratification 1)
//
// "S3" means the S3-compatible API. The writer is the backend-neutral
// ReportArchive Go INTERFACE (a content-addressed Put plus a Has existence
// check); the DFIR agent depends on the INTERFACE, not on minio-go. The
// S3-compatible default implementation (S3Archive, s3.go) reuses the EXISTING
// Story 4.2 minio-go client construction + SSE-KMS directive (it does NOT add a
// second S3 library). A future native Azure Blob / GCS / filesystem backend can
// satisfy the SAME interface; those are clean-room-only and are NOT built here
// (BI-11).
//
// # Trust boundary and Ring discipline (BI-9)
//
// The report is a downstream post-mortem artifact; this package is a Ring-5
// LEAF. It must NOT import internal/report/dfir, internal/decision/score, or any
// FSM package: the DFIR agent calls INWARD to archive, never the reverse. The
// writer only PUTs bytes, sets per-object retention, HEADs for dedup, and
// records a metric; it never folds a score, never imports the FSM, and never
// re-redacts (Story 4.5 already redacted the bytes).
//
// # Scope fence (BI-11)
//
// This package does the DIRECT content-addressed PUT + KMS + object-lock +
// HEAD-dedup ONLY. The retry/deferred queue is Story 4.7 (on a durable-write
// failure the caller fails LOUD with a metric, NO inline retry loop); the
// notification webhook is Story 4.8. The writer NEVER creates the bucket in
// production code (an object-lock-enabled, versioned bucket is an operator/Helm
// precondition).
package archive

import (
	"context"
	"time"
)

// RetentionMode is the S3 object-lock retention mode the writer applies per
// object (PO ratification 5). GOVERNANCE is the default: a privileged identity
// holding the audited BypassGovernanceRetention permission can correct a
// mis-write, so a delete is never SILENT (defeating FR45's silent-mutation /
// silent-delete threat) while still allowing an operator override. COMPLIANCE is
// the stricter posture for regulated deployments: no override, immutable until
// expiry. The mode is Helm-tunable.
type RetentionMode string

const (
	// RetentionGovernance is the default object-lock mode (PO ratification 5):
	// retention is enforced, but a privileged identity with the audited
	// BypassGovernanceRetention permission can override it.
	RetentionGovernance RetentionMode = "GOVERNANCE"
	// RetentionCompliance is the stricter object-lock mode: retention is
	// immutable until expiry; no identity can override it.
	RetentionCompliance RetentionMode = "COMPLIANCE"
)

// IsValid reports whether m is one of the two recognised object-lock modes.
func (m RetentionMode) IsValid() bool {
	return m == RetentionGovernance || m == RetentionCompliance
}

// PutOptions carries the per-object write directives for a single report PUT.
// All fields are optional: a zero PutOptions falls back to the archive's
// configured defaults (the configured KMS alias, retention mode, and retention
// period). The per-call overrides exist so a caller (or a future backend) can
// vary the encryption key or retention on a single object without rebuilding the
// archive.
type PutOptions struct {
	// KMSKeyAlias overrides the archive's default SSE-KMS key alias for this
	// object. Empty leaves the archive default in force; if that is also empty,
	// SSE falls to the bucket default (no agent-applied directive).
	KMSKeyAlias string
	// RetentionMode overrides the archive's default object-lock mode for this
	// object. Empty leaves the archive default in force.
	RetentionMode RetentionMode
	// RetentionPeriod overrides the archive's default retention period for this
	// object (now + RetentionPeriod = the retain-until date). Zero leaves the
	// archive default in force.
	RetentionPeriod time.Duration
}

// Receipt is the durable-write acknowledgement the writer returns on a Put. It
// carries the content-addressed key actually written, the destination bucket,
// the object's reported size and ETag, the version id (object-lock buckets are
// versioned), the retain-until date the per-object retention was set to, and a
// Deduped flag that is true when the key already existed and the PUT was skipped
// (the AC2 HEAD-then-skip no-op).
type Receipt struct {
	// Key is the content-addressed object key the report was written under
	// (reports/{yyyy}/{mm}/{dd}/{sha256}.md).
	Key string
	// Bucket is the destination bucket.
	Bucket string
	// Size is the number of bytes the object store reports it stored. Zero on a
	// deduped no-op (the existing object's bytes were not re-read).
	Size int64
	// ETag is the object store's entity tag for the stored object. Empty on a
	// deduped no-op.
	ETag string
	// VersionID is the stored object's version (object-lock buckets are
	// versioned). Empty on a deduped no-op or a non-versioned bucket.
	VersionID string
	// RetainUntil is the object-lock retain-until date the per-object retention
	// was set to (now + the resolved retention period). Zero on a deduped no-op.
	RetainUntil time.Time
	// Deduped is true when Has reported the key already existed and the PUT was
	// skipped (AC2): the receipt then references the pre-existing object's key
	// with no new write performed.
	Deduped bool
}

// ReportArchive is the backend-neutral durable-report writer (BI-1, PO
// ratification 1). The DFIR agent depends on THIS interface, not on a concrete
// S3 client, so unit tests inject an in-memory fake and a future native backend
// (Azure Blob / GCS / filesystem) satisfies the same contract without touching
// the caller.
//
// Put writes body under the content-addressed key (the SHA-of-redacted-bytes
// key Story 4.4 computed and Story 4.5 narrowed; the caller supplies it, the
// archive never recomputes it), KMS-encrypted, with per-object object-lock
// retention applied. It is a HEAD-then-skip content-addressed no-op (AC2): if
// the key already exists, Put returns a Deduped receipt without re-writing.
// Because the key encodes the content, a re-PUT of byte-identical content is
// idempotent regardless; the HEAD-skip is a cost optimisation AND an
// object-lock write-collision guard (BI-7).
//
// Has reports whether the content-addressed key already exists in the archive (a
// HEAD/StatObject). A not-found is (false, nil); any other error is (false,
// err).
type ReportArchive interface {
	Put(ctx context.Context, key string, body []byte, opts PutOptions) (Receipt, error)
	Has(ctx context.Context, key string) (bool, error)
}
