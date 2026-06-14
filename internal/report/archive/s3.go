package archive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/encrypt"
)

// reportContentType is the MIME type stamped on every report object. The report
// is rendered Markdown (YAML front-matter + Markdown body), so text/markdown is
// the honest content type for an operator browsing the archive.
const reportContentType = "text/markdown; charset=utf-8"

// DefaultRetentionDays is the Story 4.6 object-lock retention default (FR45, PO
// ratification 5): 90 days. It is Helm-tunable via response.report_archive
// .retention_days.
const DefaultRetentionDays = 90

// S3Config configures an S3Archive. Endpoint/AccessKey/SecretKey/Bucket are
// required; UseSSL toggles TLS to the endpoint (off for a plaintext local
// MinIO, on for production). Region is optional (MinIO ignores it; AWS S3 needs
// it). KMSKeyAlias is the default SSE-KMS key applied to every PUT. RetentionDays
// is the object-lock retention period in days (default 90 when zero). Mode is
// the object-lock retention mode (default GOVERNANCE when empty, PO
// ratification 5).
type S3Config struct {
	Endpoint    string
	AccessKey   string
	SecretKey   string
	Bucket      string
	Region      string
	UseSSL      bool
	KMSKeyAlias string
	// RetentionDays is the per-object retention period in days. Zero falls back
	// to DefaultRetentionDays (90).
	RetentionDays int
	// Mode is the object-lock retention mode. Empty falls back to
	// RetentionGovernance (PO ratification 5).
	Mode RetentionMode
}

// errMissingS3Config is returned by NewS3Archive when a required field is
// absent, so a misconfigured deployment fails fast at wiring time rather than
// silently dropping report writes at the first finalisation (mirrors the
// forensics errMissingS3Config precedent).
var errMissingS3Config = errors.New("archive: incomplete S3 config (endpoint, access key, secret key, and bucket are all required)")

// errInvalidMode is returned by NewS3Archive when the configured object-lock
// mode is neither GOVERNANCE nor COMPLIANCE.
var errInvalidMode = errors.New("archive: object-lock mode must be GOVERNANCE or COMPLIANCE")

// S3Archive is the S3-compatible default ReportArchive (BI-1). It wraps a
// minio-go client and performs a content-addressed, SSE-KMS-encrypted PutObject
// under the caller-supplied key with per-object object-lock retention, plus a
// HEAD-then-skip dedup. minio-go is the EXISTING Story 4.2 S3 client (reused
// VERBATIM): a single well-maintained module, lighter than aws-sdk-go-v2,
// SSE-KMS via encrypt.NewSSEKMS, object-lock via the PutObject retention
// directive, and the native client for the MinIO integration boundary (AC6). No
// second S3 library is added.
//
// The writer uses ONLY PutObject (the report PUT plus the object-lock
// retain-until header) and StatObject (the dedup HEAD): the least-privilege
// write-and-head-only operation set (AC4, BI-4). It NEVER calls DeleteObject,
// ListObjects, GetObject, or MakeBucket in production (the bucket is an
// operator/Helm precondition, BI-5).
type S3Archive struct {
	client      objectStore
	bucket      string
	kmsKeyAlias string
	retention   time.Duration
	mode        RetentionMode
	now         func() time.Time
}

// objectStore is the minimal S3-object seam S3Archive depends on: exactly the
// two operations the least-privilege writer uses, PutObject (+ the object-lock
// retain-until directive) and StatObject (the dedup HEAD). *minio.Client
// satisfies it directly; a fake satisfies it in unit tests so the dedup
// HEAD-skip, the success path, and the exists/locked tolerance are unit-testable
// without a real S3 boundary (NFR35). It deliberately excludes Delete/List/Get
// (the write-and-head-only fence, BI-4).
type objectStore interface {
	PutObject(ctx context.Context, bucket, object string, reader io.Reader, size int64, opts minio.PutObjectOptions) (minio.UploadInfo, error)
	StatObject(ctx context.Context, bucket, object string, opts minio.StatObjectOptions) (minio.ObjectInfo, error)
}

// NewS3Archive constructs an S3Archive from cfg. It validates that all required
// fields are present and the object-lock mode is recognised, then initialises
// the minio-go client (reusing the Story 4.2 construction verbatim). It does NOT
// create the bucket (the writer must never assume create-bucket rights; an
// object-lock-enabled, versioned bucket is an operator/Helm precondition, BI-5).
func NewS3Archive(cfg S3Config) (*S3Archive, error) {
	if cfg.Endpoint == "" || cfg.AccessKey == "" || cfg.SecretKey == "" || cfg.Bucket == "" {
		return nil, errMissingS3Config
	}
	mode := cfg.Mode
	if mode == "" {
		mode = RetentionGovernance
	}
	if !mode.IsValid() {
		return nil, fmt.Errorf("%w (got %q)", errInvalidMode, cfg.Mode)
	}
	days := cfg.RetentionDays
	if days <= 0 {
		days = DefaultRetentionDays
	}
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("archive: construct minio client: %w", err)
	}
	return &S3Archive{
		client:      client,
		bucket:      cfg.Bucket,
		kmsKeyAlias: cfg.KMSKeyAlias,
		retention:   time.Duration(days) * 24 * time.Hour,
		mode:        mode,
		now:         func() time.Time { return time.Now().UTC() },
	}, nil
}

// Put writes body under the content-addressed key, SSE-KMS encrypted, with
// per-object object-lock retention, and returns a Receipt on a confirmed write
// (AC1). It HEADs the key first (Has, AC2): if the object already exists it
// returns a Deduped receipt WITHOUT re-PUTting (the cost optimisation +
// object-lock write-collision guard, BI-7). A "key exists / object locked" PUT
// error from a lost HEAD race is tolerated as a non-fatal dedup outcome rather
// than a hard failure (BI-7).
//
// The object-lock retain-until is set INLINE on the PutObject directive (the
// X-Amz-Object-Lock-Retain-Until-Date + mode headers), so a single PutObject
// call durably lands the object AND its retention atomically: the writer needs
// only the s3:PutObject action (the retention headers are part of the PUT) plus
// s3:HeadObject for the dedup HEAD, matching the least-privilege grant (AC4,
// BI-4). The bucket MUST be object-lock-enabled (operator precondition, BI-5).
func (a *S3Archive) Put(ctx context.Context, key string, body []byte, opts PutOptions) (Receipt, error) {
	if key == "" {
		return Receipt{}, errors.New("archive: empty object key")
	}

	// AC2 dedup: HEAD-then-skip on the content-addressed key. A pre-existing
	// object is a no-op (the key encodes the content, so the bytes are
	// identical), avoiding a redundant PUT and an object-lock write collision.
	exists, herr := a.Has(ctx, key)
	if herr != nil {
		return Receipt{}, herr
	}
	if exists {
		return Receipt{Key: key, Bucket: a.bucket, Deduped: true}, nil
	}

	alias := opts.KMSKeyAlias
	if alias == "" {
		alias = a.kmsKeyAlias
	}
	mode := opts.RetentionMode
	if mode == "" {
		mode = a.mode
	}
	period := opts.RetentionPeriod
	if period <= 0 {
		period = a.retention
	}
	retainUntil := a.now().Add(period)

	putOpts, err := buildPutOptions(alias, mode, retainUntil)
	if err != nil {
		return Receipt{}, err
	}

	info, err := a.client.PutObject(ctx, a.bucket, key, bytes.NewReader(body), int64(len(body)), putOpts)
	if err != nil {
		// BI-7: a lost HEAD race against a second finalisation of identical
		// content can leave the object already present and under retention, so a
		// second PutObject is rejected by the store. Because the key encodes the
		// content (same key, same bytes), that rejection is a dedup no-op, NOT a
		// durable-write failure: tolerate it as a Deduped receipt rather than a
		// hard error that would block the DFIR path.
		if isAlreadyExistsOrLocked(err) {
			return Receipt{Key: key, Bucket: a.bucket, Deduped: true}, nil
		}
		return Receipt{}, fmt.Errorf("archive: put object %q to bucket %q: %w", key, a.bucket, err)
	}

	return Receipt{
		Key:         key,
		Bucket:      a.bucket,
		Size:        info.Size,
		ETag:        info.ETag,
		VersionID:   info.VersionID,
		RetainUntil: retainUntil,
	}, nil
}

// Has reports whether key already exists in the bucket via a StatObject (HEAD,
// AC2). A not-found maps to (false, nil); any other error maps to (false, err).
// This is the s3:HeadObject operation (AC4, BI-4): the writer's only read-shaped
// call, and it reads no object body.
func (a *S3Archive) Has(ctx context.Context, key string) (bool, error) {
	_, err := a.client.StatObject(ctx, a.bucket, key, minio.StatObjectOptions{})
	if err == nil {
		return true, nil
	}
	if isNotFound(err) {
		return false, nil
	}
	return false, fmt.Errorf("archive: head object %q in bucket %q: %w", key, a.bucket, err)
}

// buildPutOptions constructs the PutObject options for a report PUT (AC1):
// text/markdown content type, the SSE-KMS server-side-encryption directive when
// alias is non-empty (an empty alias leaves SSE to the bucket default, the
// no-KES MinIO integration path), and the per-object object-lock retention mode
// + retain-until date so the single PUT applies object lock. Extracted so the
// encryption + retention directives have direct unit coverage (the forensics
// buildPutOptions precedent).
func buildPutOptions(alias string, mode RetentionMode, retainUntil time.Time) (minio.PutObjectOptions, error) {
	putOpts := minio.PutObjectOptions{
		ContentType:     reportContentType,
		Mode:            minio.RetentionMode(mode),
		RetainUntilDate: retainUntil,
		SendContentMd5:  true,
	}
	if alias != "" {
		sse, err := encrypt.NewSSEKMS(alias, nil)
		if err != nil {
			return minio.PutObjectOptions{}, fmt.Errorf("archive: build SSE-KMS directive for key alias %q: %w", alias, err)
		}
		putOpts.ServerSideEncryption = sse
	}
	return putOpts, nil
}

// isNotFound reports whether err is an S3 object-not-found (a 404 / NoSuchKey),
// the benign Has miss the writer maps to (false, nil).
func isNotFound(err error) bool {
	resp := minio.ToErrorResponse(err)
	return resp.StatusCode == http.StatusNotFound || resp.Code == "NoSuchKey"
}

// isAlreadyExistsOrLocked reports whether a PUT error is an object-lock /
// retention write collision against a pre-existing identical object (the lost
// HEAD race, BI-7). MinIO and AWS return a method-not-allowed / precondition /
// retention error in this case; treat it as a dedup no-op rather than a hard
// failure.
func isAlreadyExistsOrLocked(err error) bool {
	resp := minio.ToErrorResponse(err)
	switch resp.StatusCode {
	case http.StatusMethodNotAllowed, http.StatusPreconditionFailed, http.StatusConflict:
		return true
	}
	switch resp.Code {
	case "ObjectLocked", "InvalidObjectState", "PreconditionFailed", "RetentionPeriodHold":
		return true
	}
	return false
}
