// Package forensics implements the Story 4.2 forensic capture controller
// (FR36). When the response-ring FSM transitions a workload into
// PRESERVED_KILLED (the Story 4.1 terminal kill state), this package captures
// a forensic bundle of the doomed pod(s) (per-container logs including the
// previous terminated container's logs, the pod spec/status, recent events,
// and a best-effort filesystem tar of the writable layers), uploads the bundle
// to an S3-compatible object store KMS-encrypted under a content-addressed
// SHA-256 key, and ONLY AFTER a confirmed upload acknowledgement deletes the
// pod(s) via the Kubernetes API.
//
// Chosen path (BI-1/BI-2, ADR-2026-05-02-01): this is the DOCUMENTED FALLBACK
// (Path A), implemented in kubectl_fallback.go. CRIU (Path B) is the rejected
// alternative: containerd 1.7 (the pinned substrate) lacks the
// CheckpointContainer CRI RPC, and CRIU fails to initialise on the kernel
// substrate. criu.go exists only as a dormant, project-owner-gated stub and is
// never wired live.
//
// Capture-before-delete with S3-ack gating is the load-bearing invariant
// (AC3): if the upload fails after retry, the controller does NOT delete the
// pod (forensic preservation has priority over the kill), increments
// olaitan_forensic_writes_deferred_total, and leaves the pod in place. The pod
// stays network-isolated because Story 4.1 retains the QUARANTINED deny-all
// NetworkPolicy on a kill (BI-5); Story 4.7 owns the deferred-write retry queue
// that eventually catches up.
//
// Ring discipline (BI-7): this package is Ring 4 (response). It owns its own
// minimal uploader interface (Uploader) rather than hard-depending on the
// not-yet-built Ring 5 hardened archive writer (internal/report/archive,
// Story 4.6). When Story 4.6 lands it either implements Uploader and is
// injected, or this minimal uploader is refactored to delegate to it.
package forensics

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/encrypt"
)

// UploadOptions carries the per-object encryption directive (BI-7). The
// KMSKeyAlias selects the SSE-KMS customer master key the object store encrypts
// the object at rest with (NFR17). An empty alias means the bucket's default
// SSE configuration applies (the uploader does not force an explicit key).
type UploadOptions struct {
	// KMSKeyAlias is the SSE-KMS key id/alias to encrypt the object with. Empty
	// leaves SSE to the bucket default.
	KMSKeyAlias string
}

// Ack is the upload acknowledgement returned to the caller on a successful PUT.
// The forensic controller treats a non-error Ack as the gate that permits the
// subsequent pod delete (AC3, capture-before-delete). It carries the
// content-addressed key actually written and the object's reported size and
// ETag so the controller can log a durable, auditable forensic-write record.
type Ack struct {
	// Key is the content-addressed object key the bundle was written under.
	Key string
	// Bucket is the destination bucket.
	Bucket string
	// Size is the number of bytes the object store reports it stored.
	Size int64
	// ETag is the object store's entity tag for the stored object.
	ETag string
	// VersionID is the object version when the bucket is versioned (empty
	// otherwise). Object lock/retention is Story 4.6; 4.2 records the version
	// only for the audit trail.
	VersionID string
}

// Uploader is the forensics-OWNED Ring-4 minimal S3 boundary (BI-7). It is
// deliberately tiny: a single content-addressed, KMS-encrypted PUT. Object
// lock, retention, access logging, and dedup-no-op hardening are Story 4.6 and
// are NOT part of this interface. The controller depends on this interface (not
// a concrete client) so unit tests inject a fake and Story 4.6 can supply a
// hardened implementation without touching the controller.
//
// Upload MUST be idempotent under a content-addressed key: a re-PUT of byte
// identical content is semantically a no-op (Open Assumption 3). It returns an
// Ack only after the object store confirms the write; any error means the write
// did not durably land and the caller MUST NOT delete the pod.
type Uploader interface {
	Upload(ctx context.Context, key string, r io.Reader, size int64, opts UploadOptions) (Ack, error)
}

// MinioConfig configures a MinioUploader. Endpoint/AccessKey/SecretKey/Bucket
// are required; UseSSL toggles TLS to the endpoint (off for a plaintext local
// MinIO, on for production). Region is optional (MinIO ignores it; AWS S3 needs
// it). KMSKeyAlias is the default SSE-KMS key applied to every PUT when the
// per-call UploadOptions does not override it.
type MinioConfig struct {
	Endpoint    string
	AccessKey   string
	SecretKey   string
	Bucket      string
	Region      string
	UseSSL      bool
	KMSKeyAlias string
}

// errMissingS3Config is returned by NewMinioUploader when a required field is
// absent, so a misconfigured deployment fails fast at wiring time rather than
// silently dropping forensic writes at the first kill.
var errMissingS3Config = errors.New("forensics: incomplete S3 uploader config (endpoint, access key, secret key, and bucket are all required)")

// MinioUploader is the minimal concrete Uploader (BI-7). It wraps a minio-go
// client and performs a single SSE-KMS-encrypted PutObject under the
// content-addressed key the caller computed. minio-go is the chosen S3 client:
// it is a single well-maintained module, far lighter than the modular
// aws-sdk-go-v2 surface, supports SSE-KMS via encrypt.NewSSEKMS, and is the
// native client for the MinIO integration boundary (AC6).
type MinioUploader struct {
	client      *minio.Client
	bucket      string
	kmsKeyAlias string
}

// NewMinioUploader constructs a MinioUploader from cfg. It validates that all
// required fields are present and initialises the minio-go client. It does NOT
// create the bucket (a forensic uploader must never assume create-bucket
// rights; the bucket is an operator/Helm precondition).
func NewMinioUploader(cfg MinioConfig) (*MinioUploader, error) {
	if cfg.Endpoint == "" || cfg.AccessKey == "" || cfg.SecretKey == "" || cfg.Bucket == "" {
		return nil, errMissingS3Config
	}
	client, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("forensics: construct minio client: %w", err)
	}
	return &MinioUploader{
		client:      client,
		bucket:      cfg.Bucket,
		kmsKeyAlias: cfg.KMSKeyAlias,
	}, nil
}

// Upload writes r (size bytes) to the configured bucket under key, SSE-KMS
// encrypted, and returns an Ack only on a confirmed write. The KMS key is the
// per-call opts.KMSKeyAlias when set, else the uploader's default. A zero/empty
// resolved key leaves SSE to the bucket default rather than failing, so a MinIO
// deployment without a configured KMS key still stores the (bucket-encrypted)
// forensic bundle.
func (u *MinioUploader) Upload(ctx context.Context, key string, r io.Reader, size int64, opts UploadOptions) (Ack, error) {
	alias := opts.KMSKeyAlias
	if alias == "" {
		alias = u.kmsKeyAlias
	}
	putOpts, err := buildPutOptions(alias)
	if err != nil {
		return Ack{}, err
	}
	info, err := u.client.PutObject(ctx, u.bucket, key, r, size, putOpts)
	if err != nil {
		return Ack{}, fmt.Errorf("forensics: put object %q to bucket %q: %w", key, u.bucket, err)
	}
	return Ack{
		Key:       key,
		Bucket:    u.bucket,
		Size:      info.Size,
		ETag:      info.ETag,
		VersionID: info.VersionID,
	}, nil
}

// buildPutOptions constructs the PutObject options for a forensic bundle PUT,
// attaching the SSE-KMS server-side-encryption directive when alias is
// non-empty (NFR17). An empty alias yields NO SSE directive: SSE then falls to
// the bucket default (the no-KES MinIO integration path). Extracted from Upload
// so the encryption directive has direct unit coverage (round-1 review:
// MED+LOW). A non-empty alias MUST set putOpts.ServerSideEncryption to a
// non-nil SSE-KMS directive carrying the alias; removing that assignment is
// caught by TestBuildPutOptions.
func buildPutOptions(alias string) (minio.PutObjectOptions, error) {
	putOpts := minio.PutObjectOptions{
		ContentType: "application/gzip",
	}
	if alias != "" {
		sse, err := encrypt.NewSSEKMS(alias, nil)
		if err != nil {
			return minio.PutObjectOptions{}, fmt.Errorf("forensics: build SSE-KMS directive for key alias %q: %w", alias, err)
		}
		putOpts.ServerSideEncryption = sse
	}
	return putOpts, nil
}
