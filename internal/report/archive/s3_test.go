package archive

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
)

// fakeStore is an in-memory objectStore seam: it drives the S3Archive Put/Has
// logic (dedup HEAD-skip, success, exists/locked tolerance) without a real S3
// boundary, so the least-privilege write-and-head-only path is unit-testable
// (NFR35). Configurable errors simulate the failure branches.
type fakeStore struct {
	objects    map[string]struct{}
	putCalls   int
	statCalls  int
	putErr     error // returned by PutObject when set
	statErr    error // returned by StatObject when set (e.g. a non-404 error)
	lastPutOpt minio.PutObjectOptions
}

func newFakeStore() *fakeStore { return &fakeStore{objects: make(map[string]struct{})} }

func (f *fakeStore) PutObject(_ context.Context, _ /*bucket*/, object string, reader io.Reader, _ int64, opts minio.PutObjectOptions) (minio.UploadInfo, error) {
	f.putCalls++
	f.lastPutOpt = opts
	if f.putErr != nil {
		return minio.UploadInfo{}, f.putErr
	}
	b, _ := io.ReadAll(reader)
	f.objects[object] = struct{}{}
	return minio.UploadInfo{Key: object, Size: int64(len(b)), ETag: "etag", VersionID: "v1"}, nil
}

func (f *fakeStore) StatObject(_ context.Context, _ /*bucket*/, object string, _ minio.StatObjectOptions) (minio.ObjectInfo, error) {
	f.statCalls++
	if f.statErr != nil {
		return minio.ObjectInfo{}, f.statErr
	}
	if _, ok := f.objects[object]; ok {
		return minio.ObjectInfo{Key: object}, nil
	}
	return minio.ObjectInfo{}, minio.ErrorResponse{StatusCode: http.StatusNotFound, Code: "NoSuchKey"}
}

// newArchiveWithStore builds an S3Archive backed by fs with a pinned clock.
func newArchiveWithStore(fs objectStore) *S3Archive {
	return &S3Archive{
		client:      fs,
		bucket:      "olaitan-reports",
		kmsKeyAlias: "alias/k",
		retention:   90 * 24 * time.Hour,
		mode:        RetentionGovernance,
		now:         func() time.Time { return time.Date(2026, 6, 14, 0, 0, 0, 0, time.UTC) },
	}
}

// TestPut_SuccessSetsRetentionAndKMS: a fresh key is PUT once, with the SSE-KMS
// directive + the object-lock retain-until (now + 90 days) on the directive, and
// the receipt carries the key/etag/version/retain-until.
func TestPut_SuccessSetsRetentionAndKMS(t *testing.T) {
	fs := newFakeStore()
	a := newArchiveWithStore(fs)
	r, err := a.Put(context.Background(), "reports/2026/06/14/x.md", []byte("body"), PutOptions{})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if r.Deduped {
		t.Error("a fresh key must not be deduped")
	}
	if fs.putCalls != 1 {
		t.Errorf("want 1 PutObject call, got %d", fs.putCalls)
	}
	if fs.lastPutOpt.ServerSideEncryption == nil {
		t.Error("the PUT must carry the SSE-KMS directive (alias configured)")
	}
	if fs.lastPutOpt.Mode != minio.Governance {
		t.Errorf("PUT object-lock mode = %q, want GOVERNANCE", fs.lastPutOpt.Mode)
	}
	wantRetain := time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC) // 2026-06-14 + 90 days
	if !r.RetainUntil.Equal(wantRetain) {
		t.Errorf("retain-until = %v, want %v (now + 90 days)", r.RetainUntil, wantRetain)
	}
	if r.Key != "reports/2026/06/14/x.md" || r.ETag != "etag" || r.VersionID != "v1" {
		t.Errorf("receipt fields wrong: %+v", r)
	}
}

// TestPut_HeadSkipDedup: when the key already exists, Put is a HEAD-detected
// no-op (AC2): no PutObject call, a Deduped receipt.
func TestPut_HeadSkipDedup(t *testing.T) {
	fs := newFakeStore()
	fs.objects["reports/2026/06/14/x.md"] = struct{}{}
	a := newArchiveWithStore(fs)
	r, err := a.Put(context.Background(), "reports/2026/06/14/x.md", []byte("body"), PutOptions{})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if !r.Deduped {
		t.Error("a pre-existing key must be a HEAD-detected dedup no-op")
	}
	if fs.putCalls != 0 {
		t.Errorf("a deduped Put must NOT call PutObject, got %d calls", fs.putCalls)
	}
}

// TestPut_HeadErrorSurfaces: a non-404 StatObject error surfaces (the writer
// cannot confirm absence, so it does not blindly PUT).
func TestPut_HeadErrorSurfaces(t *testing.T) {
	fs := newFakeStore()
	fs.statErr = minio.ErrorResponse{StatusCode: http.StatusForbidden, Code: "AccessDenied"}
	a := newArchiveWithStore(fs)
	if _, err := a.Put(context.Background(), "reports/2026/06/14/x.md", []byte("body"), PutOptions{}); err == nil {
		t.Fatal("a non-404 HEAD error must surface")
	}
	if fs.putCalls != 0 {
		t.Error("a HEAD error must not proceed to PutObject")
	}
}

// TestPut_ExistsLockedToleratedAsDedup: a PUT rejected by the object-lock /
// retention write collision (the lost HEAD race, BI-7) is tolerated as a Deduped
// no-op, NOT a hard failure that would block the DFIR path.
func TestPut_ExistsLockedToleratedAsDedup(t *testing.T) {
	fs := newFakeStore()
	fs.putErr = minio.ErrorResponse{StatusCode: http.StatusMethodNotAllowed, Code: "ObjectLocked"}
	a := newArchiveWithStore(fs)
	r, err := a.Put(context.Background(), "reports/2026/06/14/x.md", []byte("body"), PutOptions{})
	if err != nil {
		t.Fatalf("an exists/locked PUT collision must be tolerated, got %v", err)
	}
	if !r.Deduped {
		t.Error("an exists/locked PUT collision must be a Deduped no-op")
	}
}

// TestPut_DurableErrorSurfaces: a generic (non-dedup) PUT error surfaces as a
// hard failure (the fail-loud path the DFIR agent counts).
func TestPut_DurableErrorSurfaces(t *testing.T) {
	fs := newFakeStore()
	fs.putErr = errors.New("dial timeout")
	a := newArchiveWithStore(fs)
	if _, err := a.Put(context.Background(), "reports/2026/06/14/x.md", []byte("body"), PutOptions{}); err == nil {
		t.Fatal("a generic PUT error must surface as a durable-write failure")
	}
}

// TestPut_PerCallOverrides: per-call PutOptions override the archive defaults
// (KMS alias, retention mode + period).
func TestPut_PerCallOverrides(t *testing.T) {
	fs := newFakeStore()
	a := newArchiveWithStore(fs)
	r, err := a.Put(context.Background(), "reports/2026/06/14/x.md", []byte("body"), PutOptions{
		RetentionMode:   RetentionCompliance,
		RetentionPeriod: 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if fs.lastPutOpt.Mode != minio.Compliance {
		t.Errorf("per-call mode override ignored: %q", fs.lastPutOpt.Mode)
	}
	if want := time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC); !r.RetainUntil.Equal(want) {
		t.Errorf("per-call retention override ignored: retain-until = %v, want %v", r.RetainUntil, want)
	}
}

// TestHas_HitMissAndError: Has is true for a present key, false for an absent
// key (404), and an error for a non-404 failure.
func TestHas_HitMissAndError(t *testing.T) {
	fs := newFakeStore()
	fs.objects["present"] = struct{}{}
	a := newArchiveWithStore(fs)

	if has, err := a.Has(context.Background(), "present"); err != nil || !has {
		t.Errorf("present key: has=%v err=%v", has, err)
	}
	if has, err := a.Has(context.Background(), "absent"); err != nil || has {
		t.Errorf("absent key: has=%v err=%v", has, err)
	}

	fs.statErr = minio.ErrorResponse{StatusCode: http.StatusForbidden}
	if has, err := a.Has(context.Background(), "x"); err == nil || has {
		t.Errorf("a non-404 HEAD error must surface: has=%v err=%v", has, err)
	}
}

// TestNewS3Archive_MissingConfigFailsFast: an incomplete S3 config (missing any
// of endpoint/access-key/secret-key/bucket) fails fast at construction rather
// than silently dropping report writes at the first finalisation.
func TestNewS3Archive_MissingConfigFailsFast(t *testing.T) {
	full := S3Config{Endpoint: "127.0.0.1:9000", AccessKey: "a", SecretKey: "s", Bucket: "b"}
	for _, tc := range []struct {
		name   string
		mutate func(*S3Config)
	}{
		{"no endpoint", func(c *S3Config) { c.Endpoint = "" }},
		{"no access key", func(c *S3Config) { c.AccessKey = "" }},
		{"no secret key", func(c *S3Config) { c.SecretKey = "" }},
		{"no bucket", func(c *S3Config) { c.Bucket = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := full
			tc.mutate(&cfg)
			if _, err := NewS3Archive(cfg); !errors.Is(err, errMissingS3Config) {
				t.Fatalf("want errMissingS3Config, got %v", err)
			}
		})
	}
}

// TestNewS3Archive_Defaults: an omitted mode defaults to GOVERNANCE (PO
// ratification 5) and an omitted/zero retention defaults to 90 days.
func TestNewS3Archive_Defaults(t *testing.T) {
	a, err := NewS3Archive(S3Config{Endpoint: "127.0.0.1:9000", AccessKey: "a", SecretKey: "s", Bucket: "b"})
	if err != nil {
		t.Fatalf("NewS3Archive: %v", err)
	}
	if a.mode != RetentionGovernance {
		t.Errorf("default object-lock mode = %q, want GOVERNANCE", a.mode)
	}
	if want := time.Duration(DefaultRetentionDays) * 24 * time.Hour; a.retention != want {
		t.Errorf("default retention = %v, want %v (90 days)", a.retention, want)
	}
}

// TestNewS3Archive_RetentionAndModeOverride: an explicit retention + COMPLIANCE
// mode are honoured.
func TestNewS3Archive_RetentionAndModeOverride(t *testing.T) {
	a, err := NewS3Archive(S3Config{
		Endpoint: "127.0.0.1:9000", AccessKey: "a", SecretKey: "s", Bucket: "b",
		RetentionDays: 30, Mode: RetentionCompliance,
	})
	if err != nil {
		t.Fatalf("NewS3Archive: %v", err)
	}
	if a.mode != RetentionCompliance {
		t.Errorf("mode = %q, want COMPLIANCE", a.mode)
	}
	if want := 30 * 24 * time.Hour; a.retention != want {
		t.Errorf("retention = %v, want %v (30 days)", a.retention, want)
	}
}

// TestNewS3Archive_InvalidModeRejected: an unrecognised object-lock mode is a
// construction error.
func TestNewS3Archive_InvalidModeRejected(t *testing.T) {
	_, err := NewS3Archive(S3Config{
		Endpoint: "127.0.0.1:9000", AccessKey: "a", SecretKey: "s", Bucket: "b",
		Mode: RetentionMode("LENIENT"),
	})
	if !errors.Is(err, errInvalidMode) {
		t.Fatalf("want errInvalidMode, got %v", err)
	}
}

// TestRetentionMode_IsValid: only GOVERNANCE and COMPLIANCE are valid.
func TestRetentionMode_IsValid(t *testing.T) {
	for _, m := range []RetentionMode{RetentionGovernance, RetentionCompliance} {
		if !m.IsValid() {
			t.Errorf("%q must be valid", m)
		}
	}
	for _, m := range []RetentionMode{"", "lenient", "governance"} {
		if m.IsValid() {
			t.Errorf("%q must be invalid", m)
		}
	}
}

// TestBuildPutOptions_SSEKMSDirective: a non-empty alias builds a non-nil
// SSE-KMS server-side-encryption directive; an empty alias leaves SSE to the
// bucket default (no directive). Removing the SSE assignment is caught here (the
// KMS-marker contract, AC1/AC6).
func TestBuildPutOptions_SSEKMSDirective(t *testing.T) {
	retain := time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)

	withAlias, err := buildPutOptions("alias/olaitan-reports", RetentionGovernance, retain)
	if err != nil {
		t.Fatalf("buildPutOptions: %v", err)
	}
	if withAlias.ServerSideEncryption == nil {
		t.Fatal("a non-empty alias must build a non-nil SSE-KMS directive")
	}
	if withAlias.ServerSideEncryption.Type() != "KMS" {
		t.Errorf("SSE directive type = %q, want KMS", withAlias.ServerSideEncryption.Type())
	}

	noAlias, err := buildPutOptions("", RetentionGovernance, retain)
	if err != nil {
		t.Fatalf("buildPutOptions: %v", err)
	}
	if noAlias.ServerSideEncryption != nil {
		t.Error("an empty alias must leave SSE to the bucket default (no directive)")
	}
}

// TestBuildPutOptions_RetentionDirective: the object-lock mode + retain-until
// date are stamped on the PutObject directive, so the single PUT applies object
// lock (AC1, BI-5). The content type is text/markdown.
func TestBuildPutOptions_RetentionDirective(t *testing.T) {
	retain := time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)
	opts, err := buildPutOptions("", RetentionCompliance, retain)
	if err != nil {
		t.Fatalf("buildPutOptions: %v", err)
	}
	if opts.Mode != minio.Compliance {
		t.Errorf("retention mode = %q, want COMPLIANCE", opts.Mode)
	}
	if !opts.RetainUntilDate.Equal(retain) {
		t.Errorf("retain-until = %v, want %v", opts.RetainUntilDate, retain)
	}
	if !strings.HasPrefix(opts.ContentType, "text/markdown") {
		t.Errorf("content type = %q, want text/markdown", opts.ContentType)
	}
}

// TestIsNotFound: a 404 / NoSuchKey is a not-found (the benign Has miss); any
// other error is not.
func TestIsNotFound(t *testing.T) {
	notFound := minio.ErrorResponse{StatusCode: http.StatusNotFound}
	if !isNotFound(notFound) {
		t.Error("a 404 must be not-found")
	}
	noSuchKey := minio.ErrorResponse{Code: "NoSuchKey"}
	if !isNotFound(noSuchKey) {
		t.Error("a NoSuchKey must be not-found")
	}
	other := minio.ErrorResponse{StatusCode: http.StatusForbidden}
	if isNotFound(other) {
		t.Error("a 403 must NOT be not-found")
	}
}

// TestIsAlreadyExistsOrLocked: an object-lock / retention write collision is
// tolerated as a dedup no-op (BI-7); a generic error is not.
func TestIsAlreadyExistsOrLocked(t *testing.T) {
	for _, e := range []minio.ErrorResponse{
		{StatusCode: http.StatusMethodNotAllowed},
		{StatusCode: http.StatusPreconditionFailed},
		{StatusCode: http.StatusConflict},
		{Code: "ObjectLocked"},
		{Code: "PreconditionFailed"},
	} {
		if !isAlreadyExistsOrLocked(e) {
			t.Errorf("%+v must be treated as an exists/locked dedup outcome", e)
		}
	}
	if isAlreadyExistsOrLocked(minio.ErrorResponse{StatusCode: http.StatusInternalServerError}) {
		t.Error("a 500 must NOT be treated as a dedup outcome")
	}
	if isAlreadyExistsOrLocked(errors.New("dial timeout")) {
		t.Error("a transport error must NOT be treated as a dedup outcome")
	}
}

// TestPut_EmptyKeyRejected: a Put with an empty key is rejected before any S3
// call (a programming-error guard).
func TestPut_EmptyKeyRejected(t *testing.T) {
	a, err := NewS3Archive(S3Config{Endpoint: "127.0.0.1:9000", AccessKey: "a", SecretKey: "s", Bucket: "b"})
	if err != nil {
		t.Fatalf("NewS3Archive: %v", err)
	}
	if _, perr := a.Put(context.Background(), "", []byte("x"), PutOptions{}); perr == nil {
		t.Fatal("an empty key must be rejected")
	}
}

// TestFakeArchive_ContentAddressedDedup is the in-memory fake's HEAD-then-skip
// proof (AC2): a second Put of the same key is a deduped no-op, and the
// write-and-head-only operation set is exercised without docker. The fake is the
// reusable ReportArchive the unit-testable surface relies on (NFR35).
func TestFakeArchive_ContentAddressedDedup(t *testing.T) {
	fa := NewFakeArchive()
	const key = "reports/2026/06/14/abc.md"

	r1, err := fa.Put(context.Background(), key, []byte("body"), PutOptions{})
	if err != nil {
		t.Fatalf("first put: %v", err)
	}
	if r1.Deduped {
		t.Error("first put must not be deduped")
	}
	has, err := fa.Has(context.Background(), key)
	if err != nil || !has {
		t.Fatalf("Has after put: has=%v err=%v", has, err)
	}
	r2, err := fa.Put(context.Background(), key, []byte("body"), PutOptions{})
	if err != nil {
		t.Fatalf("second put: %v", err)
	}
	if !r2.Deduped {
		t.Error("a second put of the same key must be a HEAD-detected dedup no-op")
	}
	// Only ONE durable object was written despite two Puts (content-addressing).
	if n := fa.PutCount(); n != 1 {
		t.Errorf("durable put count = %d, want 1 (dedup no-op)", n)
	}
	// Body / Keys expose the stored object for cross-package assertions.
	if body, ok := fa.Body(key); !ok || string(body) != "body" {
		t.Errorf("Body(%q) = %q,%v; want \"body\",true", key, body, ok)
	}
	if keys := fa.Keys(); len(keys) != 1 || keys[0] != key {
		t.Errorf("Keys() = %v, want [%q]", keys, key)
	}
}
