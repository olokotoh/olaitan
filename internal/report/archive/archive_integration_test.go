//go:build integration

package archive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// integrationState holds the package-shared MinIO plumbing, configured once in
// TestMain and reused across the suite (AC6). It mirrors the Story 4.2 forensics
// integration TestMain env-gated skip/require contract (BI-6), but stands up an
// OBJECT-LOCK-ENABLED, versioned bucket (the report-archive requirement) under a
// distinct bucket name so the two integration boundaries stay independent (Open
// Assumption 2).
//
// Configuration via environment:
//
//	REPORT_ARCHIVE_INTEGRATION_SKIP=1     -> explicit opt-out, exit 0.
//	REPORT_ARCHIVE_INTEGRATION_REQUIRED=1 -> fail loudly if MinIO is unreachable.
//	S3_ENDPOINT   (default 127.0.0.1:9000)
//	S3_ACCESS_KEY (default minioadmin)
//	S3_SECRET_KEY (default minioadmin)
//	S3_BUCKET     (default olaitan-reports-it)
//	S3_KMS_KEY    (optional SSE-KMS key alias; empty => bucket default SSE)
var integrationState struct {
	endpoint  string
	accessKey string
	secretKey string
	bucket    string
	kmsKey    string
	client    *minio.Client
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func TestMain(m *testing.M) {
	if os.Getenv("REPORT_ARCHIVE_INTEGRATION_SKIP") == "1" {
		_, _ = os.Stderr.WriteString("report-archive integration: REPORT_ARCHIVE_INTEGRATION_SKIP=1, skipping (exit 0)\n")
		os.Exit(0)
	}
	integrationState.endpoint = envOr("S3_ENDPOINT", "127.0.0.1:9000")
	integrationState.accessKey = envOr("S3_ACCESS_KEY", "minioadmin")
	integrationState.secretKey = envOr("S3_SECRET_KEY", "minioadmin")
	integrationState.bucket = envOr("S3_BUCKET", "olaitan-reports-it")
	integrationState.kmsKey = os.Getenv("S3_KMS_KEY")

	client, err := minio.New(integrationState.endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(integrationState.accessKey, integrationState.secretKey, ""),
		Secure: false,
	})
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = ensureObjectLockBucket(ctx, client, integrationState.bucket)
		cancel()
	}
	if err != nil {
		if os.Getenv("REPORT_ARCHIVE_INTEGRATION_REQUIRED") == "1" {
			_, _ = os.Stderr.WriteString("report-archive integration: MinIO unavailable (REPORT_ARCHIVE_INTEGRATION_REQUIRED=1, failing): " + err.Error() + "\n")
			os.Exit(1)
		}
		_, _ = os.Stderr.WriteString("report-archive integration: MinIO unavailable; exiting 0 (set REPORT_ARCHIVE_INTEGRATION_REQUIRED=1 to fail loudly): " + err.Error() + "\n")
		os.Exit(0)
	}
	integrationState.client = client
	os.Exit(m.Run())
}

// ensureObjectLockBucket creates the report bucket with object lock ENABLED
// (which forces versioning) if it does not yet exist (test setup ONLY; the
// production writer never creates the bucket, BI-5).
func ensureObjectLockBucket(ctx context.Context, c *minio.Client, bucket string) error {
	exists, err := c.BucketExists(ctx, bucket)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return c.MakeBucket(ctx, bucket, minio.MakeBucketOptions{ObjectLocking: true})
}

func itArchive(t *testing.T) *S3Archive {
	t.Helper()
	if integrationState.client == nil {
		t.Skip("MinIO unavailable; skipping integration suite")
	}
	a, err := NewS3Archive(S3Config{
		Endpoint:      integrationState.endpoint,
		AccessKey:     integrationState.accessKey,
		SecretKey:     integrationState.secretKey,
		Bucket:        integrationState.bucket,
		UseSSL:        false,
		KMSKeyAlias:   integrationState.kmsKey,
		RetentionDays: 1, // short retention so the test object is not pinned for 90 days
		Mode:          RetentionGovernance,
	})
	if err != nil {
		t.Fatalf("NewS3Archive: %v", err)
	}
	return a
}

// reportKey content-addresses body under the Story 4.4 layout
// reports/{yyyy}/{mm}/{dd}/{sha256}.md, the key shape the production caller
// (the DFIR agent) computes; the archive never recomputes it (BI-2).
func reportKey(now time.Time, body []byte) string {
	sum := sha256.Sum256(body)
	t := now.UTC()
	return fmt.Sprintf("reports/%04d/%02d/%02d/%s.md", t.Year(), int(t.Month()), t.Day(), hex.EncodeToString(sum[:]))
}

// TestIntegration_ContentAddressedPutDedupRetentionKMS exercises the full
// Story 4.6 write path against a real, object-lock-enabled MinIO (AC6):
//
//	(a) a content-addressed PUT durably lands the redacted report under
//	    reports/{yyyy}/{mm}/{dd}/{sha256}.md;
//	(b) a SECOND write of identical content is a HEAD-detected no-op (AC2);
//	(c) per-object object-lock retention is applied (GetObjectRetention reports a
//	    retain-until marker);
//	(d) when an SSE-KMS alias is configured, the encryption marker is present on
//	    the uploaded object.
func TestIntegration_ContentAddressedPutDedupRetentionKMS(t *testing.T) {
	a := itArchive(t)
	ctx := context.Background()

	// Unique body per run so re-runs do not collide on a retained object.
	body := []byte("---\nschema_version: \"report.v1\"\nincident_id: \"it-" +
		fmt.Sprint(time.Now().UnixNano()) + "\"\n---\n\n## Analyst narrative\n\nThe miner ran.\n")
	key := reportKey(time.Now(), body)

	// (a) Content-addressed PUT durably lands.
	r1, err := a.Put(ctx, key, body, PutOptions{})
	if err != nil {
		t.Fatalf("first Put: %v", err)
	}
	if r1.Deduped {
		t.Error("first Put must not be deduped")
	}
	if r1.Key != key {
		t.Errorf("receipt key = %q, want %q", r1.Key, key)
	}
	if r1.RetainUntil.IsZero() {
		t.Error("first Put receipt must carry a retain-until marker")
	}

	// Durably present and byte-identical.
	obj, err := integrationState.client.GetObject(ctx, integrationState.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		t.Fatalf("GetObject: %v", err)
	}
	got, _ := io.ReadAll(obj)
	_ = obj.Close()
	if !bytes.Equal(got, body) {
		t.Error("the durably-stored bytes must match the PUT bytes")
	}

	// (b) HEAD-detected dedup no-op on a second identical write.
	r2, err := a.Put(ctx, key, body, PutOptions{})
	if err != nil {
		t.Fatalf("second Put: %v", err)
	}
	if !r2.Deduped {
		t.Error("a second write of identical content must be a HEAD-detected dedup no-op (AC2)")
	}

	// (c) Per-object object-lock retention is applied.
	mode, retainUntil, err := integrationState.client.GetObjectRetention(ctx, integrationState.bucket, key, "")
	if err != nil {
		t.Fatalf("GetObjectRetention: %v", err)
	}
	if mode == nil || *mode != minio.Governance {
		t.Errorf("object-lock mode = %v, want GOVERNANCE", mode)
	}
	if retainUntil == nil || retainUntil.Before(time.Now()) {
		t.Errorf("retain-until = %v, want a future date", retainUntil)
	}

	// (d) SSE-KMS encryption marker present when an alias is configured.
	info, err := integrationState.client.StatObject(ctx, integrationState.bucket, key, minio.StatObjectOptions{})
	if err != nil {
		t.Fatalf("StatObject: %v", err)
	}
	if integrationState.kmsKey != "" {
		sse := info.Metadata.Get("X-Amz-Server-Side-Encryption")
		if sse != "aws:kms" {
			t.Errorf("SSE-KMS encryption marker = %q, want aws:kms (KMS alias configured)", sse)
		}
	}
}

// TestIntegration_HasReportsMissAndHit: Has is (false, nil) for an absent key
// and (true, nil) after a PUT (the dedup HEAD, AC2).
func TestIntegration_HasReportsMissAndHit(t *testing.T) {
	a := itArchive(t)
	ctx := context.Background()

	body := []byte("has-probe-" + fmt.Sprint(time.Now().UnixNano()))
	key := reportKey(time.Now(), body)

	has, err := a.Has(ctx, key)
	if err != nil {
		t.Fatalf("Has (miss): %v", err)
	}
	if has {
		t.Fatal("Has must be false for an absent key")
	}

	if _, err := a.Put(ctx, key, body, PutOptions{}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	has, err = a.Has(ctx, key)
	if err != nil {
		t.Fatalf("Has (hit): %v", err)
	}
	if !has {
		t.Fatal("Has must be true after a PUT")
	}
}
