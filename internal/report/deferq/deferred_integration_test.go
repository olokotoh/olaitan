//go:build integration

package deferq

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	redisclient "github.com/olokotoh/olaitan/internal/redis"
	"github.com/olokotoh/olaitan/internal/report/archive"
)

// itRealArchive constructs an S3Archive against the same env-gated MinIO harness
// the Story 4.6 report-archive integration suite uses (AC5). It skips cleanly
// when MinIO is unavailable so the suite compiles + skips without infra.
func itRealArchive(t *testing.T) archive.ReportArchive {
	t.Helper()
	if os.Getenv("REPORT_ARCHIVE_INTEGRATION_SKIP") == "1" {
		t.Skip("REPORT_ARCHIVE_INTEGRATION_SKIP=1")
	}
	endpoint := envOr("S3_ENDPOINT", "127.0.0.1:9000")
	accessKey := envOr("S3_ACCESS_KEY", "minioadmin")
	secretKey := envOr("S3_SECRET_KEY", "minioadmin")
	bucket := envOr("S3_BUCKET", "olaitan-reports-it")

	probe, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: false,
	})
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		exists, berr := probe.BucketExists(ctx, bucket)
		cancel()
		if berr != nil {
			err = berr
		} else if !exists {
			ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
			err = probe.MakeBucket(ctx2, bucket, minio.MakeBucketOptions{ObjectLocking: true})
			cancel2()
		}
	}
	if err != nil {
		if os.Getenv("REPORT_ARCHIVE_INTEGRATION_REQUIRED") == "1" {
			t.Fatalf("MinIO unavailable (REPORT_ARCHIVE_INTEGRATION_REQUIRED=1): %v", err)
		}
		t.Skipf("MinIO unavailable; skipping deferq integration: %v", err)
	}
	a, err := archive.NewS3Archive(archive.S3Config{
		Endpoint:      endpoint,
		AccessKey:     accessKey,
		SecretKey:     secretKey,
		Bucket:        bucket,
		UseSSL:        false,
		KMSKeyAlias:   os.Getenv("S3_KMS_KEY"),
		RetentionDays: 1,
		Mode:          archive.RetentionGovernance,
	})
	if err != nil {
		t.Fatalf("NewS3Archive: %v", err)
	}
	return a
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func reportKey(now time.Time, body []byte) string {
	sum := sha256.Sum256(body)
	u := now.UTC()
	return fmt.Sprintf("reports/%04d/%02d/%02d/%s.md", u.Year(), int(u.Month()), u.Day(), hex.EncodeToString(sum[:]))
}

// TestIntegration_DeferredQueueDrainOnRecovery is the Story 4.7 AC5 end-to-end
// proof against a real MinIO + an in-process miniredis: an outage LONGER than the
// inline budget enqueues to reports:deferred; on recovery the drain worker
// re-PUTs the deferred report FIFO to the real store and the deferred-depth gauge
// decrements to zero; a double-drain (re-enqueue + re-drain) is a HEAD-deduped
// no-op (idempotency, BI-9).
func TestIntegration_DeferredQueueDrainOnRecovery(t *testing.T) {
	ctx := context.Background()
	real := itRealArchive(t)
	flaky := archive.NewFlakyArchive(real, 100) // long outage

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	rcfg := redisclient.DefaultConfig()
	rcfg.Addr = mr.Addr()
	rc, err := redisclient.NewClient(rcfg)
	if err != nil {
		t.Fatalf("redis client: %v", err)
	}
	defer func() { _ = rc.Close(ctx) }()

	m := testMetrics(t)
	q, err := NewDeferredQueue(rc, 1000, m, nil)
	if err != nil {
		t.Fatalf("queue: %v", err)
	}
	dr, err := NewDeferredDrainer(q, flaky, time.Hour, nil)
	if err != nil {
		t.Fatalf("drainer: %v", err)
	}

	// Two reports deferred during the outage (the DFIR inline path would enqueue
	// here after its inline retry exhausted).
	bodies := [][]byte{
		[]byte("deferred-A-" + fmt.Sprint(time.Now().UnixNano())),
		[]byte("deferred-B-" + fmt.Sprint(time.Now().UnixNano()+1)),
	}
	keys := make([]string, len(bodies))
	for i, b := range bodies {
		keys[i] = reportKey(time.Now(), b)
		if err := q.Enqueue(ctx, keys[i], b, archive.PutOptions{}, fmt.Sprintf("inc-%d", i)); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	if got := gaugeValue(t, m.Deferred); got != 2 {
		t.Fatalf("gauge after defer = %v, want 2", got)
	}

	// Still down: the drain leaves the queue intact.
	dr.DrainOnce(ctx)
	if got := gaugeValue(t, m.Deferred); got != 2 {
		t.Fatalf("gauge while S3 down = %v, want 2 (FIFO head left in place)", got)
	}

	// Recovery: the drain re-PUTs both, FIFO, to the real store.
	flaky.SetFailFor(0)
	dr.DrainOnce(ctx)
	if got := gaugeValue(t, m.Deferred); got != 0 {
		t.Fatalf("gauge after recovery drain = %v, want 0", got)
	}
	for _, k := range keys {
		has, herr := real.Has(ctx, k)
		if herr != nil || !has {
			t.Fatalf("deferred report %q must durably land on recovery (has=%v err=%v)", k, has, herr)
		}
	}

	// Double-drain (crash-replay): re-enqueue the SAME envelope and re-drain; the
	// re-PUT is a HEAD-deduped no-op (no second durable write, BI-9).
	if err := q.Enqueue(ctx, keys[0], bodies[0], archive.PutOptions{}, "inc-0-replay"); err != nil {
		t.Fatalf("re-enqueue: %v", err)
	}
	dr.DrainOnce(ctx)
	if got := counterValue(t, m.Writes, "deduped"); got < 1 {
		t.Errorf("a double-drain must be a deduped no-op, got deduped=%v", got)
	}
	if got := gaugeValue(t, m.Deferred); got != 0 {
		t.Fatalf("gauge after double-drain = %v, want 0", got)
	}
}
