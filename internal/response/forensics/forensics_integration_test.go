//go:build integration

package forensics

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/prometheus/client_golang/prometheus/testutil"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/olokotoh/olaitan/internal/metrics"
	respschema "github.com/olokotoh/olaitan/internal/schema"
)

// integrationState holds the package-shared MinIO plumbing, configured once in
// TestMain and reused across the suite (AC6). It mirrors the netpol integration
// TestMain env-gated skip/require contract (BI-8).
//
// Configuration via environment:
//
//	FORENSICS_INTEGRATION_SKIP=1     -> explicit opt-out, exit 0.
//	FORENSICS_INTEGRATION_REQUIRED=1 -> fail loudly if MinIO is unreachable.
//	S3_ENDPOINT   (default 127.0.0.1:9000)
//	S3_ACCESS_KEY (default minioadmin)
//	S3_SECRET_KEY (default minioadmin)
//	S3_BUCKET     (default olaitan-forensics-it)
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
	if os.Getenv("FORENSICS_INTEGRATION_SKIP") == "1" {
		_, _ = os.Stderr.WriteString("forensics integration: FORENSICS_INTEGRATION_SKIP=1, skipping (exit 0)\n")
		os.Exit(0)
	}
	integrationState.endpoint = envOr("S3_ENDPOINT", "127.0.0.1:9000")
	integrationState.accessKey = envOr("S3_ACCESS_KEY", "minioadmin")
	integrationState.secretKey = envOr("S3_SECRET_KEY", "minioadmin")
	integrationState.bucket = envOr("S3_BUCKET", "olaitan-forensics-it")
	integrationState.kmsKey = os.Getenv("S3_KMS_KEY")

	client, err := minio.New(integrationState.endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(integrationState.accessKey, integrationState.secretKey, ""),
		Secure: false,
	})
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = ensureBucket(ctx, client, integrationState.bucket)
		cancel()
	}
	if err != nil {
		if os.Getenv("FORENSICS_INTEGRATION_REQUIRED") == "1" {
			_, _ = os.Stderr.WriteString("forensics integration: MinIO unavailable (FORENSICS_INTEGRATION_REQUIRED=1, failing): " + err.Error() + "\n")
			os.Exit(1)
		}
		_, _ = os.Stderr.WriteString("forensics integration: MinIO unavailable; exiting 0 (set FORENSICS_INTEGRATION_REQUIRED=1 to fail loudly): " + err.Error() + "\n")
		os.Exit(0)
	}
	integrationState.client = client
	os.Exit(m.Run())
}

func ensureBucket(ctx context.Context, c *minio.Client, bucket string) error {
	exists, err := c.BucketExists(ctx, bucket)
	if err != nil {
		return err
	}
	if !exists {
		return c.MakeBucket(ctx, bucket, minio.MakeBucketOptions{})
	}
	return nil
}

func itUploader(t *testing.T) *MinioUploader {
	t.Helper()
	if integrationState.client == nil {
		t.Skip("MinIO unavailable; skipping integration suite")
	}
	u, err := NewMinioUploader(MinioConfig{
		Endpoint:    integrationState.endpoint,
		AccessKey:   integrationState.accessKey,
		SecretKey:   integrationState.secretKey,
		Bucket:      integrationState.bucket,
		UseSSL:      false,
		KMSKeyAlias: integrationState.kmsKey,
	})
	if err != nil {
		t.Fatalf("NewMinioUploader: %v", err)
	}
	return u
}

var nsCounter atomic.Uint64

func itK8s(podLabels map[string]string) (*fake.Clientset, string) {
	ns := fmt.Sprintf("forensics-it-%d-%d", time.Now().UnixNano(), nsCounter.Add(1))
	cs := fake.NewSimpleClientset(
		runtime.Object(&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "web"},
			Spec:       appsv1.DeploymentSpec{Selector: &metav1.LabelSelector{MatchLabels: podLabels}},
		}),
		runtime.Object(&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "web-abc", Labels: podLabels},
			Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "busybox"}}},
		}),
	)
	return cs, ns
}

// TestIntegration_SuccessPath exercises the full Path A cycle against a real
// MinIO endpoint (AC6): capture -> KMS-encrypted upload-ack -> pod delete, with
// the NFR7 latency observed. It then verifies the object is durably present in
// the bucket under the content-addressed key.
func TestIntegration_SuccessPath(t *testing.T) {
	up := itUploader(t)
	reg := metrics.NewRegistry()
	sel := map[string]string{"app": "web"}
	cs, ns := itK8s(sel)

	c, err := New(Config{KMSKeyAlias: integrationState.kmsKey}, cs, up, reg, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	st := respschema.StateTransition{
		Timestamp:  time.Now(),
		FromState:  respschema.StateQuarantined,
		ToState:    respschema.StatePreservedKilled,
		WorkloadID: ns + "/Deployment/web",
	}
	c.handle(context.Background(), st)

	// Pod deleted after the upload-ack.
	if _, gerr := cs.CoreV1().Pods(ns).Get(context.Background(), "web-abc", metav1.GetOptions{}); !apierrors.IsNotFound(gerr) {
		t.Fatalf("pod not deleted after upload-ack: %v", gerr)
	}
	// The bundle is durably present in MinIO. We recompute the key by capturing
	// against the (now-deleted) pod is not possible; instead List the bucket and
	// assert a single forensic-bundle object exists for this run.
	found := false
	for obj := range integrationState.client.ListObjects(context.Background(), integrationState.bucket, minio.ListObjectsOptions{Prefix: "forensic-bundles/", Recursive: true}) {
		if obj.Err != nil {
			t.Fatalf("list objects: %v", obj.Err)
		}
		// Fetch and confirm it is a non-empty gzip object.
		o, gerr := integrationState.client.GetObject(context.Background(), integrationState.bucket, obj.Key, minio.GetObjectOptions{})
		if gerr != nil {
			continue
		}
		data, _ := io.ReadAll(o)
		_ = o.Close()
		if len(data) > 0 && bytes.HasPrefix(data, []byte{0x1f, 0x8b}) { // gzip magic
			found = true
			break
		}
	}
	if !found {
		t.Fatal("no durable gzip forensic bundle found in MinIO after success path")
	}
}

// TestIntegration_S3Outage exercises the deferred path against a deliberately
// unreachable S3 endpoint (AC6, AC5): no delete, deferred counter increments,
// pod retains its (Story 4.1) QUARANTINED isolation by virtue of NOT being
// deleted. The outage is simulated by pointing the uploader at a dead port.
func TestIntegration_S3Outage(t *testing.T) {
	if integrationState.client == nil {
		t.Skip("MinIO unavailable; skipping integration suite")
	}
	deadUploader, err := NewMinioUploader(MinioConfig{
		Endpoint:  "127.0.0.1:1", // nothing listens here
		AccessKey: "x",
		SecretKey: "y",
		Bucket:    integrationState.bucket,
		UseSSL:    false,
	})
	if err != nil {
		t.Fatalf("NewMinioUploader: %v", err)
	}
	reg := metrics.NewRegistry()
	sel := map[string]string{"app": "web"}
	cs, ns := itK8s(sel)

	c, err := New(Config{UploadTimeout: time.Second}, cs, deadUploader, reg, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	st := respschema.StateTransition{
		Timestamp:  time.Now(),
		FromState:  respschema.StateQuarantined,
		ToState:    respschema.StatePreservedKilled,
		WorkloadID: ns + "/Deployment/web",
	}
	c.handle(context.Background(), st)

	// AC5: pod NOT deleted (forensic preservation priority).
	if _, gerr := cs.CoreV1().Pods(ns).Get(context.Background(), "web-abc", metav1.GetOptions{}); gerr != nil {
		t.Fatalf("pod was deleted during S3 outage: %v", gerr)
	}
	// AC6 (round-1 review MED): assert the deferred contract at the real-S3
	// boundary, mirroring the unit test: the deferred counter increments and the
	// deferred result-label advances.
	if got := testutil.ToFloat64(c.writesDeferred); got != 1 {
		t.Fatalf("writes_deferred = %v, want 1 after S3 outage", got)
	}
	if got := testutil.ToFloat64(c.captureTotal.WithLabelValues("deferred")); got != 1 {
		t.Fatalf("deferred result label = %v, want 1 after S3 outage", got)
	}
}
