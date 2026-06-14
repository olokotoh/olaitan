package forensics

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/olokotoh/olaitan/internal/metrics"
	respschema "github.com/olokotoh/olaitan/internal/schema"
)

func discardLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeUploader records calls and returns a configurable result. failN fails the
// first failN attempts then succeeds; failAll always fails.
type fakeUploader struct {
	mu       sync.Mutex
	calls    int
	failN    int
	failAll  bool
	lastKey  string
	lastSize int64
	lastKMS  string
	gotBytes []byte
}

func (f *fakeUploader) Upload(ctx context.Context, key string, r io.Reader, size int64, opts UploadOptions) (Ack, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastKey = key
	f.lastSize = size
	f.lastKMS = opts.KMSKeyAlias
	data, _ := io.ReadAll(r)
	f.gotBytes = data
	if f.failAll || f.calls <= f.failN {
		return Ack{}, errors.New("simulated S3 outage")
	}
	return Ack{Key: key, Bucket: "test-bucket", Size: size, ETag: "etag-1"}, nil
}

func (f *fakeUploader) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func deployment(ns, name string, sel map[string]string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: sel},
		},
	}
}

func pod(ns, name string, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: labels},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "busybox"}},
		},
	}
}

func killTransition(workloadID string) respschema.StateTransition {
	return respschema.StateTransition{
		Timestamp:   time.Now().Add(-50 * time.Millisecond),
		FromState:   respschema.StateQuarantined,
		ToState:     respschema.StatePreservedKilled,
		WorkloadID:  workloadID,
		TriggerType: "automated",
		Reason:      respschema.ReasonKillConditionMet,
	}
}

// newController builds a controller with a fixed injectable clock so NFR7
// observations are deterministic.
func newController(t *testing.T, cs *fake.Clientset, up Uploader, reg *metrics.Registry) *Controller {
	t.Helper()
	c, err := New(Config{KMSKeyAlias: "alias/forensics"}, cs, up, reg, discardLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Pin the clock so capture latency is a fixed, deterministic value well
	// under the 10s NFR7 budget regardless of wall-clock jitter.
	fixed := killTransitionTimestampPlus(2 * time.Second)
	c.now = func() time.Time { return fixed }
	return c
}

var fixedKillTime = time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)

func killTransitionTimestampPlus(d time.Duration) time.Time {
	return fixedKillTime.Add(d)
}

// TestNew_NilArgs covers the New guard clauses.
func TestNew_NilArgs(t *testing.T) {
	if _, err := New(Config{}, nil, &fakeUploader{}, nil, nil); !errors.Is(err, errNilClientset) {
		t.Fatalf("nil clientset: want errNilClientset, got %v", err)
	}
	if _, err := New(Config{}, fake.NewSimpleClientset(), nil, nil, nil); !errors.Is(err, errNilUploader) {
		t.Fatalf("nil uploader: want errNilUploader, got %v", err)
	}
}

// TestPublish_FiltersToPreservedKilled confirms Publish enqueues only kill
// transitions and is non-blocking (drops on a full queue with a metric).
func TestPublish_FiltersToPreservedKilled(t *testing.T) {
	cs := fake.NewSimpleClientset()
	c, _ := New(Config{QueueSize: 1}, cs, &fakeUploader{}, nil, discardLog())

	// A non-kill transition is ignored entirely (queue stays empty).
	c.Publish(respschema.StateTransition{ToState: respschema.StateQuarantined, WorkloadID: "ns/Deployment/web"})
	if len(c.queue) != 0 {
		t.Fatalf("non-kill transition was enqueued: queue len %d", len(c.queue))
	}

	// A kill transition is enqueued.
	c.Publish(killTransition("ns/Deployment/web"))
	if len(c.queue) != 1 {
		t.Fatalf("kill transition not enqueued: queue len %d", len(c.queue))
	}

	// A second kill on the size-1 queue is dropped (non-blocking), not blocked.
	done := make(chan struct{})
	go func() {
		c.Publish(killTransition("ns/Deployment/web2"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Publish blocked on a full queue; must be non-blocking")
	}
}

// TestHandle_SuccessCapturesUploadsDeletes is the happy path (AC3): a resolved
// Deployment workload's pod is captured, uploaded (KMS alias passed), deleted
// AFTER the upload, and the NFR7 histogram + captured counter advance.
func TestHandle_SuccessCapturesUploadsDeletes(t *testing.T) {
	reg := metrics.NewRegistry()
	sel := map[string]string{"app": "web"}
	cs := fake.NewSimpleClientset(
		runtime.Object(deployment("ns", "web", sel)),
		runtime.Object(pod("ns", "web-abc", sel)),
	)
	up := &fakeUploader{}
	c := newController(t, cs, up, reg)

	c.handle(context.Background(), killTransition("ns/Deployment/web"))

	if up.callCount() != 1 {
		t.Fatalf("upload calls = %d, want 1", up.callCount())
	}
	if up.lastKMS != "alias/forensics" {
		t.Fatalf("KMS alias not propagated: got %q", up.lastKMS)
	}
	// Pod must be deleted (after the upload-ack).
	if _, err := cs.CoreV1().Pods("ns").Get(context.Background(), "web-abc", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("pod not deleted after upload-ack: err=%v", err)
	}
	if got := testutil.ToFloat64(c.captureTotal.WithLabelValues("captured")); got != 1 {
		t.Fatalf("captured counter = %v, want 1", got)
	}
	if got := histogramSampleCount(t, c.captureSeconds); got != 1 {
		t.Fatalf("capture histogram sample count = %d, want 1", got)
	}
}

// TestHandle_NFR7BudgetObserved asserts the success-path latency is observed
// against the histogram and lands under the 10s NFR7 ceiling, using the
// injectable clock so the measurement is deterministic (no real sleeps). The
// transition timestamp is fixedKillTime and c.now is fixedKillTime + 2s, so the
// observed latency is exactly 2s.
func TestHandle_NFR7BudgetObserved(t *testing.T) {
	reg := metrics.NewRegistry()
	cs := fake.NewSimpleClientset(runtime.Object(pod("ns", "p", map[string]string{"x": "y"})))
	up := &fakeUploader{}
	c := newController(t, cs, up, reg)

	st := killTransition("ns/Pod/p")
	st.Timestamp = fixedKillTime // deterministic: now() - timestamp == 2s
	c.handle(context.Background(), st)

	sum := histogramSampleSum(t, c.captureSeconds)
	if sum <= 0 || sum > 10 {
		t.Fatalf("observed capture latency %.3fs not in (0, 10] NFR7 budget", sum)
	}
	if sum != 2 {
		t.Fatalf("deterministic latency = %.3fs, want 2.000s", sum)
	}
}

func histogramSampleSum(t *testing.T, h prometheus.Collector) float64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 1)
	h.Collect(ch)
	close(ch)
	m := <-ch
	var dtoMetric dto.Metric
	if err := m.Write(&dtoMetric); err != nil {
		t.Fatalf("write histogram dto: %v", err)
	}
	return dtoMetric.Histogram.GetSampleSum()
}

// histogramSampleCount returns the observed sample count of a histogram by
// collecting it into a dto and reading SampleCount. testutil.CollectAndCount
// counts metric series (always 1 for a plain histogram), not observations, so
// it cannot be used to assert how many times Observe was called.
func histogramSampleCount(t *testing.T, h prometheus.Collector) uint64 {
	t.Helper()
	ch := make(chan prometheus.Metric, 1)
	h.Collect(ch)
	close(ch)
	m := <-ch
	var dtoMetric dto.Metric
	if err := m.Write(&dtoMetric); err != nil {
		t.Fatalf("write histogram dto: %v", err)
	}
	if dtoMetric.Histogram == nil {
		t.Fatalf("metric is not a histogram")
	}
	return dtoMetric.Histogram.GetSampleCount()
}

// TestHandle_UploadOrderingBeforeDelete proves the delete happens STRICTLY after
// a successful upload by failing the upload and asserting the pod survives.
func TestHandle_S3OutageDefersDelete(t *testing.T) {
	reg := metrics.NewRegistry()
	sel := map[string]string{"app": "web"}
	cs := fake.NewSimpleClientset(
		runtime.Object(deployment("ns", "web", sel)),
		runtime.Object(pod("ns", "web-abc", sel)),
	)
	up := &fakeUploader{failAll: true}
	c := newController(t, cs, up, reg)
	// Default UploadRetries is 1 -> 2 attempts total.

	c.handle(context.Background(), killTransition("ns/Deployment/web"))

	if up.callCount() != 2 {
		t.Fatalf("upload attempts = %d, want 2 (1 + 1 retry)", up.callCount())
	}
	// AC5: pod is NOT deleted (forensic preservation priority).
	if _, err := cs.CoreV1().Pods("ns").Get(context.Background(), "web-abc", metav1.GetOptions{}); err != nil {
		t.Fatalf("pod was deleted despite S3 outage: err=%v", err)
	}
	if got := testutil.ToFloat64(c.writesDeferred); got != 1 {
		t.Fatalf("writes_deferred = %v, want 1", got)
	}
	if got := testutil.ToFloat64(c.captureTotal.WithLabelValues("deferred")); got != 1 {
		t.Fatalf("deferred counter = %v, want 1", got)
	}
	// NFR7 histogram must NOT advance on the deferred path.
	if got := histogramSampleCount(t, c.captureSeconds); got != 0 {
		t.Fatalf("capture histogram advanced on deferred path: count=%d", got)
	}
}

// TestHandle_RetrySucceedsOnSecondAttempt confirms the in-line retry recovers a
// transient outage and then deletes.
func TestHandle_RetrySucceedsOnSecondAttempt(t *testing.T) {
	reg := metrics.NewRegistry()
	sel := map[string]string{"app": "web"}
	cs := fake.NewSimpleClientset(
		runtime.Object(deployment("ns", "web", sel)),
		runtime.Object(pod("ns", "web-abc", sel)),
	)
	up := &fakeUploader{failN: 1}
	c := newController(t, cs, up, reg)

	c.handle(context.Background(), killTransition("ns/Deployment/web"))

	if up.callCount() != 2 {
		t.Fatalf("upload attempts = %d, want 2", up.callCount())
	}
	if _, err := cs.CoreV1().Pods("ns").Get(context.Background(), "web-abc", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("pod not deleted after retry success: err=%v", err)
	}
	if got := testutil.ToFloat64(c.captureTotal.WithLabelValues("captured")); got != 1 {
		t.Fatalf("captured = %v, want 1", got)
	}
}

// TestHandle_ExcludedNamespaceSkips confirms an excluded namespace is never
// captured or deleted.
func TestHandle_ExcludedNamespaceSkips(t *testing.T) {
	reg := metrics.NewRegistry()
	cs := fake.NewSimpleClientset(runtime.Object(pod("kube-system", "p", map[string]string{"a": "b"})))
	up := &fakeUploader{}
	c, _ := New(Config{ExcludedNamespaces: []string{"kube-system"}}, cs, up, reg, discardLog())

	c.handle(context.Background(), killTransition("kube-system/Pod/p"))

	if up.callCount() != 0 {
		t.Fatalf("upload called for excluded namespace: %d", up.callCount())
	}
	if got := testutil.ToFloat64(c.captureTotal.WithLabelValues("skipped")); got != 1 {
		t.Fatalf("skipped = %v, want 1", got)
	}
}

// TestHandle_NoPodsResolvedSkips confirms a workload with no live pods is a
// benign skip (no evidence to preserve), not a deferral.
func TestHandle_NoPodsResolvedSkips(t *testing.T) {
	reg := metrics.NewRegistry()
	sel := map[string]string{"app": "web"}
	cs := fake.NewSimpleClientset(runtime.Object(deployment("ns", "web", sel)))
	up := &fakeUploader{}
	c, _ := New(Config{}, cs, up, reg, discardLog())

	c.handle(context.Background(), killTransition("ns/Deployment/web"))

	if up.callCount() != 0 {
		t.Fatalf("upload called with no pods: %d", up.callCount())
	}
	if got := testutil.ToFloat64(c.captureTotal.WithLabelValues("skipped")); got != 1 {
		t.Fatalf("skipped = %v, want 1", got)
	}
}

// TestHandle_OrphanPodKind covers the Pod orphan-fallback resolution + delete.
func TestHandle_OrphanPodKind(t *testing.T) {
	reg := metrics.NewRegistry()
	cs := fake.NewSimpleClientset(runtime.Object(pod("ns", "lonely", map[string]string{"x": "y"})))
	up := &fakeUploader{}
	c := newController(t, cs, up, reg)

	c.handle(context.Background(), killTransition("ns/Pod/lonely"))

	if up.callCount() != 1 {
		t.Fatalf("upload calls = %d, want 1", up.callCount())
	}
	if _, err := cs.CoreV1().Pods("ns").Get(context.Background(), "lonely", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("orphan pod not deleted: err=%v", err)
	}
}

// TestHandle_DeleteNotFoundIsSuccess confirms an already-gone pod at delete time
// is treated as success (the bundle was preserved).
func TestHandle_DeleteNotFoundIsSuccess(t *testing.T) {
	reg := metrics.NewRegistry()
	cs := fake.NewSimpleClientset(runtime.Object(pod("ns", "vanishing", map[string]string{"x": "y"})))
	up := &fakeUploader{}
	c := newController(t, cs, up, reg)
	// Delete the pod out from under the controller right before its own delete,
	// via a reactor that returns NotFound on delete.
	cs.PrependReactor("delete", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "vanishing")
	})

	c.handle(context.Background(), killTransition("ns/Pod/vanishing"))

	if got := testutil.ToFloat64(c.captureTotal.WithLabelValues("captured")); got != 1 {
		t.Fatalf("NotFound delete should count as captured success: got %v", got)
	}
}

// TestHandle_StateOracleVetoesDelete confirms BI-5: a queued kill whose workload
// is no longer PRESERVED_KILLED is skipped (no delete).
func TestHandle_StateOracleVetoesDelete(t *testing.T) {
	reg := metrics.NewRegistry()
	cs := fake.NewSimpleClientset(runtime.Object(pod("ns", "p", map[string]string{"x": "y"})))
	up := &fakeUploader{}
	c := newController(t, cs, up, reg)
	c.SetStateOracle(oracleFunc(func(string) (respschema.PodSecurityState, bool) {
		return respschema.StateQuarantined, true // released back to QUARANTINED
	}))

	c.handle(context.Background(), killTransition("ns/Pod/p"))

	if up.callCount() != 0 {
		t.Fatalf("upload called despite oracle veto: %d", up.callCount())
	}
	if _, err := cs.CoreV1().Pods("ns").Get(context.Background(), "p", metav1.GetOptions{}); err != nil {
		t.Fatalf("pod deleted despite oracle veto: err=%v", err)
	}
	if got := testutil.ToFloat64(c.captureTotal.WithLabelValues("skipped")); got != 1 {
		t.Fatalf("skipped = %v, want 1", got)
	}
}

// TestHandle_MalformedWorkloadID covers the parse-error error path.
func TestHandle_MalformedWorkloadID(t *testing.T) {
	reg := metrics.NewRegistry()
	cs := fake.NewSimpleClientset()
	c, _ := New(Config{}, cs, &fakeUploader{}, reg, discardLog())
	c.handle(context.Background(), killTransition("not-a-valid-id"))
	if got := testutil.ToFloat64(c.captureTotal.WithLabelValues("error")); got != 1 {
		t.Fatalf("error counter = %v, want 1", got)
	}
}

// TestRun_DrainsAndStops confirms Run drains the queue and returns nil on ctx
// cancellation.
func TestRun_DrainsAndStops(t *testing.T) {
	cs := fake.NewSimpleClientset(runtime.Object(pod("ns", "p", map[string]string{"x": "y"})))
	up := &fakeUploader{}
	c := newController(t, cs, up, metrics.NewRegistry())

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- c.Run(ctx) }()

	c.Publish(killTransition("ns/Pod/p"))
	// Wait for the upload to be observed.
	deadline := time.After(2 * time.Second)
	for up.callCount() == 0 {
		select {
		case <-deadline:
			t.Fatal("Run did not process the queued kill")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("Run returned %v, want nil on cancel", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// TestHandle_DeleteErrorAfterUpload covers the leg-3 error branch: the upload
// succeeds (evidence preserved) but the pod delete fails with a non-NotFound
// error; the outcome is counted as error and the write is NOT double-counted as
// deferred.
func TestHandle_DeleteErrorAfterUpload(t *testing.T) {
	reg := metrics.NewRegistry()
	cs := fake.NewSimpleClientset(runtime.Object(pod("ns", "p", map[string]string{"x": "y"})))
	up := &fakeUploader{}
	c := newController(t, cs, up, reg)
	cs.PrependReactor("delete", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver boom")
	})

	c.handle(context.Background(), killTransition("ns/Pod/p"))

	if up.callCount() != 1 {
		t.Fatalf("upload calls = %d, want 1", up.callCount())
	}
	if got := testutil.ToFloat64(c.captureTotal.WithLabelValues("error")); got != 1 {
		t.Fatalf("error = %v, want 1", got)
	}
	if got := testutil.ToFloat64(c.writesDeferred); got != 0 {
		t.Fatalf("writes_deferred = %v, want 0 (upload succeeded)", got)
	}
}

// TestHandle_PodGoneBeforeCapture covers the capture leg NotFound branch: the
// pod vanishes before capture, which is a benign skip (no evidence, delete moot).
func TestHandle_PodGoneBeforeCapture(t *testing.T) {
	reg := metrics.NewRegistry()
	// The orphan-pod resolution returns the named pod even when Get during
	// capture later fails; simulate by listing the pod for resolution but a
	// reactor that NotFounds the capture Get.
	cs := fake.NewSimpleClientset(runtime.Object(pod("ns", "p", map[string]string{"x": "y"})))
	up := &fakeUploader{}
	c := newController(t, cs, up, reg)
	getCalls := 0
	cs.PrependReactor("get", "pods", func(action k8stesting.Action) (bool, runtime.Object, error) {
		getCalls++
		if getCalls >= 2 { // first Get is resolvePods existence check; second is capture
			return true, nil, apierrors.NewNotFound(schema.GroupResource{Resource: "pods"}, "p")
		}
		return false, nil, nil
	})

	c.handle(context.Background(), killTransition("ns/Pod/p"))

	if up.callCount() != 0 {
		t.Fatalf("upload called after pod gone: %d", up.callCount())
	}
	if got := testutil.ToFloat64(c.captureTotal.WithLabelValues("skipped")); got != 1 {
		t.Fatalf("skipped = %v, want 1", got)
	}
}

// TestGetPodEvents covers the events capture branch with a real event object.
func TestGetPodEvents(t *testing.T) {
	ev := &corev1.Event{
		ObjectMeta:     metav1.ObjectMeta{Namespace: "ns", Name: "p.evt"},
		InvolvedObject: corev1.ObjectReference{Kind: "Pod", Name: "p", Namespace: "ns"},
		Reason:         "Killing",
		Message:        "Stopping container app",
	}
	cs := fake.NewSimpleClientset(runtime.Object(ev))
	got := getPodEvents(context.Background(), cs, "ns", "p")
	// The fake clientset does not apply the field selector, so it returns all
	// events in the namespace; the assertion is simply that a List succeeds and
	// returns the event (the capture path is best-effort either way).
	if len(got) == 0 {
		t.Fatal("expected at least one event")
	}
}

// oracleFunc adapts a func to the StateOracle interface.
type oracleFunc func(string) (respschema.PodSecurityState, bool)

func (f oracleFunc) CurrentState(id string) (respschema.PodSecurityState, bool) {
	return f(id)
}

// readBundle decompresses a forensic bundle into a name->bytes map for asserts.
func readBundle(t *testing.T, gz []byte) map[string][]byte {
	t.Helper()
	gr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	tr := tar.NewReader(gr)
	out := map[string][]byte{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		data, _ := io.ReadAll(tr)
		out[hdr.Name] = data
	}
	return out
}
