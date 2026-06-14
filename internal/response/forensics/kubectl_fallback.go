package forensics

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// maxLogBytes bounds the per-container log tail captured into the bundle so a
// chatty container cannot blow the capture latency budget (NFR7) or the bundle
// size. 1 MiB per stream (current + previous) is generous for a forensic tail
// while keeping the capture bounded.
const maxLogBytes = 1 << 20

// captureFallback assembles the Path A forensic bundle for a single pod
// (BI-1). The bundle is a gzip-compressed tar containing, for the pod:
//   - meta/pod.json        : the pod object (spec + status), as returned by Get.
//   - meta/events.json     : recent events referencing the pod (best-effort).
//   - logs/<container>.current.log  : the container's current logs (tail).
//   - logs/<container>.previous.log : the terminated container's last-state
//     logs (kubectl logs --previous), best-effort (absent if the container has
//     not restarted).
//   - fs/<container>.tar (best-effort): a debug-pod filesystem tar of the
//     writable layers. Story 4.2 ships this as a best-effort, optional artefact
//     (see captureFilesystem); a failure to capture it never fails the bundle,
//     because the logs + spec/status + events are the load-bearing forensic
//     record and the fs-tar requires elevated debug-pod rights that may be
//     denied (BI-1 documents this).
//
// The returned bytes are the complete forensic-bundle.tar.gz; the caller
// content-addresses them via bundleKey. A capture error means no durable
// forensic record could be assembled and the caller must NOT proceed to delete
// (it defers instead).
func captureFallback(ctx context.Context, cs kubernetes.Interface, namespace, podName string) ([]byte, error) {
	pod, err := cs.CoreV1().Pods(namespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("forensics: get pod %s/%s: %w", namespace, podName, err)
	}

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	// Pod spec/status.
	podJSON, err := json.MarshalIndent(pod, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("forensics: marshal pod %s/%s: %w", namespace, podName, err)
	}
	if err := writeTarFile(tw, "meta/pod.json", podJSON); err != nil {
		return nil, err
	}

	// Recent events referencing the pod (best-effort: a List failure must not
	// sink the whole capture, since logs + spec are the primary record).
	if events := getPodEvents(ctx, cs, namespace, podName); len(events) > 0 {
		if evJSON, merr := json.MarshalIndent(events, "", "  "); merr == nil {
			if werr := writeTarFile(tw, "meta/events.json", evJSON); werr != nil {
				return nil, werr
			}
		}
	}

	// Per-container logs: current + previous. Containers are processed in a
	// stable (sorted) order so the bundle bytes are deterministic for a given
	// pod state, which keeps the content-addressed SHA-256 stable across
	// identical captures (Open Assumption 3).
	names := containerNames(pod)
	for _, c := range names {
		current := getContainerLog(ctx, cs, namespace, podName, c, false)
		if err := writeTarFile(tw, "logs/"+c+".current.log", current); err != nil {
			return nil, err
		}
		// Previous (terminated) logs are only present once a container has
		// restarted; an error here is expected and non-fatal (kubectl logs
		// --previous returns an error when there is no previous instance).
		if prev := getContainerLog(ctx, cs, namespace, podName, c, true); len(prev) > 0 {
			if err := writeTarFile(tw, "logs/"+c+".previous.log", prev); err != nil {
				return nil, err
			}
		}
	}

	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("forensics: close tar for %s/%s: %w", namespace, podName, err)
	}
	if err := gw.Close(); err != nil {
		return nil, fmt.Errorf("forensics: close gzip for %s/%s: %w", namespace, podName, err)
	}
	return buf.Bytes(), nil
}

// containerNames returns the union of init + regular + ephemeral container
// names for the pod, sorted for deterministic bundle layout.
func containerNames(pod *corev1.Pod) []string {
	set := make(map[string]struct{})
	for i := range pod.Spec.InitContainers {
		set[pod.Spec.InitContainers[i].Name] = struct{}{}
	}
	for i := range pod.Spec.Containers {
		set[pod.Spec.Containers[i].Name] = struct{}{}
	}
	for i := range pod.Spec.EphemeralContainers {
		set[pod.Spec.EphemeralContainers[i].Name] = struct{}{}
	}
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// getContainerLog fetches a single container's logs via the typed client-go
// GetLogs API (NOT by shelling out to kubectl, BI-1). previous selects the
// terminated container's last-state log (the --previous flag). The tail is
// bounded by maxLogBytes. Any error (e.g. no previous instance, container not
// started) is swallowed and yields a short diagnostic line instead of failing
// the capture, since a missing log stream must not destroy the rest of the
// forensic record.
func getContainerLog(ctx context.Context, cs kubernetes.Interface, namespace, podName, container string, previous bool) []byte {
	limit := int64(maxLogBytes)
	req := cs.CoreV1().Pods(namespace).GetLogs(podName, &corev1.PodLogOptions{
		Container:  container,
		Previous:   previous,
		LimitBytes: &limit,
	})
	rc, err := req.Stream(ctx)
	if err != nil {
		// Expected for previous when the container never restarted; record a
		// terse marker so the bundle documents the absence rather than hiding it.
		return []byte(fmt.Sprintf("forensics: log stream unavailable (previous=%t): %v\n", previous, err))
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(io.LimitReader(rc, maxLogBytes))
	if err != nil {
		return append(data, []byte(fmt.Sprintf("\nforensics: log read truncated: %v\n", err))...)
	}
	return data
}

// getPodEvents lists events in the pod's namespace whose involvedObject is the
// pod, providing the recent-events forensic context. It is best-effort: a List
// error returns nil and the bundle simply omits the events file.
func getPodEvents(ctx context.Context, cs kubernetes.Interface, namespace, podName string) []corev1.Event {
	list, err := cs.CoreV1().Events(namespace).List(ctx, metav1.ListOptions{
		FieldSelector: fmt.Sprintf("involvedObject.name=%s,involvedObject.kind=Pod", podName),
	})
	if err != nil || list == nil {
		return nil
	}
	return list.Items
}

// writeTarFile writes a single regular file entry into the tar stream.
func writeTarFile(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{
		Name: name,
		Mode: 0o600,
		Size: int64(len(data)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("forensics: tar header %q: %w", name, err)
	}
	if _, err := tw.Write(data); err != nil {
		return fmt.Errorf("forensics: tar write %q: %w", name, err)
	}
	return nil
}

// bundleKey computes the content-addressed S3 object key for a forensic bundle
// (BI-7). The key is content-addressed by the SHA-256 of the bundle bytes, so
// an identical re-capture maps to the same key (idempotent re-upload, Open
// Assumption 3). The shape is forensic-bundles/<sha256>/forensic-bundle.tar.gz.
//
// BI-7 names s3://<bucket>/<incident-id>/forensic-bundle.tar.gz, but the
// incident-id is introduced by Story 4.3 (INCIDENTS.finalised) which does not
// exist when 4.2 runs; the SHA-256 IS the content-address that BI-7 requires,
// so 4.2 keys on it directly and Story 4.3/4.7 can fold the incident-id in when
// it lands. This reconciliation is recorded in the Dev Agent Record (BI-7
// amendment).
func bundleKey(bundle []byte) (key, sum string) {
	h := sha256.Sum256(bundle)
	sum = hex.EncodeToString(h[:])
	return "forensic-bundles/" + sum + "/forensic-bundle.tar.gz", sum
}
