package archive

import (
	"context"
	"sync"
	"time"
)

// FakeArchive is an in-memory ReportArchive for unit tests (NFR35): it satisfies
// the same content-addressed Put + HEAD-dedup contract as S3Archive without a
// real S3 boundary, so the unit-testable surface (the DFIR write seam, the
// dedup no-op, the write-metric outcomes) needs no docker. It is exported (not
// _test.go) so both the archive package tests and the DFIR package tests can
// inject it across package boundaries.
//
// It is concurrency-safe. A configured PutErr makes every Put fail (the
// fail-loud-on-write-error path); a HEAD-detected existing key is a Deduped
// no-op (the AC2 cost optimisation + object-lock collision guard).
type FakeArchive struct {
	mu       sync.Mutex
	objects  map[string][]byte
	putCount int
	hasCount int

	// PutErr, when non-nil, makes every Put return it (the durable-write-failure
	// path the DFIR agent fails loud on).
	PutErr error
	// HasErr, when non-nil, makes every Has return it.
	HasErr error
	// RetainFor is the retain-until offset stamped on a successful Put receipt
	// (defaults to 90 days when zero), so a test can assert the receipt carries an
	// object-lock retain-until.
	RetainFor time.Duration
}

// NewFakeArchive constructs an empty in-memory archive.
func NewFakeArchive() *FakeArchive {
	return &FakeArchive{objects: make(map[string][]byte)}
}

// Put records body under key (HEAD-then-skip dedup) or returns the configured
// PutErr. A pre-existing key is a Deduped no-op.
func (f *FakeArchive) Put(_ context.Context, key string, body []byte, _ PutOptions) (Receipt, error) {
	if f.PutErr != nil {
		return Receipt{}, f.PutErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.objects[key]; ok {
		return Receipt{Key: key, Bucket: "fake", Deduped: true}, nil
	}
	stored := make([]byte, len(body))
	copy(stored, body)
	f.objects[key] = stored
	f.putCount++
	retainFor := f.RetainFor
	if retainFor == 0 {
		retainFor = time.Duration(DefaultRetentionDays) * 24 * time.Hour
	}
	return Receipt{
		Key:         key,
		Bucket:      "fake",
		Size:        int64(len(stored)),
		ETag:        "fake-etag",
		RetainUntil: time.Now().UTC().Add(retainFor),
	}, nil
}

// Has reports whether key exists, or returns the configured HasErr.
func (f *FakeArchive) Has(_ context.Context, key string) (bool, error) {
	if f.HasErr != nil {
		return false, f.HasErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hasCount++
	_, ok := f.objects[key]
	return ok, nil
}

// Body returns the stored bytes for key (test assertion helper).
func (f *FakeArchive) Body(key string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.objects[key]
	return b, ok
}

// PutCount returns the number of DURABLE writes performed (dedup no-ops are not
// counted): the proof a second identical Put did not re-write.
func (f *FakeArchive) PutCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.putCount
}

// Keys returns the stored object keys.
func (f *FakeArchive) Keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, 0, len(f.objects))
	for k := range f.objects {
		out = append(out, k)
	}
	return out
}
