package archive

import (
	"context"
	"errors"
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

// FlakyArchive is a ReportArchive decorator that simulates a transient S3 outage
// (Story 4.7 AC5, BI-10): for the first FailFor Put calls it returns the
// configured FailWith error (a transient 5xx/connection-shaped error by default),
// then delegates every subsequent Put to the wrapped archive. It is the
// simulated-outage seam the inline-retry / defer / drain-on-recovery tests drive
// deterministically WITHOUT stopping a real MinIO. It is exported (not _test.go)
// so both the archive integration tests and the deferq unit tests can use it
// across package boundaries.
//
// FailFor is decremented per failing Put. With FailFor=0 the decorator is a
// transparent pass-through. SetFailFor / Outage adjust the remaining failure
// budget at test time (e.g. to simulate recovery).
type FlakyArchive struct {
	inner ReportArchive

	mu      sync.Mutex
	failFor int
	// FailWith is the error returned while the outage is active. When nil a
	// default transient error (errTransientOutage) is used.
	FailWith error
}

// errTransientOutage is the default transient-shaped error FlakyArchive returns
// while an outage is active. It is classified transient by IsTransientS3 (no
// recognised HTTP status => transport fault).
var errTransientOutage = errors.New("archive: simulated transient S3 outage (connection refused)")

// NewFlakyArchive wraps inner with an initial outage budget of failFor Put calls.
func NewFlakyArchive(inner ReportArchive, failFor int) *FlakyArchive {
	return &FlakyArchive{inner: inner, failFor: failFor}
}

// SetFailFor sets the remaining number of Put calls that will fail (simulating
// the start or end of an outage). Pass 0 to simulate immediate recovery.
func (f *FlakyArchive) SetFailFor(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failFor = n
}

// Put fails (decrementing the outage budget) while the outage is active, else
// delegates to the wrapped archive.
func (f *FlakyArchive) Put(ctx context.Context, key string, body []byte, opts PutOptions) (Receipt, error) {
	f.mu.Lock()
	if f.failFor > 0 {
		f.failFor--
		err := f.FailWith
		f.mu.Unlock()
		if err == nil {
			err = errTransientOutage
		}
		return Receipt{}, err
	}
	f.mu.Unlock()
	return f.inner.Put(ctx, key, body, opts)
}

// Has delegates to the wrapped archive.
func (f *FlakyArchive) Has(ctx context.Context, key string) (bool, error) {
	return f.inner.Has(ctx, key)
}
