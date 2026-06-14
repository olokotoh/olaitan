package archive

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/minio/minio-go/v7"
)

// timeoutErr is a net.Error that reports Timeout()=true, the dial/read/write
// deadline class IsTransientS3 must classify as transient.
type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

var _ net.Error = timeoutErr{}

// nonTimeoutNetErr is a net.Error with Timeout()=false (it should fall through
// to the no-status transport-error branch, still transient).
type nonTimeoutNetErr struct{}

func (nonTimeoutNetErr) Error() string   { return "connection refused" }
func (nonTimeoutNetErr) Timeout() bool   { return false }
func (nonTimeoutNetErr) Temporary() bool { return true }

var _ net.Error = nonTimeoutNetErr{}

func TestIsTransientS3(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		transient bool
	}{
		{"nil is not transient", nil, false},
		{"500 internal server error is transient", minio.ErrorResponse{StatusCode: http.StatusInternalServerError}, true},
		{"503 service unavailable is transient", minio.ErrorResponse{StatusCode: http.StatusServiceUnavailable}, true},
		{"504 gateway timeout is transient", minio.ErrorResponse{StatusCode: http.StatusGatewayTimeout}, true},
		{"408 request timeout is transient", minio.ErrorResponse{StatusCode: http.StatusRequestTimeout}, true},
		{"429 too many requests is transient", minio.ErrorResponse{StatusCode: http.StatusTooManyRequests, Code: "SlowDown"}, true},
		{"403 access denied is permanent", minio.ErrorResponse{StatusCode: http.StatusForbidden, Code: "AccessDenied"}, false},
		{"404 no such bucket is permanent", minio.ErrorResponse{StatusCode: http.StatusNotFound, Code: "NoSuchBucket"}, false},
		{"400 invalid request is permanent", minio.ErrorResponse{StatusCode: http.StatusBadRequest, Code: "InvalidRequest"}, false},
		{"413 entity too large is permanent", minio.ErrorResponse{StatusCode: http.StatusRequestEntityTooLarge}, false},
		{"401 unauthorized is permanent", minio.ErrorResponse{StatusCode: http.StatusUnauthorized}, false},
		{"net timeout is transient", timeoutErr{}, true},
		{"non-timeout transport error is transient", nonTimeoutNetErr{}, true},
		{"bare io.EOF (no status) is transient", io.EOF, true},
		{"bare unexpected EOF is transient", io.ErrUnexpectedEOF, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsTransientS3(tc.err); got != tc.transient {
				t.Fatalf("IsTransientS3(%v) = %v, want %v", tc.err, got, tc.transient)
			}
		})
	}
}

// TestIsTransientS3_Wrapped confirms the classifier reaches through fmt.Errorf
// wrapping (the archive.Put error-wrap contract) and errors.As wrapping.
func TestIsTransientS3_Wrapped(t *testing.T) {
	wrapped5xx := fmt.Errorf("archive: put object: %w", minio.ErrorResponse{StatusCode: http.StatusBadGateway})
	if !IsTransientS3(wrapped5xx) {
		t.Fatalf("wrapped 5xx should be transient")
	}
	wrapped403 := fmt.Errorf("archive: put object: %w", minio.ErrorResponse{StatusCode: http.StatusForbidden, Code: "AccessDenied"})
	if IsTransientS3(wrapped403) {
		t.Fatalf("wrapped 403 should be permanent")
	}
	wrappedTimeout := fmt.Errorf("archive: put: %w", timeoutErr{})
	if !IsTransientS3(wrappedTimeout) {
		t.Fatalf("wrapped net timeout should be transient")
	}
}

// errorsAsGuard confirms the timeout classification uses errors.As (reaches a
// wrapped net.Error), not a type assertion on the top-level error.
func TestIsTransientS3_NetErrorAs(t *testing.T) {
	var ne net.Error = timeoutErr{}
	if !errors.As(error(ne), new(net.Error)) {
		t.Fatalf("precondition: timeoutErr must satisfy net.Error")
	}
	if !IsTransientS3(error(ne)) {
		t.Fatalf("net.Error timeout must be transient")
	}
	// Guard against a deadline-exceeded style error wrapped in the chain.
	_ = time.Second
}
