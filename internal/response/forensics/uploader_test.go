package forensics

import (
	"errors"
	"net/http"
	"testing"

	"github.com/minio/minio-go/v7/pkg/encrypt"
)

// TestNewMinioUploader_RequiredFields covers the config validation guard.
func TestNewMinioUploader_RequiredFields(t *testing.T) {
	cases := []MinioConfig{
		{},
		{Endpoint: "e"},
		{Endpoint: "e", AccessKey: "a"},
		{Endpoint: "e", AccessKey: "a", SecretKey: "s"}, // missing bucket
	}
	for i, cfg := range cases {
		if _, err := NewMinioUploader(cfg); !errors.Is(err, errMissingS3Config) {
			t.Fatalf("case %d: want errMissingS3Config, got %v", i, err)
		}
	}
}

// TestNewMinioUploader_OK confirms a complete config constructs a client.
func TestNewMinioUploader_OK(t *testing.T) {
	u, err := NewMinioUploader(MinioConfig{
		Endpoint:  "localhost:9000",
		AccessKey: "minioadmin",
		SecretKey: "minioadmin",
		Bucket:    "forensics",
	})
	if err != nil {
		t.Fatalf("NewMinioUploader: %v", err)
	}
	if u.bucket != "forensics" {
		t.Fatalf("bucket = %q", u.bucket)
	}
}

// TestBuildPutOptions gives the SSE-KMS PUT directive direct coverage (round-1
// review MED+LOW). A non-empty alias MUST yield a non-nil SSE-KMS directive
// carrying the alias; an empty alias MUST yield no SSE directive (bucket
// default). Mutation-check: removing putOpts.ServerSideEncryption = sse in
// buildPutOptions makes the non-empty-alias assertions below fail.
func TestBuildPutOptions(t *testing.T) {
	t.Run("non-empty alias yields SSE-KMS directive", func(t *testing.T) {
		opts, err := buildPutOptions("alias/forensics")
		if err != nil {
			t.Fatalf("buildPutOptions: %v", err)
		}
		if opts.ServerSideEncryption == nil {
			t.Fatal("non-empty alias must set a non-nil ServerSideEncryption directive")
		}
		if got := opts.ServerSideEncryption.Type(); got != encrypt.KMS {
			t.Fatalf("SSE type = %v, want SSE-KMS", got)
		}
		// The directive must carry the alias on the wire (X-Amz-Server-Side-
		// Encryption-Aws-Kms-Key-Id), proving the alias is actually plumbed
		// through rather than a bare bucket-default SSE.
		h := http.Header{}
		opts.ServerSideEncryption.Marshal(h)
		found := false
		for _, vs := range h {
			for _, v := range vs {
				if v == "alias/forensics" {
					found = true
				}
			}
		}
		if !found {
			t.Fatalf("SSE-KMS directive headers %v do not carry the key alias", h)
		}
	})

	t.Run("empty alias yields no SSE directive", func(t *testing.T) {
		opts, err := buildPutOptions("")
		if err != nil {
			t.Fatalf("buildPutOptions: %v", err)
		}
		if opts.ServerSideEncryption != nil {
			t.Fatal("empty alias must leave ServerSideEncryption nil (bucket default)")
		}
	})
}
