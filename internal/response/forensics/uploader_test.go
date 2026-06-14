package forensics

import (
	"errors"
	"testing"
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
