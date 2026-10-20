package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func fakeJWT(payload string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(payload)) + "." + enc([]byte("sig"))
}

func TestOwnServiceAccountUsername(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "token")
	if err := os.WriteFile(p, []byte(fakeJWT(`{"sub":"system:serviceaccount:olaitan:olaitan-aggregator"}`)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ownServiceAccountUsername(p); got != "system:serviceaccount:olaitan:olaitan-aggregator" {
		t.Fatalf("got %q", got)
	}
	for name, tok := range map[string]string{
		"not a jwt":       "abc",
		"bad base64":      "a.!!!.c",
		"not json":        fakeJWT("nope"),
		"user, not an SA": fakeJWT(`{"sub":"kubernetes-admin"}`),
		"no sub claim":    fakeJWT(`{"iss":"x"}`),
	} {
		if got := subjectFromJWT(tok); got != "" {
			t.Errorf("%s: got %q, want empty", name, got)
		}
	}
	if got := ownServiceAccountUsername(filepath.Join(dir, "missing")); got != "" {
		t.Errorf("missing file: got %q", got)
	}
}
