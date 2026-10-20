package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
)

// serviceAccountTokenPath is where Kubernetes projects the pod's own
// ServiceAccount token.
const serviceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// ownServiceAccountUsername returns the apiserver username of the
// ServiceAccount this process runs as ("system:serviceaccount:<ns>:<name>"),
// read from the "sub" claim of its projected token, or "" when it cannot
// be read (outside a cluster, token not mounted). The token is only
// decoded, never verified, logged or sent anywhere: the claim is used to
// recognise Olaitan's own API calls in the audit stream (Story 10.12), so
// the baseline does not count the aggregator's identity lookups as the
// workload's behaviour on any install, whatever the release namespace.
func ownServiceAccountUsername(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return subjectFromJWT(strings.TrimSpace(string(b)))
}

func subjectFromJWT(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	if !strings.HasPrefix(claims.Sub, "system:serviceaccount:") {
		return ""
	}
	return claims.Sub
}
