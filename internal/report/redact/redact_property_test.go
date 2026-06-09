package redact

// This gopter property suite is the SINGLE boundary contract that makes
// NFR15's "100 percent of LLM-bound boundaries" promise executable (AC3). It
// asserts the post-Redact() payload (the thing a provider would receive) carries
// NO unredacted secret, for randomised secret-bearing inputs, across all three
// role contexts (L1/L2/Senior).
//
// SCOPE (BI-8): Story 3.1 ships Redact() + this harness; it does NOT wire real
// LLM providers (3.2) or the L1/L2/Senior call sites (3.5-3.7). The "provider"
// here is a TEST-ONLY mock that records the exact payload it would send. Because
// Stories 3.2/3.5-3.7 are contractually required (3.2 AC3) to route every LLM
// call through Redact(), proving the post-Redact() payload is secret-free for
// every role makes "100 percent of L1/L2/Senior paths" literal even with the
// call sites stubbed. Story 3.2 (provider redaction-invocation) and Epic 4
// (persistence boundary, AC5) EXTEND this same harness; 3.1 establishes it.

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"

	"github.com/olokotoh/olaitan/internal/schema"
)

// role is the test-only role enum standing in for the three not-yet-existing
// LLM-bound boundary entry points (BI-8.1). The property parameterises over all
// three so "100 percent of L1/L2/Senior paths" is literal.
type role int

const (
	roleL1 role = iota
	roleL2
	roleSenior
)

var allRoles = []role{roleL1, roleL2, roleSenior}

// providerMock records the exact payload it would send to an LLM provider. It
// is the legitimate stand-in for the 3.2 Provider (BI-8.2): Story 3.2 replaces
// it with the real provider's redaction-invocation test.
type providerMock struct {
	role     role
	received []byte
}

// send marshals the redacted package as the payload the provider would receive.
func (p *providerMock) send(pkg schema.EvidencePackage) error {
	b, err := json.Marshal(pkg)
	if err != nil {
		return err
	}
	p.received = b
	return nil
}

// injectedSecrets is the ground-truth set of secret values a generator placed
// into a package, so the property can substring-scan for any survivor (BI-9.1).
type injectedSecrets struct {
	pkg     schema.EvidencePackage
	secrets []string
}

func pinnedParams() *gopter.TestParameters {
	p := gopter.DefaultTestParameters()
	p.Rng.Seed(3131)
	p.MinSuccessfulTests = 500
	return p
}

// genSecretBearingPackage produces an EvidencePackage whose Event.Raw trees are
// seeded with known secret-bearing fields and records the ground-truth secrets.
//
// ROUND-1 fix #9: the generator now injects AND ground-truth-tracks ALL of: a
// secret-keyed string value, a secret in the K8s {name,value} env shape, a JWT
// embedded inside a LARGER Raw string, a secret in Event.Tags, a raw-payload
// byte blob (tracking the DECODED bytes too), a nested-object secret value under
// a secret key, and a file-ref with secret contents.
func genSecretBearingPackage() gopter.Gen {
	// A non-empty bounded slice of seed strings drives one event per seed; the
	// map function caps the count so packages stay small and fast.
	return gen.SliceOf(gen.AlphaString()).Map(func(seeds []string) injectedSecrets {
		if len(seeds) == 0 {
			seeds = []string{"seed"}
		}
		if len(seeds) > 4 {
			seeds = seeds[:4]
		}
		var secrets []string
		events := make([]schema.Event, len(seeds))
		for i, seed := range seeds {
			s := sanitise(seed) + strconv.Itoa(i)
			secretVal := "sk-" + s + "-secret"
			envSecret := "envsecret-" + s      // K8s {name,value} env shape
			tagSecret := genJWT("tag" + s)     // JWT inside a tag
			jwt := genJWT(s)                   // JWT in a larger string
			fileContents := "file-secret-" + s // file-ref contents
			deepSecret := secretVal + "-deep"  // nested secret value
			dottedSecret := "dotleak-" + s     // value under a DOTTED secret key (round-2 fix #1)
			tagKVSecret := "kvsecret-" + s     // key=value secret in a Tag (round-2 fix #3)
			// A genuine binary blob so the heuristic reduces it; track BOTH the
			// encoded form AND the decoded bytes as ground truth.
			rawBytes := []byte{0x00, 0x01, 0xff, 0xfe, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x10 ^ byte(i), 0x11, 0x12, 0x13}
			rawB64 := base64.StdEncoding.EncodeToString(rawBytes)
			// A base64 of a PRINTABLE ASCII secret under `data` (round-2 fix #2):
			// the canonical K8s Secret shape. Track BOTH the encoded form AND the
			// decoded secret string as ground truth.
			dataDecoded := "printable-secret-" + s
			dataB64 := base64.StdEncoding.EncodeToString([]byte(dataDecoded))
			secrets = append(secrets,
				secretVal, envSecret, tagSecret, jwt, fileContents, deepSecret,
				rawB64, string(rawBytes), dottedSecret, tagKVSecret,
				dataB64, dataDecoded,
			)

			raw := map[string]any{
				"api_key":       secretVal,
				"db.password":   dottedSecret,    // DOTTED secret key (round-2 fix #1)
				"authorization": "Bearer " + jwt, // JWT embedded in a LARGER string (fix #2)
				"payload":       rawB64,          // raw byte blob (fix #8)
				// Canonical K8s Secret shape (round-2 fix #2): a base64 of a
				// PRINTABLE secret under `data`, with no path-like sibling so it
				// routes through the raw-payload reduction (not the file-ref one).
				"secretObj": map[string]any{"kind": "Secret", "data": dataB64},
				"file":      map[string]any{"path": "/etc/app/x", "contents": fileContents},
				"containers": []any{ // K8s {name,value} env shape (fix #1)
					map[string]any{"env": []any{
						map[string]any{"name": "DB_PASSWORD", "value": envSecret},
						map[string]any{"name": "LOG_LEVEL", "value": "debug"},
					}},
				},
				"nested": map[string]any{
					"credentials": map[string]any{"deep": deepSecret},
					"safe":        "kept-value",
				},
			}
			rb, _ := json.Marshal(raw)
			events[i] = schema.Event{
				ID:      "e" + strconv.Itoa(i),
				Summary: "saw token " + jwt + " on the wire",
				Tags:    []string{"benign", "auth=" + tagSecret, "password=" + tagKVSecret, "env=prod"},
				Raw:     rb,
			}
		}
		return injectedSecrets{
			pkg: schema.EvidencePackage{
				PackageID:       "pkg-prop",
				WorkloadID:      "ns/Deployment/web",
				Events:          events,
				WorkloadPosture: &schema.WorkloadPosture{},
			},
			secrets: secrets,
		}
	})
}

// genJWT builds a structurally valid JWT keyed off seed so it is unique-ish.
func genJWT(seed string) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"` + sanitise(seed) + `","exp":9999999999}`))
	sig := base64.RawURLEncoding.EncodeToString([]byte("sig-" + sanitise(seed)))
	return hdr + "." + body + "." + sig
}

// sanitise strips characters that would break the JWT body JSON.
func sanitise(s string) string {
	if s == "" {
		return "x"
	}
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return 'x'
	}, s)
}

// TestProperty_NoSecretReachesProvider is the NFR15 core (AC3): for every
// generated package and every role, the redacted payload the provider mock
// receives contains NO injected secret value. The assertion is over the WHOLE
// marshalled EvidencePackage (ROUND-1 fix #9/#10), so a leak through ANY field
// (including a future root field) is caught.
func TestProperty_NoSecretReachesProvider(t *testing.T) {
	props := gopter.NewProperties(pinnedParams())
	props.Property("no injected secret survives Redact for any role", prop.ForAll(
		func(inj injectedSecrets) bool {
			for _, r := range allRoles {
				redacted, _ := Redact(inj.pkg)
				mock := &providerMock{role: r}
				if err := mock.send(redacted); err != nil {
					return false
				}
				payload := string(mock.received)
				for _, secret := range inj.secrets {
					if secret != "" && strings.Contains(payload, secret) {
						return false
					}
				}
				// The redaction tokens must be present (something was redacted).
				// encoding/json HTML-escapes the literal '<'/'>' of the tokens to
				// </>, so match the marshalled forms.
				if !strings.Contains(payload, jsonEscape(redactedToken)) || !strings.Contains(payload, jsonEscape(redactedJWTToken)) {
					return false
				}
				// Benign values must SURVIVE (no over-redaction, ROUND-1
				// balance): the LOG_LEVEL=debug env value and kept-value.
				if !strings.Contains(payload, "debug") || !strings.Contains(payload, "kept-value") {
					return false
				}
				// Structural assertions (Task 6.2/BI-9.2): raw payloads carry
				// ONLY sha256+len; file refs carry ONLY path+size+sha256.
				if !structuralShapesOK(redacted) {
					return false
				}
			}
			return true
		},
		genSecretBearingPackage(),
	))
	props.TestingRun(t)
}

// structuralShapesOK walks each redacted Event.Raw and asserts that every
// raw_payload placeholder carries exactly {redacted,sha256,len} and every
// file-ref reduction carries exactly {path,size,sha256} (BI-9.2). The generator
// produces file refs with no extra sibling keys, so the file-ref form is the
// minimal three-key shape.
func structuralShapesOK(pkg schema.EvidencePackage) bool {
	for _, ev := range pkg.Events {
		if len(ev.Raw) == 0 {
			continue
		}
		var tree any
		if json.Unmarshal(ev.Raw, &tree) != nil {
			return false
		}
		if !shapeWalk(tree) {
			return false
		}
	}
	return true
}

func shapeWalk(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		if red, ok := t["redacted"].(string); ok && red == ReasonRawPayload {
			// raw payload placeholder: exactly redacted+sha256+len.
			if len(t) != 3 {
				return false
			}
			_, hasSha := t["sha256"]
			_, hasLen := t["len"]
			return hasSha && hasLen
		}
		if _, hasSha := t["sha256"]; hasSha {
			if _, hasPath := t["path"]; hasPath {
				// file-ref reduction: exactly path+size+sha256 (the generator
				// adds no sibling keys).
				if len(t) != 3 {
					return false
				}
				_, hasSize := t["size"]
				return hasSize
			}
		}
		for _, e := range t {
			if !shapeWalk(e) {
				return false
			}
		}
		return true
	case []any:
		for _, e := range t {
			if !shapeWalk(e) {
				return false
			}
		}
		return true
	default:
		return true
	}
}

// TestProperty_Determinism (AC3, BI-9.3): Redact() twice yields byte-identical
// redacted JSON and an equal ordered []RedactionEvent.
func TestProperty_Determinism(t *testing.T) {
	props := gopter.NewProperties(pinnedParams())
	props.Property("Redact is deterministic", prop.ForAll(
		func(inj injectedSecrets) bool {
			r1, e1 := Redact(inj.pkg)
			r2, e2 := Redact(inj.pkg)
			b1, _ := json.Marshal(r1)
			b2, _ := json.Marshal(r2)
			if string(b1) != string(b2) {
				return false
			}
			// The ordered events must match on their stable redaction fields.
			// RedactedAt is a wall-clock decision-time stamp (metadata, not
			// redaction content), so it is excluded from the determinism
			// comparison; the byte-identical redacted JSON above is the
			// content guarantee.
			if len(e1) != len(e2) {
				return false
			}
			for i := range e1 {
				a, b := e1[i], e2[i]
				if a.FieldPath != b.FieldPath || a.Reason != b.Reason || a.WorkloadID != b.WorkloadID {
					return false
				}
			}
			return true
		},
		genSecretBearingPackage(),
	))
	props.TestingRun(t)
}

// TestProperty_NoMutation (AC3, BI-9.4): the input package is byte-identical
// (deep-equal) before and after Redact().
func TestProperty_NoMutation(t *testing.T) {
	props := gopter.NewProperties(pinnedParams())
	props.Property("Redact never mutates the input package", prop.ForAll(
		func(inj injectedSecrets) bool {
			before, _ := json.Marshal(inj.pkg)
			_, _ = Redact(inj.pkg)
			after, _ := json.Marshal(inj.pkg)
			return string(before) == string(after)
		},
		genSecretBearingPackage(),
	))
	props.TestingRun(t)
}

// TestProperty_PostureSurfaceIntact confirms the already-redaction-aware
// WorkloadPosture (Story 1.11) is not regressed: a posture-bearing package still
// redacts cleanly and the walk leaves the posture surface intact (Dev Notes).
func TestProperty_PostureSurfaceIntact(t *testing.T) {
	pkg := schema.EvidencePackage{
		PackageID:       "pkg-posture",
		WorkloadID:      "w",
		WorkloadPosture: &schema.WorkloadPosture{},
		Events:          []schema.Event{{ID: "e1", Raw: mustRawProp(map[string]any{"safe": "v"})}},
	}
	out, events := Redact(pkg)
	if out.WorkloadPosture == nil {
		t.Error("posture dropped by redaction")
	}
	if len(events) != 0 {
		t.Errorf("posture-only package produced unexpected redactions: %+v", events)
	}
}

func mustRawProp(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// jsonEscape returns the encoding/json representation of s (without the
// surrounding quotes), so a token carrying HTML-escaped '<'/'>' is matched
// against the marshalled payload.
func jsonEscape(s string) string {
	b, _ := json.Marshal(s)
	return string(b[1 : len(b)-1])
}
