package schema

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Story 6.3 (AC4, NFR40): the external-consumer round-trip gate. For each
// of the three reflection-generated Class A schemas this suite generates
// property-driven, populated Go-struct instances (NOT a single
// fixture-of-convenience), marshals each through the SAME encoding/json
// path an external consumer sees, and validates the result against the
// COMMITTED docs/schemas/<name>.json compiled with jsonschema/v6. A
// matching negative case per schema proves the committed schema actually
// constrains (additionalProperties:false / missing-required), so a
// vacuous always-passing schema cannot slip the gate.

// pinnedParams fixes the gopter seed so the property suite is flake-free
// across runs (the repo-wide Story 1.17 retrospective lesson).
func pinnedParams() *gopter.TestParameters {
	p := gopter.DefaultTestParameters()
	p.Rng.Seed(42)
	p.MinSuccessfulTests = 200
	return p
}

// compileCommittedSchema compiles docs/schemas/<base>.json (the
// committed copy `make schemas` produced) into a validator. The relative
// path resolves from internal/schema/ up to the repo root, mirroring the
// idiom the analyst schema tests use.
func compileCommittedSchema(t *testing.T, base string) *jsonschema.Schema {
	t.Helper()
	path := filepath.Join("..", "..", "docs", "schemas", base+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read committed schema %s: %v", path, err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("parse committed schema %s: %v", path, err)
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource(base+".json", doc); err != nil {
		t.Fatalf("add resource %s: %v", base, err)
	}
	sch, err := c.Compile(base + ".json")
	if err != nil {
		t.Fatalf("compile committed schema %s: %v", base, err)
	}
	return sch
}

// validateMarshalled marshals v through encoding/json and validates the
// result against sch. It returns the validation error (nil on success)
// after re-decoding the bytes into the generic any tree jsonschema
// expects. A marshalling failure is a hard test failure (the production
// path must always marshal).
func validateMarshalled(t *testing.T, sch *jsonschema.Schema, v any) error {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("re-decode marshalled payload: %v", err)
	}
	return sch.Validate(inst)
}

// --- Event ---------------------------------------------------------------

// genEvent produces a populated, edge-case-bearing Event: the sampled and
// unsampled engagement boundary, optional severity/tags present or empty,
// and a raw payload sometimes set. Every generated instance is a VALID
// Event a collector could emit.
func genEvent() gopter.Gen {
	sources := []EventSource{SourceFalco, SourceAudit, SourceRuntime, SourceNetwork, SourceAppLog}
	cats := []EventCategory{CategorySyscall, CategoryAPI, CategoryAudit, CategoryLifecycle, CategoryFlow, CategoryLog}
	return gen.Struct(reflectTypeOf(Event{}), map[string]gopter.Gen{
		"ID":        gen.Identifier().SuchThat(func(s string) bool { return s != "" }),
		"Timestamp": genTime(),
		"Source":    gen.OneConstOf(sources[0], sources[1], sources[2], sources[3], sources[4]),
		"Pod":       genPodRef(),
		"Severity":  gen.OneConstOf("", "low", "medium", "high", "critical"),
		"Category":  gen.OneConstOf(cats[0], cats[1], cats[2], cats[3], cats[4], cats[5]),
		"Summary":   gen.AnyString(),
		"Tags":      gen.SliceOf(gen.Identifier()),
		"Sampled":   gen.Bool(),
	})
}

func TestProperty_Event_ValidatesAgainstCommittedSchema(t *testing.T) {
	sch := compileCommittedSchema(t, "olt_event")
	props := gopter.NewProperties(pinnedParams())
	props.Property("every generated Event validates against olt_event.json", prop.ForAll(
		func(ev Event) bool {
			return validateMarshalled(t, sch, ev) == nil
		}, genEvent()))
	props.TestingRun(t)
}

// --- EvidencePackage -----------------------------------------------------

func genEvidencePackage() gopter.Gen {
	return gen.Struct(reflectTypeOf(EvidencePackage{}), map[string]gopter.Gen{
		"SchemaVersion":    gen.Const("evidence.v1"),
		"PackageID":        gen.Identifier().SuchThat(func(s string) bool { return s != "" }),
		"WorkloadID":       gen.AnyString(),
		"WorkloadIdentity": genWorkloadIdentity(),
		"AssembledAt":      genTime(),
		"WindowStart":      genTime(),
		"WindowEnd":        genTime(),
		"Trigger":          genTrigger(),
		"Events":           genBoundedEvents(),
		"SamplingActive":   gen.Bool(),
	})
}

func TestProperty_EvidencePackage_ValidatesAgainstCommittedSchema(t *testing.T) {
	sch := compileCommittedSchema(t, "evidence_package")
	props := gopter.NewProperties(pinnedParams())
	props.Property("every generated EvidencePackage validates against evidence_package.json", prop.ForAll(
		func(pkg EvidencePackage) bool {
			return validateMarshalled(t, sch, pkg) == nil
		}, genEvidencePackage()))
	props.TestingRun(t)
}

// --- WorkloadPosture -----------------------------------------------------

func genWorkloadPosture() gopter.Gen {
	return gen.Struct(reflectTypeOf(WorkloadPosture{}), map[string]gopter.Gen{
		"Identity":          genWorkloadIdentity(),
		"OrphanPod":         gen.Bool(),
		"Unavailable":       gen.Bool(),
		"UnavailableReason": gen.OneConstOf("", PostureUnavailableTransient, PostureUnavailablePermissionDenied, PostureUnavailableNotFound, PostureUnavailablePermanent),
		"CapturedAt":        genTime(),
		"ServiceAccount":    gen.AnyString(),
	})
}

func TestProperty_WorkloadPosture_ValidatesAgainstCommittedSchema(t *testing.T) {
	sch := compileCommittedSchema(t, "workload_posture")
	props := gopter.NewProperties(pinnedParams())
	props.Property("every generated WorkloadPosture validates against workload_posture.json", prop.ForAll(
		func(p WorkloadPosture) bool {
			return validateMarshalled(t, sch, p) == nil
		}, genWorkloadPosture()))
	props.TestingRun(t)
}

// --- Negative cases ------------------------------------------------------

// TestNegative_CommittedSchemasConstrain proves each committed schema is
// not vacuous: an extra field is rejected by additionalProperties:false,
// and a missing required field is rejected by `required`. Both must fail
// for the RIGHT reason (the keyword in the error), mirroring the
// invalidExemplarKeyword discipline in the analyst schema tests; a
// schema that accepted these would be a silent always-pass.
func TestNegative_CommittedSchemasConstrain(t *testing.T) {
	cases := []struct {
		name    string
		base    string
		payload string
		keyword string
	}{
		{
			name:    "olt_event rejects additional property",
			base:    "olt_event",
			payload: `{"id":"e1","timestamp":"2026-05-15T10:00:00Z","source":"falco","pod":{"name":"p","namespace":"ns","uid":"u"},"category":"syscall","summary":"s","bogus_field":1}`,
			keyword: "additional",
		},
		{
			name:    "olt_event rejects missing required (summary)",
			base:    "olt_event",
			payload: `{"id":"e1","timestamp":"2026-05-15T10:00:00Z","source":"falco","pod":{"name":"p","namespace":"ns","uid":"u"},"category":"syscall"}`,
			keyword: "summary",
		},
		{
			name:    "evidence_package rejects missing required (package_id)",
			base:    "evidence_package",
			payload: `{"schema_version":"evidence.v1","workload_id":"w","workload_identity":{"namespace":"ns","owner_kind":"Deployment","owner_name":"a"},"assembled_at":"2026-05-18T10:00:00Z","window_start":"2026-05-18T09:59:00Z","window_end":"2026-05-18T10:00:00Z","trigger":{"type":"rule_match","fired_at":"2026-05-18T10:00:00Z"}}`,
			keyword: "package_id",
		},
		{
			name:    "workload_posture rejects additional property",
			base:    "workload_posture",
			payload: `{"identity":{"namespace":"ns","owner_kind":"Deployment","owner_name":"a"},"captured_at":"2026-05-12T22:00:00Z","not_a_field":true}`,
			keyword: "additional",
		},
		{
			name:    "workload_posture rejects missing required (captured_at)",
			base:    "workload_posture",
			payload: `{"identity":{"namespace":"ns","owner_kind":"Deployment","owner_name":"a"}}`,
			keyword: "captured_at",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sch := compileCommittedSchema(t, tc.base)
			inst, err := jsonschema.UnmarshalJSON(bytes.NewReader([]byte(tc.payload)))
			if err != nil {
				t.Fatalf("payload is not JSON: %v", err)
			}
			verr := sch.Validate(inst)
			if verr == nil {
				t.Fatalf("payload unexpectedly passed %s schema: %s", tc.base, tc.payload)
			}
			if !contains(verr.Error(), tc.keyword) {
				t.Errorf("failed for the wrong reason: want %q in error, got: %v", tc.keyword, verr)
			}
		})
	}
}

// --- shared generators ---------------------------------------------------

// reflectTypeOf is a tiny alias so the gen.Struct calls read cleanly.
func reflectTypeOf(v any) reflect.Type { return reflect.TypeOf(v) }

func genTime() gopter.Gen {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return gen.Int64Range(0, 365*24*3600).Map(func(secs int64) time.Time {
		return base.Add(time.Duration(secs) * time.Second).UTC()
	})
}

func genPodRef() gopter.Gen {
	return gen.Struct(reflectTypeOf(PodRef{}), map[string]gopter.Gen{
		"Name":      gen.Identifier().SuchThat(func(s string) bool { return s != "" }),
		"Namespace": gen.Identifier().SuchThat(func(s string) bool { return s != "" }),
		"Node":      gen.AnyString(),
		"UID":       gen.Identifier().SuchThat(func(s string) bool { return s != "" }),
	})
}

func genWorkloadIdentity() gopter.Gen {
	return gen.Struct(reflectTypeOf(WorkloadIdentity{}), map[string]gopter.Gen{
		"Namespace": gen.Identifier().SuchThat(func(s string) bool { return s != "" }),
		"OwnerKind": gen.OneConstOf("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"),
		"OwnerName": gen.Identifier().SuchThat(func(s string) bool { return s != "" }),
		"PodName":   gen.AnyString(),
	})
}

// genBoundedEvents caps the embedded Events slice at a small length so
// the property suite does not spend minutes generating deeply-nested
// packages; a handful of events still exercises the array sub-schema.
func genBoundedEvents() gopter.Gen {
	return gen.IntRange(0, 4).FlatMap(func(n any) gopter.Gen {
		gens := make([]gopter.Gen, n.(int))
		for i := range gens {
			gens[i] = genEvent()
		}
		return gopter.CombineGens(gens...).Map(func(vals []any) []Event {
			out := make([]Event, len(vals))
			for i, v := range vals {
				out[i] = v.(Event)
			}
			return out
		})
	}, reflect.TypeOf([]Event{}))
}

func genTrigger() gopter.Gen {
	return gen.Struct(reflectTypeOf(EvidenceTrigger{}), map[string]gopter.Gen{
		"Type":    gen.OneConstOf("rule_match", "baseline_deviation", "multi_signal"),
		"EventID": gen.AnyString(),
		"FiredAt": genTime(),
	})
}
