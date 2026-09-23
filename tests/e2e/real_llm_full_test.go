//go:build e2e

// Story 10.6: a real incident on kind-full is investigated by a real model.
//
// Nothing here is published to NATS by the test, and no model output is
// supplied by it. A fresh workload reads /etc/shadow inside its own
// container; Falco's stock "Read sensitive file untrusted" rule fires, the
// collector ingests it, the correlator packages it, the FR19 gate starts
// the L1 -> L2 -> Senior chain, each role calls the in-cluster Ollama, and
// the chain publishes its assessment to AUDIT.assessments. The test only
// reads that record and checks it:
//
//   - AC1: L1, L2 and Senior all contributed, and each output validates
//     against its published model contract (docs/schemas).
//   - AC2: every role's recorded provider and model is what the live
//     release was configured with (read from the release's own ConfigMap,
//     not from a constant in this file), and the Ollama server really holds
//     that model.
//   - AC3: the model's own confidence was above the ollama cap of 25 and the
//     audit record carries it capped to exactly 25.
//
// Gated twice, like the Story 10.7 test: OLT_E2E_FULL says the cluster runs
// the full profile, OLT_E2E_REAL_LLM says it runs it with its real model
// (not the fake-LLM overlay `make e2e-full-report-archive` leaves behind).
// `make e2e-full-real-llm` restores the profile and runs this.
package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/olokotoh/olaitan/internal/config"
	"github.com/olokotoh/olaitan/internal/subjects"
)

const (
	// ollamaScoreCap is the trust cap of the ollama family, enforced in code
	// (cmd/olaitan/analyst_chain.go roleScoreCap). Deliberately a constant
	// here and not read from the release: AC3 is about the code path, and a
	// value lowered in the release would make the check easier, not stronger.
	ollamaScoreCap = 25

	// A 3B model on CPU reads a few thousand prompt tokens per role before
	// it writes a word, and the chain runs L1, L2 and Senior in turn, inline
	// in the single FSM consumer, behind any package that qualified before
	// the attack. This bounds the whole path, syscall to audit record; it
	// asserts provenance and validity, not latency.
	realLLMBudget = 25 * time.Minute
)

// realLLMWant is what the audit record must attribute every role to.
type realLLMWant struct {
	Provider string
	Model    string
	Cap      int
}

// modelSchemas are the compiled model output contracts, keyed by the audit
// record field they validate.
type modelSchemas map[string]*jsonschema.Schema

// loadModelSchemas compiles the published L1, L2 and Senior contracts from
// docs/schemas. They are byte-identical to the copies the runners embed
// (internal/decision/analyst/*_schema.json); the checker reads the docs
// copy so it validates against what the project publishes, independently
// of the code under test.
func loadModelSchemas(t *testing.T) modelSchemas {
	t.Helper()
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Join(filepath.Dir(here), "..", "..", "docs", "schemas")
	out := modelSchemas{}
	for field, file := range map[string]string{
		"l1_hypothesis":     "l1_hypothesis.json",
		"l2_verification":   "l2_verification.json",
		"threat_assessment": "threat_assessment.json",
	} {
		b, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		c := jsonschema.NewCompiler()
		if err := c.AddResource(file, doc); err != nil {
			t.Fatalf("add %s: %v", file, err)
		}
		s, err := c.Compile(file)
		if err != nil {
			t.Fatalf("compile %s: %v", file, err)
		}
		out[field] = s
	}
	return out
}

// realLLMRecord is the slice of the AUDIT.assessments v2 payload the
// checker reads. The per-role outputs stay raw so they are validated as
// published, not as re-encoded by a Go struct that might drop a field.
type realLLMRecord struct {
	SchemaVersion       string            `json:"schema_version"`
	PackageID           string            `json:"package_id"`
	WorkloadID          string            `json:"workload_id"`
	Mode                string            `json:"mode"`
	AgentsAvailable     []string          `json:"agents_available"`
	PromptVersions      map[string]string `json:"prompt_versions"`
	Providers           map[string]string `json:"providers"`
	Models              map[string]string `json:"models"`
	RawConfidence       int               `json:"raw_confidence"`
	LLMCappedConfidence int               `json:"llm_capped_confidence"`
	L1Hypothesis        json.RawMessage   `json:"l1_hypothesis"`
	L2Verification      json.RawMessage   `json:"l2_verification"`
	ThreatAssessment    json.RawMessage   `json:"threat_assessment"`
	RedactedEvidence    struct {
		Events []struct {
			ID     string `json:"id"`
			Source string `json:"source"`
		} `json:"events"`
	} `json:"redacted_evidence"`
	RedactionApplied bool `json:"redaction_applied"`
}

// seniorContractFields are the ThreatAssessment keys the Senior model
// produces (docs/schemas/threat_assessment.json). The audit record carries
// the whole ThreatAssessment, controller-stamped fields included, so the
// model's part is projected out before validation; the model's confidence
// is the RAW one (the capped value is the controller's).
var seniorContractFields = []string{"threat_type", "reasoning", "mitre_techniques", "noted_disagreements", "kill_chain_stage"}

// checkRealLLMAssessment returns every way raw fails AC1-AC3 for want; an
// empty result means the record proves all three.
func checkRealLLMAssessment(raw []byte, want realLLMWant, schemas modelSchemas) []string {
	var p []string
	var rec realLLMRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return []string{fmt.Sprintf("record is not an AUDIT.assessments JSON object: %v", err)}
	}
	if rec.SchemaVersion != "audit.assessments.v2" {
		p = append(p, fmt.Sprintf("schema_version = %q, want audit.assessments.v2", rec.SchemaVersion))
	}
	if rec.Mode != "full" {
		p = append(p, fmt.Sprintf("mode = %q, want full (L1 -> L2 -> Senior)", rec.Mode))
	}
	agents := append([]string(nil), rec.AgentsAvailable...)
	sort.Strings(agents)
	if strings.Join(agents, ",") != "l1,l2,senior" {
		p = append(p, fmt.Sprintf("agents_available = %v, want exactly l1, l2 and senior (a role that degraded did not contribute)", rec.AgentsAvailable))
	}
	if !rec.RedactionApplied {
		p = append(p, "redaction_applied = false; the model must only ever see redacted evidence")
	}

	// AC2: provenance, per role.
	for _, role := range []string{"l1", "l2", "senior"} {
		if got := rec.Providers[role]; got != want.Provider {
			p = append(p, fmt.Sprintf("providers[%s] = %q, want the configured %q", role, got, want.Provider))
		}
		if got := rec.Models[role]; got != want.Model {
			p = append(p, fmt.Sprintf("models[%s] = %q, want the configured %q", role, got, want.Model))
		}
		if rec.PromptVersions[role] == "" {
			p = append(p, fmt.Sprintf("prompt_versions[%s] missing; the output cannot be traced to a prompt", role))
		}
	}

	// AC1: each role's output validates against its published contract.
	validate := func(field string, doc []byte) {
		if len(doc) == 0 || string(doc) == "null" {
			p = append(p, fmt.Sprintf("%s missing from the record", field))
			return
		}
		inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
		if err != nil {
			p = append(p, fmt.Sprintf("%s is not JSON: %v", field, err))
			return
		}
		if err := schemas[field].Validate(inst); err != nil {
			p = append(p, fmt.Sprintf("%s does not validate against its schema: %v", field, err))
		}
	}
	validate("l1_hypothesis", rec.L1Hypothesis)
	validate("l2_verification", rec.L2Verification)

	var ta map[string]any
	if len(rec.ThreatAssessment) == 0 || json.Unmarshal(rec.ThreatAssessment, &ta) != nil || ta == nil {
		p = append(p, "threat_assessment missing or not an object")
	} else {
		if v, _ := ta["llm_unavailable"].(bool); v {
			p = append(p, "threat_assessment.llm_unavailable = true: the Senior verdict is the degrade, not model output")
		}
		senior := map[string]any{}
		for _, k := range seniorContractFields {
			if v, ok := ta[k]; ok {
				senior[k] = v
			}
		}
		senior["confidence"] = ta["raw_confidence"]
		b, _ := json.Marshal(senior)
		validate("threat_assessment", b)

		// AC3, on the assessment itself as well as the envelope.
		if got := jsonInt(ta["raw_confidence"]); got != rec.RawConfidence {
			p = append(p, fmt.Sprintf("threat_assessment.raw_confidence = %d but the record says %d", got, rec.RawConfidence))
		}
		if got := jsonInt(ta["llm_capped_confidence"]); got != want.Cap {
			p = append(p, fmt.Sprintf("threat_assessment.llm_capped_confidence = %d, want the %s cap %d", got, want.Provider, want.Cap))
		}
	}

	// AC3: the model's confidence was above the cap, and the cap held.
	if rec.RawConfidence <= want.Cap {
		p = append(p, fmt.Sprintf("raw_confidence = %d is not above the cap %d, so this record does not exercise the trust cap", rec.RawConfidence, want.Cap))
	}
	if rec.LLMCappedConfidence != want.Cap {
		p = append(p, fmt.Sprintf("llm_capped_confidence = %d, want the %s cap %d", rec.LLMCappedConfidence, want.Provider, want.Cap))
	}

	// The record is about a real Falco detection, not some other signal.
	falco := false
	for _, ev := range rec.RedactedEvidence.Events {
		if ev.Source == "falco" {
			falco = true
		}
	}
	if !falco {
		p = append(p, "redacted_evidence carries no falco event; this is not the in-pod attack the test ran")
	}
	return p
}

// jsonInt reads a JSON number decoded into any; anything else is -1.
func jsonInt(v any) int {
	if f, ok := v.(float64); ok {
		return int(f)
	}
	return -1
}

// configuredChain reads the analyst configuration of the LIVE release from
// its own ConfigMap and returns what every role must be attributed to.
func configuredChain(t *testing.T) realLLMWant {
	t.Helper()
	raw := kubectl(t, "get", "configmap", defaultReleaseName+"-config", "-n", defaultNamespace,
		"-o", `jsonpath={.data.olaitan\.yaml}`)
	path := filepath.Join(t.TempDir(), "olaitan.yaml")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("the live release's config does not load: %v", err)
	}
	a := cfg.Analyst
	if a.Provider != "local" {
		t.Fatalf("live analyst.provider = %q, want local: this is not the full profile's real-model configuration (run `make e2e-full-real-llm`, which restores it)", a.Provider)
	}
	for role, p := range map[string]string{"l1": a.L1Provider, "l2": a.L2Provider, "senior": a.SeniorProvider} {
		if p != "" && p != "ollama" {
			t.Fatalf("live analyst.%s_provider = %q: a role is routed away from the in-cluster model (the fake-LLM overlay is still applied?)", role, p)
		}
	}
	if a.Local.Model == "" {
		t.Fatal("live analyst.local.model is empty")
	}
	if strings.Contains(raw, "fake-llm") {
		t.Fatal("the live release's config references fake-llm")
	}
	return realLLMWant{Provider: "ollama", Model: a.Local.Model, Cap: ollamaScoreCap}
}

func TestRealLLM_RealIncidentOnFullProfile(t *testing.T) {
	if os.Getenv("OLT_E2E_FULL") == "" || os.Getenv("OLT_E2E_REAL_LLM") == "" {
		t.Skip("real-LLM smoke skipped; set OLT_E2E_FULL=1 and OLT_E2E_REAL_LLM=1 (make e2e-full-real-llm) to run")
	}
	requireKindCluster(t)
	requireFullProfile(t)
	schemas := loadModelSchemas(t)

	want := configuredChain(t)
	t.Logf("configured chain: every role -> provider %q model %q (cap %d)", want.Provider, want.Model, want.Cap)

	// The server really holds that model: the provenance in the record is
	// then a claim about something that exists, not a label.
	list := kubectl(t, "exec", "deploy/"+defaultReleaseName+"-ollama", "-n", defaultNamespace, "--", "ollama", "list")
	t.Logf("ollama list:\n%s", strings.TrimSpace(list))
	if !strings.Contains(list, want.Model) {
		t.Fatalf("the in-cluster Ollama does not hold %q", want.Model)
	}

	runID := fmt.Sprintf("%d", time.Now().UnixNano()%1e9)
	ns := "olaitan-llm-" + runID
	workloadID := ns + "/Deployment/victim"

	// Read AUDIT_ASSESSMENTS from a start time, for the reason given in the
	// Story 10.7 test: an explicit ephemeral consumer cannot race the attack.
	start := time.Now().Add(-2 * time.Second)
	portForward(t, "svc/"+defaultReleaseName+"-nats", natsLocalPort, "4222")
	nc, err := nats.Connect("nats://localhost:" + natsLocalPort)
	if err != nil {
		t.Fatalf("nats connect: %v", err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatalf("jetstream: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cons, err := js.CreateOrUpdateConsumer(ctx, "AUDIT_ASSESSMENTS", jetstream.ConsumerConfig{
		FilterSubject:     subjects.AuditAssessments,
		AckPolicy:         jetstream.AckNonePolicy,
		DeliverPolicy:     jetstream.DeliverByStartTimePolicy,
		OptStartTime:      &start,
		InactiveThreshold: 30 * time.Minute,
	})
	if err != nil {
		t.Fatalf("AUDIT_ASSESSMENTS consumer: %v", err)
	}

	// --- the attack, for real, inside a pod ---------------------------------
	t.Cleanup(func() {
		_ = exec.Command("kubectl", "delete", "namespace", ns, "--ignore-not-found", "--wait=false").Run()
	})
	mustRun(t, "create namespace "+ns, "kubectl", "create", "namespace", ns)
	mustRun(t, "create victim", "kubectl", "-n", ns, "create", "deployment", "victim", "--image=nginx:1.27-alpine")
	mustRun(t, "victim ready", "kubectl", "-n", ns, "rollout", "status", "deploy/victim", "--timeout=3m")
	// Let Falco's container plugin learn the new container (Story 10.3).
	time.Sleep(10 * time.Second)
	attackAt := time.Now()
	mustRun(t, "falco: read /etc/shadow in the victim",
		"kubectl", "-n", ns, "exec", "deploy/victim", "--", "sh", "-c", "cat /etc/shadow > /dev/null")

	// --- the assessment -----------------------------------------------------
	// The FIRST full-chain record for the victim must pass. Taking any later
	// one that happens to pass would hide a model that is only sometimes
	// schema-valid.
	deadline := time.Now().Add(realLLMBudget)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("no full-chain AUDIT.assessments record for %s within %s of the attack: the incident was not raised, the chain did not trigger, or the model did not answer in time (see the aggregator log)",
				workloadID, realLLMBudget)
		}
		batch, err := cons.Fetch(10, jetstream.FetchMaxWait(5*time.Second))
		if err != nil {
			time.Sleep(time.Second)
			continue
		}
		for msg := range batch.Messages() {
			var head struct {
				WorkloadID string `json:"workload_id"`
				Mode       string `json:"mode"`
				PackageID  string `json:"package_id"`
			}
			if json.Unmarshal(msg.Data(), &head) != nil {
				continue
			}
			if head.WorkloadID != workloadID {
				t.Logf("AUDIT.assessments for another workload (%s, mode %s) while waiting", head.WorkloadID, head.Mode)
				continue
			}
			if head.Mode == "dfir" {
				continue
			}
			var pretty bytes.Buffer
			_ = json.Indent(&pretty, msg.Data(), "", "  ")
			t.Logf("first chain record for the victim, %s after the attack:\n%s", time.Since(attackAt).Round(time.Second), pretty.String())
			if problems := checkRealLLMAssessment(msg.Data(), want, schemas); len(problems) > 0 {
				t.Fatalf("the first chain record for the victim fails Story 10.6:\n  - %s", strings.Join(problems, "\n  - "))
			}
			var rec realLLMRecord
			_ = json.Unmarshal(msg.Data(), &rec)
			t.Logf("AC1 ok: L1, L2 and Senior outputs from %s validate against docs/schemas", want.Model)
			t.Logf("AC2 ok: providers %v, models %v", rec.Providers, rec.Models)
			t.Logf("AC3 ok: raw_confidence %d capped to llm_capped_confidence %d (ollama cap %d)", rec.RawConfidence, rec.LLMCappedConfidence, want.Cap)
			return
		}
		if err := batch.Error(); err != nil && !errors.Is(err, nats.ErrTimeout) && !errors.Is(err, context.DeadlineExceeded) {
			t.Logf("AUDIT_ASSESSMENTS batch: %v", err)
		}
	}
}
