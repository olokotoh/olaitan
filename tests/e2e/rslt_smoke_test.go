//go:build e2e

package e2e_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// auditAssessment mirrors the slice of the AUDIT.assessments v2 payload this
// test asserts (Story 3.14 schema); only the fields AC7 checks are decoded.
type auditAssessment struct {
	SchemaVersion       string            `json:"schema_version"`
	Mode                string            `json:"mode"`
	AgentsAvailable     []string          `json:"agents_available"`
	PromptVersions      map[string]string `json:"prompt_versions"`
	LLMCappedConfidence int               `json:"llm_capped_confidence"`
	RedactionApplied    bool              `json:"redaction_applied"`
}

// TestKindSmoke_RSLTFull_ChainProducesCappedAssessment is the Story 3.16 AC7
// smoke: against an RSLT-full install routed at the in-cluster fake-LLM, an
// S2-style high-severity trigger drives the full L1 -> L2 -> Senior chain,
// which publishes a capped ThreatAssessment to AUDIT.assessments carrying the
// per-role prompt versions, and the redaction-applied guarantee holds.
//
// Gated on OLT_E2E_RSLT so it runs ONLY under `make e2e-local-rslt` (which
// stands up the RSLT-full chart + fake-LLM); the default RS e2e job skips it.
func TestKindSmoke_RSLTFull_ChainProducesCappedAssessment(t *testing.T) {
	if os.Getenv("OLT_E2E_RSLT") == "" {
		t.Skip("RSLT-full smoke skipped; set OLT_E2E_RSLT=1 (make e2e-local-rslt) to run")
	}
	requireKindCluster(t)
	waitForPodsReady(t)
	podName := applySyntheticWorkload(t)
	waitForNATSReady(t)
	portForward(t, "svc/"+defaultReleaseName+"-nats", natsLocalPort, "4222")

	nc, err := nats.Connect("nats://localhost:" + natsLocalPort)
	if err != nil {
		t.Fatalf("NATS connect: %v", err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatalf("JetStream: %v", err)
	}

	// The proven RS trigger emits an EvidencePackage carrying the severity-90
	// OLT-PRIV-001 rule match, which clears the FR19 gate (>= 50) and fires
	// the investigation chain.
	publishCorrelatorTrigger(t, js, podName)

	// Poll AUDIT.assessments (NFR5 budget is 5s; allow generous slack for the
	// kind-loaded fake-LLM chain + JetStream propagation).
	ctx, cancel := context.WithTimeout(context.Background(), assertionTimeout)
	defer cancel()
	cons, err := js.CreateOrUpdateConsumer(ctx, "AUDIT_ASSESSMENTS", jetstream.ConsumerConfig{
		AckPolicy:     jetstream.AckExplicitPolicy,
		DeliverPolicy: jetstream.DeliverAllPolicy,
	})
	if err != nil {
		t.Fatalf("AUDIT_ASSESSMENTS consumer: %v", err)
	}

	deadline := time.After(assertionTimeout)
	for {
		select {
		case <-deadline:
			t.Fatal("no AUDIT.assessments full-chain assessment within the assertion budget")
		default:
		}
		msgs, ferr := cons.Fetch(10, jetstream.FetchMaxWait(2*time.Second))
		if ferr != nil {
			continue
		}
		for msg := range msgs.Messages() {
			_ = msg.Ack()
			var a auditAssessment
			if json.Unmarshal(msg.Data(), &a) != nil {
				continue
			}
			if a.SchemaVersion != "audit.assessments.v2" {
				continue
			}
			// AC7: full chain, capped confidence > 0, all three role prompt
			// versions present, redaction applied.
			if a.Mode != "full" {
				continue
			}
			if a.LLMCappedConfidence <= 0 {
				t.Errorf("full-chain assessment llm_capped_confidence = %d, want > 0", a.LLMCappedConfidence)
			}
			for _, role := range []string{"l1", "l2", "senior"} {
				if a.PromptVersions[role] == "" {
					t.Errorf("assessment missing prompt_versions[%s]: %+v", role, a.PromptVersions)
				}
			}
			if !a.RedactionApplied {
				t.Error("assessment must carry redaction_applied=true")
			}
			return // success
		}
	}
}
