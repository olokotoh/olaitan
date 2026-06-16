package rubric

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVariants_ByteDeterministic asserts both variant generators render
// byte-identically over the same synthetic incident across repeated calls (no
// time.Now() in rendered content, no map-iteration ordering), so the offline
// golden is reproducible (AC1/AC5/OQ5).
func TestVariants_ByteDeterministic(t *testing.T) {
	inc := SyntheticS1Incident()

	llmA := RenderLLMVariant(inc)
	llmB := RenderLLMVariant(inc)
	if llmA != llmB {
		t.Fatalf("LLM variant not byte-deterministic across two renders")
	}
	tmplA := RenderTemplatedVariant(inc)
	tmplB := RenderTemplatedVariant(inc)
	if tmplA != tmplB {
		t.Fatalf("templated variant not byte-deterministic across two renders")
	}
}

// TestVariants_DistinctNarrative asserts variant (a) carries the LLM narrative
// and variant (b) carries the fixed templated stub: the (a)-vs-(b) contrast is
// the analyst narrative (AC1, BI-1/BI-7). It also asserts both render the SAME
// factual sections over the same evidence (a fair like-for-like).
func TestVariants_DistinctNarrative(t *testing.T) {
	inc := SyntheticS1Incident()
	llm := RenderLLMVariant(inc)
	tmpl := RenderTemplatedVariant(inc)

	if llm == tmpl {
		t.Fatalf("variants must differ (the LLM narrative vs the templated stub)")
	}
	if !strings.Contains(llm, syntheticNarrative) {
		t.Fatalf("LLM variant missing the synthetic narrative")
	}
	if strings.Contains(tmpl, syntheticNarrative) {
		t.Fatalf("templated variant must NOT carry the LLM narrative")
	}
	if !strings.Contains(tmpl, templatedStub) {
		t.Fatalf("templated variant missing the templated stub")
	}
	// Both render the same factual ATT&CK technique over the same evidence.
	for _, body := range []string{llm, tmpl} {
		if !strings.Contains(body, "T1611") {
			t.Fatalf("variant missing the shared factual ATT&CK technique T1611")
		}
		if !strings.Contains(body, "Kill-chain timeline") {
			t.Fatalf("variant missing the shared kill-chain timeline section")
		}
	}
}

// TestBlindPair_SeededReproducible asserts the blind-randomised pairing is
// reproducible from the incident_id seed and the un-blinding key round-trips
// (AC2/OQ5): two BlindPair calls over the same incident produce the identical
// slot order and key, and every slot maps back to a real variant.
func TestBlindPair_SeededReproducible(t *testing.T) {
	inc := SyntheticS1Incident()
	a := BlindPair(inc)
	b := BlindPair(inc)

	if a.IncidentID != b.IncidentID {
		t.Fatalf("incident id drift: %q vs %q", a.IncidentID, b.IncidentID)
	}
	for i := range a.Reports {
		if a.Reports[i].Slot != b.Reports[i].Slot || a.Reports[i].Body != b.Reports[i].Body {
			t.Fatalf("blinded pair not reproducible at slot %d", i)
		}
	}
	// The key round-trips: both slots present, mapping to the two distinct
	// variants, and the un-blinding lookup agrees with the slot order.
	seen := map[Variant]bool{}
	for _, report := range a.Reports {
		v, ok := a.VariantForSlot(report.Slot)
		if !ok {
			t.Fatalf("slot %q has no un-blinding entry", report.Slot)
		}
		seen[v] = true
	}
	if !seen[VariantLLM] || !seen[VariantTemplated] {
		t.Fatalf("un-blinding key must cover both variants, got %v", seen)
	}
}

// TestBlindPair_BodyMatchesUnblindedVariant asserts the body in a blinded slot
// is the SAME bytes the un-blinded variant renderer produces for that slot's
// true variant (the blinding only permutes slot order, it never alters content).
func TestBlindPair_BodyMatchesUnblindedVariant(t *testing.T) {
	inc := SyntheticS1Incident()
	pair := BlindPair(inc)
	want := map[Variant]string{
		VariantLLM:       RenderLLMVariant(inc),
		VariantTemplated: RenderTemplatedVariant(inc),
	}
	for _, report := range pair.Reports {
		v, ok := pair.VariantForSlot(report.Slot)
		if !ok {
			t.Fatalf("slot %q missing from key", report.Slot)
		}
		if report.Body != want[v] {
			t.Fatalf("slot %q body does not match the un-blinded %q variant", report.Slot, v)
		}
	}
}

// TestRunOffline_EmitterShape asserts the full offline harness produces the
// rubric.score.v1 records the Story-5.5 reader requires (AC2/AC3/AC5): one
// record per (incident, variant, rater, dimension), keyed on the 5 canonical
// dimension strings EXACTLY, every record labelled synthetic (BI-2/BI-5).
func TestRunOffline_EmitterShape(t *testing.T) {
	result, err := RunOffline(Options{Scenario: "s1", NRaters: 2})
	if err != nil {
		t.Fatalf("RunOffline: %v", err)
	}

	// One incident x 2 variants x 2 raters x 5 dimensions = 20 records.
	const wantRecords = 1 * 2 * 2 * 5
	if len(result.Scores) != wantRecords {
		t.Fatalf("got %d records, want %d", len(result.Scores), wantRecords)
	}

	dims := map[Dimension]int{}
	variants := map[Variant]int{}
	for _, sc := range result.Scores {
		if sc.SchemaVersion != SchemaVersionRubricScore {
			t.Fatalf("record has schema_version %q, want %q", sc.SchemaVersion, SchemaVersionRubricScore)
		}
		if !sc.Synthetic {
			t.Fatalf("offline record not labelled synthetic: %+v", sc)
		}
		if !strings.HasPrefix(sc.Rater, OfflineRaterPrefix) {
			t.Fatalf("offline rater %q missing the synthetic prefix", sc.Rater)
		}
		if sc.Score < LikertMin || sc.Score > LikertMax {
			t.Fatalf("score %d out of Likert range", sc.Score)
		}
		dims[sc.Dimension]++
		variants[sc.Variant]++
	}
	for _, dim := range CanonicalDimensions {
		if dims[dim] == 0 {
			t.Fatalf("dimension %q absent from the records", dim)
		}
	}
	if len(dims) != len(CanonicalDimensions) {
		t.Fatalf("got %d distinct dimensions, want %d (no 6th dimension)", len(dims), len(CanonicalDimensions))
	}
	if variants[VariantLLM] == 0 || variants[VariantTemplated] == 0 {
		t.Fatalf("both variants must be scored, got %v", variants)
	}
}

// TestEmit_ByteDeterministic asserts the emitter writes byte-identical artefacts
// across two runs of the same Result (seeded, sorted, no wall-clock), so the
// offline golden is reproducible (OQ5).
func TestEmit_ByteDeterministic(t *testing.T) {
	result, err := RunOffline(Options{Scenario: "s1", NRaters: 2})
	if err != nil {
		t.Fatalf("RunOffline: %v", err)
	}
	dirA := t.TempDir()
	dirB := t.TempDir()
	if err := Emit(dirA, result); err != nil {
		t.Fatalf("Emit A: %v", err)
	}
	if err := Emit(dirB, result); err != nil {
		t.Fatalf("Emit B: %v", err)
	}
	runDir := RunDirName(result.Summary)
	for _, name := range []string{ScoresFile, MetadataFile} {
		a := readFile(t, filepath.Join(dirA, runDir, name))
		b := readFile(t, filepath.Join(dirB, runDir, name))
		if a != b {
			t.Fatalf("%s not byte-deterministic across two emits", name)
		}
	}
}

// TestEmit_ScoresParseAsRubricScoreV1 asserts the emitted scores.jsonl parses
// back into rubric.score.v1 records with the exact wire fields the Story-5.5
// reader requires (the schema cannot drift between the Go emitter and the Python
// reader, OQ4).
func TestEmit_ScoresParseAsRubricScoreV1(t *testing.T) {
	result, err := RunOffline(Options{Scenario: "s1", NRaters: 2})
	if err != nil {
		t.Fatalf("RunOffline: %v", err)
	}
	dir := t.TempDir()
	if err := Emit(dir, result); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	path := filepath.Join(dir, RunDirName(result.Summary), ScoresFile)
	f, err := os.Open(path) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatalf("open scores: %v", err)
	}
	defer f.Close() //nolint:errcheck // read-only test file

	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var sc RubricScore
		if err := json.Unmarshal([]byte(line), &sc); err != nil {
			t.Fatalf("line %d not parseable as rubric.score.v1: %v", count+1, err)
		}
		if sc.SchemaVersion != SchemaVersionRubricScore || sc.IncidentID == "" || sc.Dimension == "" {
			t.Fatalf("line %d missing required fields: %+v", count+1, sc)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan scores: %v", err)
	}
	if count != len(result.Scores) {
		t.Fatalf("read %d records, emitted %d", count, len(result.Scores))
	}
}

// TestEmit_MetadataCarriesJoinKeys asserts metadata.yaml carries the
// join/provenance keys the Story-5.5 load_rubric_scores reader reads (OQ4): the
// scenario, the counts, the synthetic honesty flag, and a manifest hash.
func TestEmit_MetadataCarriesJoinKeys(t *testing.T) {
	result, err := RunOffline(Options{Scenario: "s1", NRaters: 2})
	if err != nil {
		t.Fatalf("RunOffline: %v", err)
	}
	dir := t.TempDir()
	if err := Emit(dir, result); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	meta := readFile(t, filepath.Join(dir, RunDirName(result.Summary), MetadataFile))
	for _, key := range []string{"scenario: s1", "n_incidents: 1", "n_raters: 2", "synthetic: true", "manifest_sha256: "} {
		if !strings.Contains(meta, key) {
			t.Fatalf("metadata missing %q\n--- metadata ---\n%s", key, meta)
		}
	}
}

// TestEmitStaticWorkflow_BlindedFilesNoVariantLabel asserts the static-file
// workflow writes the blinded report files + per-rater scoring sheets and that
// the rater-facing report files are INDISTINGUISHABLE in their self-description
// (AC2/OQ3, HIGH-1): the ENTIRE rater-facing body - front-matter AND prose -
// carries no variant label, no asymmetric provenance metadata (report_kind /
// dfir_provider / dfir_model / prompt_hash, the LLM report.v1, the templated
// rubric.templated.v1), and no prose self-identifying tell (the
// templated-baseline markers "fixed Markdown template" / "language-model" /
// "machine-rendered" / "baseline", or the LLM-variant markers "SYNTHETIC" /
// "synthetic offline" / "not a thesis-final"). Both files' front-matter blocks
// must also be structurally identical (same keys). The two reports may differ
// ONLY in narrative substance/quality, never in self-description. The un-blinding
// key is kept separate (off disk).
func TestEmitStaticWorkflow_BlindedFilesNoVariantLabel(t *testing.T) {
	result, err := RunOffline(Options{Scenario: "s1", NRaters: 2})
	if err != nil {
		t.Fatalf("RunOffline: %v", err)
	}
	dir := t.TempDir()
	if err := EmitStaticWorkflow(dir, result); err != nil {
		t.Fatalf("EmitStaticWorkflow: %v", err)
	}
	incidentDir := filepath.Join(dir, RunDirName(result.Summary), "workflow", result.Pairs[0].IncidentID)
	// The variant-identifying tokens that must NOT appear ANYWHERE in EITHER
	// rater-facing file - front-matter AND prose (HIGH-1, the prose-level
	// blinding regression). The first group are the front-matter provenance
	// markers; the rest are the prose self-labelling tells (the templated
	// baseline's and the synthetic narrative's self-description).
	identifyingTokens := []string{
		"variant: llm", "variant: templated", `"variant"`,
		"report_kind", "dfir_provider", "dfir_model", "prompt_hash",
		"report.v1", "rubric.templated.v1",
		"language-model", "fixed Markdown template", "templated-baseline", "baseline",
		"machine-rendered", "machine-generated", "SYNTHETIC", "synthetic offline",
		"not a thesis-final",
	}
	var frontMatterKeySets [][]string
	for _, slot := range blindLabels {
		body := readFile(t, filepath.Join(incidentDir, slot+".md"))
		for _, tok := range identifyingTokens {
			if strings.Contains(body, tok) {
				t.Fatalf("blinded report %s leaks identifying token %q", slot, tok)
			}
		}
		frontMatterKeySets = append(frontMatterKeySets, frontMatterKeys(t, slot, body))
	}
	// The two rater-facing files must be structurally identical in their
	// identifying header: same front-matter keys, in the same order.
	if len(frontMatterKeySets) != 2 {
		t.Fatalf("expected 2 blinded files, got %d", len(frontMatterKeySets))
	}
	if strings.Join(frontMatterKeySets[0], ",") != strings.Join(frontMatterKeySets[1], ",") {
		t.Fatalf("blinded files have different front-matter keys: %v vs %v",
			frontMatterKeySets[0], frontMatterKeySets[1])
	}
	for raterIdx := 1; raterIdx <= result.Summary.NRaters; raterIdx++ {
		sheet := readFile(t, filepath.Join(incidentDir, "scoring-sheet-synthetic-"+itoa(raterIdx)+".md"))
		for _, dim := range CanonicalDimensions {
			if !strings.Contains(sheet, string(dim)) {
				t.Fatalf("scoring sheet missing dimension %q", dim)
			}
		}
	}
}

// frontMatterKeys extracts the ordered YAML keys of the leading front-matter
// block of a rater-facing report body (the "---" ... "---" header), so the test
// can assert the two blinded files are structurally identical in their
// identifying header. It fails the test if the body has no front-matter block.
func frontMatterKeys(t *testing.T, slot, body string) []string {
	t.Helper()
	if !strings.HasPrefix(body, "---\n") {
		t.Fatalf("blinded report %s has no leading front-matter block", slot)
	}
	rest := body[len("---\n"):]
	end := strings.Index(rest, "\n---\n")
	if end < 0 {
		t.Fatalf("blinded report %s front-matter is not closed", slot)
	}
	var keys []string
	for _, line := range strings.Split(rest[:end], "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if i := strings.Index(line, ":"); i >= 0 {
			keys = append(keys, line[:i])
		}
	}
	return keys
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // test-controlled path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
