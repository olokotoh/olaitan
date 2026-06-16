package rubric

import (
	"hash/fnv"
	"math/rand"

	"github.com/olokotoh/olaitan/internal/report/dfir"
)

// blindLabels are the rater-facing slot labels for a blinded pair. The rater
// scores "report-a" and "report-b" WITHOUT knowing which slot holds the
// LLM-generated variant; the un-blinding key records the slot->variant mapping
// for scoring (AC2).
var blindLabels = [2]string{"report-a", "report-b"}

// BlindedReport is one rater-facing report in a blinded pair: the slot label the
// rater sees and the rendered Markdown body. The variant is NOT carried here
// (the rater must not see it); it lives only in the BlindedPair un-blinding key.
type BlindedReport struct {
	Slot string
	Body string
}

// BlindedPair is one incident's two variants presented in a SEEDED random slot
// order WITHOUT the variant label visible to the rater, plus the un-blinding KEY
// (Slots maps the rater-facing slot label to the true variant) kept separately
// for scoring (AC2, OQ5). The order is reproducible from the incident_id seed.
type BlindedPair struct {
	IncidentID string
	Reports    [2]BlindedReport
	// Slots is the un-blinding key: slot label -> true variant. The harness
	// keeps it separate from the rater-facing reports so scoring can map a
	// rater's per-slot scores back to the LLM/templated variant.
	Slots map[string]Variant
}

// seedFromIncidentID derives a deterministic 64-bit RNG seed from the
// incident_id (OQ5), so the blinded slot order is reproducible per incident and
// the offline golden is byte-stable. FNV-1a is a stable, dependency-free hash;
// the same incident_id always yields the same seed (and thus the same order).
func seedFromIncidentID(incidentID string) int64 {
	h := fnv.New64a()
	// fnv.Write never returns an error; the hash is over the incident_id bytes.
	_, _ = h.Write([]byte(incidentID))
	return int64(h.Sum64())
}

// BlindPair renders both variants over the incident and presents them in a
// SEEDED random slot order (OQ5), returning the rater-facing reports plus the
// un-blinding key. The seed is derived from the incident_id, so two runs over
// the same incident produce the identical blinded order and key (byte-reproducible
// for the offline golden).
func BlindPair(inc dfir.Incident) BlindedPair {
	incidentID := IncidentID(inc)
	// The two variants in canonical (un-blinded) order. The RNG below permutes
	// them into the rater-facing slots.
	variants := [2]Variant{VariantLLM, VariantTemplated}
	bodies := map[Variant]string{
		VariantLLM:       RenderLLMVariant(inc),
		VariantTemplated: RenderTemplatedVariant(inc),
	}

	// A deterministic local RNG seeded from the incident_id (NOT the math/rand
	// global state and NOT time.Now()), so the slot assignment is reproducible.
	rng := rand.New(rand.NewSource(seedFromIncidentID(incidentID))) //nolint:gosec // determinism, not security; the blinding key is kept separately
	order := [2]int{0, 1}
	// A single seeded coin-flip decides whether the two variants keep their
	// canonical order or swap into the slots. Two outcomes, fully reproducible.
	if rng.Intn(2) == 1 {
		order[0], order[1] = 1, 0
	}

	pair := BlindedPair{
		IncidentID: incidentID,
		Slots:      map[string]Variant{},
	}
	for slotIdx, variantIdx := range order {
		variant := variants[variantIdx]
		slot := blindLabels[slotIdx]
		pair.Reports[slotIdx] = BlindedReport{Slot: slot, Body: bodies[variant]}
		pair.Slots[slot] = variant
	}
	return pair
}

// VariantForSlot returns the true variant a rater-facing slot label maps to (the
// un-blinding lookup used at scoring time). The bool is false for an unknown
// slot label.
func (p BlindedPair) VariantForSlot(slot string) (Variant, bool) {
	v, ok := p.Slots[slot]
	return v, ok
}
