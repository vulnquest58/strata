package pipeline

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"testing"

	"aperture/internal/consensus"
	"aperture/internal/model"
	"aperture/internal/reliability"
	"aperture/internal/sources"
	"aperture/internal/store"
)

func TestReliabilityBeforeFusion(t *testing.T) {
	// Scenario 1: Source A (high reliability = 0.9) and Source B (low reliability = 0.3)
	// Both report raw score = 70.0.
	// Step 1: Adjusted scores before fusion:
	//   adj_A = 70 * 0.9 = 63.0
	//   adj_B = 70 * 0.3 = 21.0
	// Step 2: Noisy-OR on [63.0, 21.0]:
	//   1 - (1 - 0.63) * (1 - 0.21) = 1 - 0.37 * 0.79 = 1 - 0.2923 = 0.7077 -> 70.77%
	adjScores1 := []float64{70.0 * 0.9, 70.0 * 0.3}
	combined1 := NoisyOR(adjScores1)
	expectedCombined1 := 100.0 * (1.0 - (1.0-0.63)*(1.0-0.21)) // 70.77

	if math.Abs(combined1-expectedCombined1) > 0.001 {
		t.Errorf("Scenario 1: combined = %f; want %f", combined1, expectedCombined1)
	}

	// In naive fusion: Noisy-OR(70, 70) = 1 - 0.3*0.3 = 91%, then multiplied by average reliability 0.6 = 54.6%
	naiveFused := NoisyOR([]float64{70.0, 70.0}) * ((0.9 + 0.3) / 2.0)
	if math.Abs(combined1-naiveFused) < 5.0 {
		t.Errorf("Reliability-then-fuse (%f) should be significantly higher than naive fusion (%f)", combined1, naiveFused)
	}

	// Verify that the combined score is dominated by Source A (63.0) with slight boost from Source B (to 70.77)
	if combined1 < 63.0 {
		t.Errorf("combined1 (%f) should be at least as high as Source A's adjusted score (63.0)", combined1)
	}

	// Scenario 2: Two sources with raw = 70.0 and equal reliability = 0.6
	// Step 1:
	//   adj_A = 70 * 0.6 = 42.0
	//   adj_B = 70 * 0.6 = 42.0
	// Step 2:
	//   1 - (1 - 0.42)^2 = 1 - 0.58^2 = 1 - 0.3364 = 0.6636 -> 66.36%
	adjScores2 := []float64{70.0 * 0.6, 70.0 * 0.6}
	combined2 := NoisyOR(adjScores2)
	expectedCombined2 := 100.0 * (1.0 - (1.0-0.42)*(1.0-0.42)) // 66.36

	if math.Abs(combined2-expectedCombined2) > 0.001 {
		t.Errorf("Scenario 2: combined = %f; want %f", combined2, expectedCombined2)
	}

	// Compare Scenario 1 vs Scenario 2:
	// Both scenarios have the same average reliability ((0.9+0.3)/2 = 0.6 == (0.6+0.6)/2 = 0.6)
	// and identical raw scores (70.0).
	// BUT because Scenario 1 has a high-confidence anchor (0.9 reliability),
	// its combined confidence (70.77%) is strictly higher than Scenario 2 (66.36%).
	if combined1 <= combined2 {
		t.Fatalf("CRITICAL: Scenario 1 (%f) should be higher than Scenario 2 (%f) due to high-reliability anchor!",
			combined1, combined2)
	}
}

func TestFuseFindingsForAssetIntegration(t *testing.T) {
	memStore, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("opening in-memory store: %v", err)
	}
	defer memStore.Close()

	relEngine := reliability.NewEngine(memStore)
	relEngine.RegisterPrior("sourceA", 0.90)
	relEngine.RegisterPrior("sourceB", 0.30)

	candidates := []sources.RawCandidate{
		{AssetID: "test.example.com", SourcePlugin: "sourceA", RawScore: 70.0, AssetType: model.AssetSubdomain},
		{AssetID: "test.example.com", SourcePlugin: "sourceB", RawScore: 70.0, AssetType: model.AssetSubdomain},
	}

	cr := consensus.ConsensusResult{
		AssetID:           "test.example.com",
		TemporalStability: 1.0,
		ResolvedIPs:       []string{"93.184.216.34"},
		Passes:            true,
	}

	f := FuseFindingsForAsset(
		context.Background(),
		"test.example.com",
		model.AssetSubdomain,
		"example.com",
		candidates,
		relEngine,
		cr,
		"test-scan-id",
		map[string]any{},
	)

	if f.ConsensusCount != 2 {
		t.Errorf("expected ConsensusCount=2, got %d", f.ConsensusCount)
	}
	if f.SourcePlugin != "sourceA,sourceB" {
		t.Errorf("expected SourcePlugin='sourceA,sourceB', got %q", f.SourcePlugin)
	}
	if f.RawConfidence != nil {
		t.Errorf("expected RawConfidence=nil for multi-source finding, got %v", *f.RawConfidence)
	}
	if f.PerSourceRawConfidence["sourceA"] != 70.0 || f.PerSourceRawConfidence["sourceB"] != 70.0 {
		t.Errorf("unexpected PerSourceRawConfidence: %v", f.PerSourceRawConfidence)
	}
	if math.Abs(f.CombinedConfidence-70.77) > 0.1 {
		t.Errorf("expected CombinedConfidence ~ 70.77, got %f", f.CombinedConfidence)
	}
	if f.AdjustedConfidence != f.CombinedConfidence {
		t.Errorf("AdjustedConfidence (%f) != CombinedConfidence (%f)", f.AdjustedConfidence, f.CombinedConfidence)
	}

	// Verify JSON marshaling: raw_confidence must be omitted when nil
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	jsonStr := string(data)
	if strings.Contains(jsonStr, `"raw_confidence"`) {
		t.Errorf("expected raw_confidence to be omitted from JSON for multi-source finding, got: %s", jsonStr)
	}

	// Single-source finding must include raw_confidence
	singleCandidates := []sources.RawCandidate{
		{AssetID: "single.example.com", SourcePlugin: "sourceA", RawScore: 65.0},
	}
	singleF := FuseFindingsForAsset(
		context.Background(),
		"single.example.com",
		model.AssetSubdomain,
		"example.com",
		singleCandidates,
		relEngine,
		cr,
		"test-scan-id",
		map[string]any{},
	)
	singleData, err := json.Marshal(singleF)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	singleJsonStr := string(singleData)
	if !strings.Contains(singleJsonStr, `"raw_confidence":65`) {
		t.Errorf("expected raw_confidence:65 in single-source JSON, got: %s", singleJsonStr)
	}
}
