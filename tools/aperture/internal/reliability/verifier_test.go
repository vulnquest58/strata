package reliability

import (
	"context"
	"testing"
	"time"

	"aperture/internal/model"
	"aperture/internal/store"
)

func TestVerifierOlderThanFiltering(t *testing.T) {
	// Initialize in-memory SQLite store
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("opening in-memory store: %v", err)
	}
	defer db.Close()

	ctx := context.Background()
	now := time.Now().UTC()

	// Finding 1: Discovered 48 hours ago (should be sampled)
	fOld := &model.Finding{
		ID:           "find-old-1",
		ScanID:       "scan-1",
		AssetID:      "old.target.com",
		AssetType:    model.AssetSubdomain,
		ParentAsset:  "target.com",
		SourcePlugin: "hackertarget",
		DiscoveredAt: now.Add(-48 * time.Hour),
	}
	if err := db.UpsertFinding(ctx, fOld); err != nil {
		t.Fatalf("upsert fOld: %v", err)
	}

	// Finding 2: Discovered 2 hours ago (should be excluded by --older-than 24h)
	fRecent := &model.Finding{
		ID:           "find-recent-1",
		ScanID:       "scan-2",
		AssetID:      "recent.target.com",
		AssetType:    model.AssetSubdomain,
		ParentAsset:  "target.com",
		SourcePlugin: "hackertarget",
		DiscoveredAt: now.Add(-2 * time.Hour),
	}
	if err := db.UpsertFinding(ctx, fRecent); err != nil {
		t.Fatalf("upsert fRecent: %v", err)
	}

	// Finding 3: Discovered 72 hours ago from different source
	fOtherSource := &model.Finding{
		ID:           "find-other-1",
		ScanID:       "scan-3",
		AssetID:      "other.target.com",
		AssetType:    model.AssetSubdomain,
		ParentAsset:  "target.com",
		SourcePlugin: "rapiddns",
		DiscoveredAt: now.Add(-72 * time.Hour),
	}
	if err := db.UpsertFinding(ctx, fOtherSource); err != nil {
		t.Fatalf("upsert fOtherSource: %v", err)
	}

	// Test 1: Sample hackertarget with olderThan = 24h
	sampled, err := db.SampleUnverifiedFindings(ctx, "hackertarget", 1.0, 24*time.Hour)
	if err != nil {
		t.Fatalf("SampleUnverifiedFindings failed: %v", err)
	}
	if len(sampled) != 1 {
		t.Fatalf("expected 1 sampled finding, got %d", len(sampled))
	}
	if sampled[0].ID != "find-old-1" {
		t.Errorf("expected find-old-1, got %s", sampled[0].ID)
	}

	// Test 2: Sample with olderThan = 1h (both hackertarget findings should qualify)
	sampledAllHackertarget, err := db.SampleUnverifiedFindings(ctx, "hackertarget", 1.0, 1*time.Hour)
	if err != nil {
		t.Fatalf("SampleUnverifiedFindings failed: %v", err)
	}
	if len(sampledAllHackertarget) != 2 {
		t.Fatalf("expected 2 sampled findings for 1h threshold, got %d", len(sampledAllHackertarget))
	}

	// Test 3: Sample with olderThan = 24h and empty source (samples across all sources)
	sampledAcrossSources, err := db.SampleUnverifiedFindings(ctx, "", 1.0, 24*time.Hour)
	if err != nil {
		t.Fatalf("SampleUnverifiedFindings across sources failed: %v", err)
	}
	if len(sampledAcrossSources) != 2 {
		t.Fatalf("expected 2 sampled findings across sources, got %d", len(sampledAcrossSources))
	}
}
