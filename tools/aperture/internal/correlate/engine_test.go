package correlate

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"aperture/internal/model"
	"aperture/internal/store"
)

func TestExtractFingerprint(t *testing.T) {
	finding := &model.Finding{
		ID:                 "f-1",
		AssetID:            "api.github.com",
		ParentAsset:        "github.com",
		ResolvedIPs:        []string{"140.82.121.6"},
		AdjustedConfidence: 79.89,
		Metadata: map[string]any{
			"san_list": []any{"api.github.com", "github.com", "*.github.io"},
			"cname":    "github.map.fastly.net",
		},
	}

	eng := NewEngine(nil)
	fp := eng.ExtractFingerprint(finding)

	if fp.AssetID != "api.github.com" {
		t.Errorf("expected AssetID api.github.com, got %s", fp.AssetID)
	}
	if fp.RootDomain != "github.com" {
		t.Errorf("expected RootDomain github.com, got %s", fp.RootDomain)
	}
	if len(fp.IPRanges24) != 1 || fp.IPRanges24[0] != "140.82.121.0/24" {
		t.Errorf("expected /24 subnet 140.82.121.0/24, got %v", fp.IPRanges24)
	}
	if len(fp.SANList) != 3 {
		t.Errorf("expected 3 SANs, got %d", len(fp.SANList))
	}
	hasFastly := false
	for _, cdn := range fp.CDNProviders {
		if cdn == "Fastly" {
			hasFastly = true
		}
	}
	if !hasFastly {
		t.Errorf("expected Fastly CDN detected, got %v", fp.CDNProviders)
	}
}

func TestCrossTargetSANOverlapCorrelation(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test_aperture.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("opening test store: %v", err)
	}
	defer st.Close()

	ctx := context.Background()

	// Fingerprint for domain A (company-a.com) holding a cert that includes company-b.com in SANs!
	fpA := &model.InfrastructureFingerprint{
		AssetID:      "portal.company-a.com",
		RootDomain:   "company-a.com",
		ResolvedIPs:  []string{"10.20.30.40"},
		IPRanges24:   []string{"10.20.30.0/24"},
		SANList:      []string{"portal.company-a.com", "api.company-b.com", "*.company-b.com"},
		ExtractedAt:  time.Now().UTC(),
	}

	// Fingerprint for domain B (company-b.com)
	fpB := &model.InfrastructureFingerprint{
		AssetID:      "api.company-b.com",
		RootDomain:   "company-b.com",
		ResolvedIPs:  []string{"10.20.30.50"}, // Same /24 subnet!
		IPRanges24:   []string{"10.20.30.0/24"},
		SANList:      []string{"api.company-b.com"},
		ExtractedAt:  time.Now().UTC(),
	}

	if err := st.SaveFingerprint(ctx, fpA); err != nil {
		t.Fatalf("saving fpA: %v", err)
	}
	if err := st.SaveFingerprint(ctx, fpB); err != nil {
		t.Fatalf("saving fpB: %v", err)
	}

	eng := NewEngine(st)
	corrs, err := eng.Correlate(ctx, "")
	if err != nil {
		t.Fatalf("running correlate: %v", err)
	}

	if len(corrs) == 0 {
		t.Fatalf("expected correlations discovered, got 0")
	}

	foundSAN := false
	foundSubnet := false
	for _, c := range corrs {
		if c.CorrelationType == "shared_cert_san" {
			foundSAN = true
			if c.Confidence != 0.95 {
				t.Errorf("expected SAN confidence 0.95, got %v", c.Confidence)
			}
			t.Logf("Found SAN Correlation: %+v", c)
		}
		if c.CorrelationType == "shared_subnet_24" {
			foundSubnet = true
			if c.Confidence != 0.98 {
				t.Errorf("expected weighted Subnet confidence 0.98, got %v", c.Confidence)
			}
			t.Logf("Found Subnet Correlation: %+v", c)
		}
	}

	if !foundSAN {
		t.Errorf("expected shared_cert_san correlation between company-a.com and company-b.com")
	}
	if !foundSubnet {
		t.Errorf("expected shared_subnet_24 correlation between company-a.com and company-b.com")
	}
}
