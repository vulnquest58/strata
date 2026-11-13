package registry

import (
	"testing"

	"aperture/internal/model"
)

func TestAllSourcesIncluded(t *testing.T) {
	all := All()
	passiveList, ok := all["passive"]
	if !ok {
		t.Fatalf("expected 'passive' category in All()")
	}

	foundOTX := false
	foundCertSpotter := false
	for _, name := range passiveList {
		if name == "otx" {
			foundOTX = true
		}
		if name == "certspotter" {
			foundCertSpotter = true
		}
	}
	if !foundOTX {
		t.Fatalf("expected 'otx' in passive sources list: %v", passiveList)
	}
	if !foundCertSpotter {
		t.Fatalf("expected 'certspotter' in passive sources list: %v", passiveList)
	}
}

func TestBuildCertSpotterSource(t *testing.T) {
	cfg := Config{
		TimeoutSecs:       20,
		CertSpotterAPIKey: "test-token",
	}

	plugins, err := Build([]string{"certspotter"}, cfg)
	if err != nil {
		t.Fatalf("Build(['certspotter']) returned error: %v", err)
	}
	if len(plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(plugins))
	}

	p := plugins[0]
	if p.Name() != "certspotter" {
		t.Errorf("expected Name() == 'certspotter', got %s", p.Name())
	}
	if p.Category() != model.SourcePassive {
		t.Errorf("expected Category() == SourcePassive, got %v", p.Category())
	}
	if p.DefaultPriorReliability() != 0.5 {
		t.Errorf("expected DefaultPriorReliability() == 0.5, got %f", p.DefaultPriorReliability())
	}
}

func TestBuildOTXSource(t *testing.T) {
	cfg := Config{
		TimeoutSecs: 20,
		OTXAPIKey:   "test-key",
	}

	plugins, err := Build([]string{"otx"}, cfg)
	if err != nil {
		t.Fatalf("Build(['otx']) returned error: %v", err)
	}
	if len(plugins) != 1 {
		t.Fatalf("expected 1 plugin, got %d", len(plugins))
	}

	p := plugins[0]
	if p.Name() != "otx" {
		t.Errorf("expected Name() == 'otx', got %s", p.Name())
	}
	if p.Category() != model.SourcePassive {
		t.Errorf("expected Category() == SourcePassive, got %v", p.Category())
	}
	if p.DefaultPriorReliability() != 0.5 {
		t.Errorf("expected DefaultPriorReliability() == 0.5, got %f", p.DefaultPriorReliability())
	}
}

func TestBuildMultipleSources(t *testing.T) {
	cfg := Config{
		TimeoutSecs: 15,
	}

	plugins, err := Build([]string{"hackertarget", "otx"}, cfg)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if len(plugins) != 2 {
		t.Fatalf("expected 2 plugins, got %d", len(plugins))
	}
}
