// Package registry provides the central factory for source plugins.
// It is intentionally separate from internal/sources (which defines the interfaces)
// to avoid import cycles: active/passive/generative sub-packages all import
// internal/sources for RawCandidate and SourcePlugin, so a registry inside
// internal/sources would create a cycle.
package registry

import (
	"fmt"
	"strings"

	"aperture/internal/sources"
	"aperture/internal/sources/active"
	"aperture/internal/sources/generative"
	"aperture/internal/sources/passive"
)

// Config holds parameters needed to instantiate source plugins.
type Config struct {
	TimeoutSecs       int
	OTXAPIKey         string
	CertSpotterAPIKey string
	ActiveEnabled     bool
	MarkovCount       int
	RawDNSServers     []string
}

// Build returns instantiated SourcePlugin objects for the given names.
// Returns an error for unknown names or if an active source is requested
// without ActiveEnabled.
func Build(names []string, cfg Config) ([]sources.SourcePlugin, error) {
	if cfg.MarkovCount == 0 {
		cfg.MarkovCount = 500
	}

	var plugins []sources.SourcePlugin
	for _, name := range names {
		name = strings.TrimSpace(strings.ToLower(name))
		p, err := buildOne(name, cfg)
		if err != nil {
			return nil, err
		}
		if p != nil {
			plugins = append(plugins, p)
		}
	}
	return plugins, nil
}

// All returns the names of every available plugin grouped by category.
func All() map[string][]string {
	return map[string][]string{
		"passive":    {"crtsh", "hackertarget", "rapiddns", "otx", "certspotter"},
		"active":     {"dns_bruteforce"},
		"generative": {"markov"},
	}
}

func buildOne(name string, cfg Config) (sources.SourcePlugin, error) {
	switch name {
	case "crtsh":
		return passive.NewCrtSh(cfg.TimeoutSecs), nil
	case "hackertarget":
		return passive.NewHackerTarget(cfg.TimeoutSecs), nil
	case "rapiddns":
		return passive.NewRapidDNS(cfg.TimeoutSecs), nil
	case "otx":
		return passive.NewOTX(cfg.TimeoutSecs, cfg.OTXAPIKey), nil
	case "certspotter":
		return passive.NewCertSpotter(cfg.TimeoutSecs, cfg.CertSpotterAPIKey), nil
	case "dns_bruteforce":
		if !cfg.ActiveEnabled {
			return nil, fmt.Errorf("dns_bruteforce requires --active flag")
		}
		return active.NewDNSBruteforce("", cfg.RawDNSServers, cfg.TimeoutSecs), nil
	case "markov":
		return generative.NewMarkovGenerator(cfg.MarkovCount), nil
	default:
		return nil, fmt.Errorf("unknown source plugin %q — available: %v", name, All())
	}
}
