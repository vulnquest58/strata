package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration structure loaded from config.yaml.
type Config struct {
	Scan      ScanConfig      `yaml:"scan"`
	Sources   SourcesConfig   `yaml:"sources"`
	Resolvers ResolversConfig `yaml:"resolvers"`
	Consensus ConsensusConfig `yaml:"consensus"`
	Storage   StorageConfig   `yaml:"storage"`
}

type ScanConfig struct {
	// DefaultConcurrency is the number of concurrent workers in the pipeline.
	DefaultConcurrency int `yaml:"default_concurrency"`
	// DefaultTimeout is the HTTP/DNS request timeout in seconds.
	DefaultTimeout int `yaml:"default_timeout"`
}

type SourcesConfig struct {
	// OTXAPIKey is the AlienVault OTX API key (optional; sourced from OTX_API_KEY env var if absent).
	OTXAPIKey string `yaml:"otx_api_key"`
	// DefaultPriorReliability is the reliability prior for unknown sources (0.0–1.0).
	DefaultPriorReliability float64 `yaml:"default_prior_reliability"`
}

type ResolversConfig struct {
	// DoHProviders is the list of DNS-over-HTTPS endpoints to use.
	DoHProviders []DoHProvider `yaml:"doh_providers"`
	// RawDNSServers is the list of raw UDP DNS servers for dns_bruteforce.
	RawDNSServers []string `yaml:"raw_dns_servers"`
}

type DoHProvider struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
}

type ConsensusConfig struct {
	// TemporalStabilityThreshold is the minimum ratio of successful resolutions to accept a finding.
	TemporalStabilityThreshold float64 `yaml:"temporal_stability_threshold"`
	// MinJitterSeconds is the minimum jitter delay between resolution attempts.
	MinJitterSeconds int `yaml:"min_jitter_seconds"`
	// MaxJitterSeconds is the maximum jitter delay between resolution attempts.
	MaxJitterSeconds int `yaml:"max_jitter_seconds"`
}

type StorageConfig struct {
	// DatabasePath is the path to the SQLite database file.
	DatabasePath string `yaml:"database_path"`
}

// Load reads the configuration from the given YAML file path.
func Load(path string) (*Config, error) {
	cfg := defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// No config file — use defaults entirely.
			applyEnvOverrides(cfg)
			return cfg, nil
		}
		return nil, fmt.Errorf("reading config file %q: %w", path, err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %q: %w", path, err)
	}

	applyEnvOverrides(cfg)
	return cfg, nil
}

// defaults returns a Config with sensible default values.
func defaults() *Config {
	return &Config{
		Scan: ScanConfig{
			DefaultConcurrency: 50,
			DefaultTimeout:     10,
		},
		Sources: SourcesConfig{
			DefaultPriorReliability: 0.5,
		},
		Resolvers: ResolversConfig{
			DoHProviders: []DoHProvider{
				{Name: "Cloudflare", URL: "https://cloudflare-dns.com/dns-query"},
				{Name: "Google", URL: "https://dns.google/dns-query"},
				{Name: "Quad9", URL: "https://dns.quad9.net/dns-query"},
			},
			RawDNSServers: []string{"8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"},
		},
		Consensus: ConsensusConfig{
			TemporalStabilityThreshold: 0.66,
			MinJitterSeconds:           5,
			MaxJitterSeconds:           45,
		},
		Storage: StorageConfig{
			DatabasePath: "aperture.db",
		},
	}
}

// applyEnvOverrides overlays environment variables on the parsed config.
func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("OTX_API_KEY"); v != "" {
		cfg.Sources.OTXAPIKey = strings.TrimSpace(v)
	}
	if v := os.Getenv("APERTURE_DB"); v != "" {
		cfg.Storage.DatabasePath = strings.TrimSpace(v)
	}
}
