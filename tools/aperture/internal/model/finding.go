package model

import "time"

// AssetType classifies the kind of network asset discovered.
type AssetType string

const (
	AssetSubdomain AssetType = "subdomain"
	AssetIP        AssetType = "ip"
	AssetCNAME     AssetType = "cname"
	AssetMX        AssetType = "mx"
)

// SourceCategory classifies how a source plugin obtains data.
type SourceCategory string

const (
	SourcePassive    SourceCategory = "passive"    // Pure OSINT, no direct contact with target
	SourceActive     SourceCategory = "active"     // Direct DNS/TCP contact with target
	SourceGenerative SourceCategory = "generative" // Algorithmically generated candidates
)

// Finding is the canonical output record from Aperture.
// It represents a single network asset discovered, corroborated, and scored.
type Finding struct {
	// ID is a UUID v4 uniquely identifying this finding record.
	ID string `json:"id"`

	// ScanID groups all findings from a single aperture discover invocation.
	ScanID string `json:"scan_id"`

	// AssetID is the canonical identifier for the asset (e.g., "api.target.com", "1.2.3.4").
	AssetID string `json:"asset_id"`

	// AssetType indicates what kind of asset this is.
	AssetType AssetType `json:"asset_type"`

	// ParentAsset is the root domain this asset was discovered under.
	ParentAsset string `json:"parent_asset"`

	// SourcePlugin is the name of the plugin that first discovered this asset.
	SourcePlugin string `json:"source_plugin"`

	// RawConfidence is nil when multiple sources discovered this asset (use per_source_raw_confidence instead).
	RawConfidence *float64 `json:"raw_confidence,omitempty"`

	// PerSourceRawConfidence holds the unadjusted raw confidence score from each discovering source plugin.
	PerSourceRawConfidence map[string]float64 `json:"per_source_raw_confidence,omitempty"`

	// CombinedConfidence is the merged confidence score computed via Noisy-OR after per-source reliability adjustment.
	CombinedConfidence float64 `json:"combined_confidence"`

	// AdjustedConfidence is the unified export score (identical to CombinedConfidence).
	AdjustedConfidence float64 `json:"adjusted_confidence"`

	// EffectiveConfidence is the time-decayed confidence score computed at read/export time.
	EffectiveConfidence float64 `json:"effective_confidence,omitempty"`

	// DecayFactor is the decay multiplier applied based on finding age (0.50–1.00).
	DecayFactor float64 `json:"decay_factor,omitempty"`

	// ConsensusCount is the number of independent source plugins that reported this same asset.
	ConsensusCount int `json:"consensus_count"`

	// TemporalStability is the fraction of temporal resolution attempts that succeeded (0.0–1.0).
	// An asset passes export only if TemporalStability >= configured threshold (default 0.66).
	TemporalStability float64 `json:"temporal_stability"`

	// ResolvedIPs contains the IP addresses returned during temporal consensus resolution.
	ResolvedIPs []string `json:"resolved_ips,omitempty"`

	// Metadata carries source-specific extra data (CNAME chains, TTLs, issuer info, etc.).
	Metadata map[string]any `json:"metadata,omitempty"`

	// Tags are free-form labels applied during discovery (e.g., "dns:verified", "cert:wildcard").
	Tags []string `json:"tags,omitempty"`

	// DiscoveredAt is the UTC timestamp when this finding was first seen in this scan.
	DiscoveredAt time.Time `json:"discovered_at"`
}
