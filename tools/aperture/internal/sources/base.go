package sources

import (
	"context"

	"aperture/internal/model"
)

// SourcePlugin is the contract every discovery source must implement.
// Each plugin is responsible for discovering raw candidates for a given target domain —
// it does not score, filter, or validate. Scoring and validation happen in the pipeline.
type SourcePlugin interface {
	// Name returns the canonical plugin identifier (e.g., "crtsh", "hackertarget").
	// This name is stored in findings and reliability records — must be stable.
	Name() string

	// Category returns how the plugin obtains data.
	Category() model.SourceCategory

	// DefaultPriorReliability returns the initial reliability estimate for this plugin
	// before any empirical data is collected. Most plugins return 0.5 (neutral prior).
	// Plugins with strong track records may return higher; experimental ones lower.
	DefaultPriorReliability() float64

	// Discover emits raw discovery candidates for the given target domain via the returned channel.
	// The channel MUST be closed when discovery is complete or the context is cancelled.
	// Errors are embedded in RawCandidate.Error so they don't break the fan-in pipeline.
	Discover(ctx context.Context, target string) (<-chan RawCandidate, error)
}

// RawCandidate is an unvalidated asset candidate emitted by a source plugin.
// It has not yet gone through reliability adjustment, deduplication, or consensus checks.
type RawCandidate struct {
	// AssetID is the discovered hostname, IP, or record value.
	AssetID string

	// SourcePlugin is the canonical name of the plugin that discovered this candidate.
	SourcePlugin string

	// AssetType classifies the kind of asset.
	AssetType model.AssetType

	// RawScore is the source-assigned confidence before reliability adjustment (0.0–100.0).
	// Sources that always assign 100.0 are fine — reliability adjustment handles the rest.
	RawScore float64

	// Evidence carries source-specific metadata (issuer, TTL, country, etc.).
	Evidence map[string]any

	// Error, if non-nil, signals that this candidate represents a partial failure.
	// The pipeline logs it and continues — one failing asset does not abort the scan.
	Error error
}
