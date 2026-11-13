package store

import (
	"context"
	"time"

	"aperture/internal/model"
)

// Store defines the persistence contract for Aperture.
// The interface is intentionally narrow — only operations actually needed by the engine.
type Store interface {
	// --- Findings ---

	// UpsertFinding saves or updates a Finding. If a finding with the same
	// (scan_id, asset_id, source_plugin) already exists, it is updated.
	UpsertFinding(ctx context.Context, f *model.Finding) error

	// GetFindingsByScanID returns all findings recorded under a given scan.
	GetFindingsByScanID(ctx context.Context, scanID string) ([]*model.Finding, error)

	// IncrementConsensusCount atomically increments the consensus_count for
	// the finding identified by (scan_id, asset_id). Used when a second source
	// confirms the same asset.
	IncrementConsensusCount(ctx context.Context, scanID, assetID string) error

	// --- Source Reliability ---

	// GetReliability returns the reliability record for (source, domainPattern).
	// If no record exists yet, it returns a new record initialised with the Bayesian prior.
	GetReliability(ctx context.Context, source, domainPattern string) (*model.SourceReliabilityRecord, error)

	// SaveReliability upserts a reliability record (insert or replace).
	SaveReliability(ctx context.Context, r *model.SourceReliabilityRecord) error

	// ListReliability returns all reliability records for a given source plugin.
	ListReliability(ctx context.Context, source string) ([]*model.SourceReliabilityRecord, error)

	// --- Verification Sampling ---

	// SampleUnverifiedFindings returns a random sample of findings from the given source
	// whose outcomes have not yet been verified and were discovered at least olderThan ago.
	// If source is empty, samples across all sources. sampleRate is a fraction in (0, 1].
	SampleUnverifiedFindings(ctx context.Context, source string, sampleRate float64, olderThan time.Duration) ([]*model.Finding, error)

	// MarkFindingVerified records that a finding has been probed and whether it was live.
	MarkFindingVerified(ctx context.Context, findingID string, live bool) error

	// --- Infrastructure Fingerprints ---

	// SaveFingerprint upserts an InfrastructureFingerprint record.
	SaveFingerprint(ctx context.Context, fp *model.InfrastructureFingerprint) error

	// GetFingerprints returns all fingerprints, optionally filtered by root domain.
	GetFingerprints(ctx context.Context, rootDomain string) ([]*model.InfrastructureFingerprint, error)

	// --- Cross-Target Correlations ---

	// SaveCorrelation upserts a CrossTargetCorrelation record.
	SaveCorrelation(ctx context.Context, c *model.CrossTargetCorrelation) error

	// ListCorrelations returns all correlations, optionally filtered by root domain.
	ListCorrelations(ctx context.Context, rootDomain string) ([]*model.CrossTargetCorrelation, error)

	// --- Lifecycle ---

	// Close releases all resources held by the store.
	Close() error
}
