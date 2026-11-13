package model

import "time"

// SourceReliabilityRecord tracks the observed accuracy of a single source plugin,
// optionally scoped to a TLD pattern (e.g., ".com", ".io").
//
// The ReliabilityScore is updated via Bayesian Beta-Binomial inference, not a simple
// moving average, so it degrades gracefully on small sample sizes and converges
// accurately at scale — see reliability.Engine for the formula.
type SourceReliabilityRecord struct {
	// SourcePlugin is the name of the plugin (e.g., "crtsh").
	SourcePlugin string `json:"source_plugin"`

	// TargetDomainPattern is the TLD or broad pattern this record applies to
	// (e.g., ".com", ".io", "*" for global). This allows per-TLD accuracy tracking
	// because some sources are more reliable on certain TLDs than others.
	TargetDomainPattern string `json:"target_domain_pattern"`

	// TotalFindings is the total number of assets reported by this source for this pattern.
	TotalFindings int64 `json:"total_findings"`

	// ConfirmedLive is the number of assets that were verified alive in a subsequent probe.
	ConfirmedLive int64 `json:"confirmed_live"`

	// ConfirmedDead is the number of assets that were probed and found dead/non-resolving.
	ConfirmedDead int64 `json:"confirmed_dead"`

	// ReliabilityScore is the current Bayesian estimate of this source's accuracy (0.0–1.0).
	// Formula: (α + confirmed_live) / (α + β + total_observed)
	// where α=2 (optimistic prior) and β=1 (slight skepticism prior).
	ReliabilityScore float64 `json:"reliability_score"`

	// SampleSize is confirmed_live + confirmed_dead — used to weight how much we trust the score.
	SampleSize int64 `json:"sample_size"`

	// LastUpdated is the time this record was last recalculated.
	LastUpdated time.Time `json:"last_updated"`
}

// Bayesian prior constants — these are the only "magic numbers" in the reliability system.
// α=2 starts each source with moderate optimism (avoids 0/0 edge case and reflects
// that most OSINT sources do find real assets most of the time).
// β=1 adds slight skepticism so a source doesn't reach reliability=1.0 instantly.
const (
	BayesAlpha = 2.0
	BayesBeta  = 1.0
)

// ComputeReliabilityScore recalculates the Bayesian Beta-Binomial reliability score
// from raw observation counts. This is the canonical formula used everywhere in the engine.
func ComputeReliabilityScore(confirmedLive, totalObserved int64) float64 {
	if totalObserved <= 0 {
		// No observations yet: return the prior mean = α / (α + β)
		return BayesAlpha / (BayesAlpha + BayesBeta)
	}
	return (BayesAlpha + float64(confirmedLive)) / (BayesAlpha + BayesBeta + float64(totalObserved))
}
