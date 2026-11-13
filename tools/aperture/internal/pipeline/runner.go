package pipeline

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"aperture/internal/consensus"
	"aperture/internal/correlate"
	"aperture/internal/model"
	"aperture/internal/output"
	"aperture/internal/reliability"
	"aperture/internal/sources"
	"aperture/internal/store"
)

// RunConfig holds all runtime parameters for a pipeline execution.
type RunConfig struct {
	Target      string
	ScanID      string
	Plugins     []sources.SourcePlugin
	Consensus   *consensus.Engine
	Reliability *reliability.Engine
	Store       store.Store
	Writer      *output.JSONLWriter
	Concurrency int
}

type aggregatedCandidate struct {
	assetID      string
	assetType    model.AssetType
	sources      []string
	candidates   []sources.RawCandidate
	combinedMeta map[string]any
}

type checkJob struct {
	agg *aggregatedCandidate
	cr  consensus.ConsensusResult
}

// Run executes the full Aperture discovery pipeline:
//
//  1. Fan-out: all plugins discover concurrently, candidates flow into a merged channel.
//  2. Aggregate: group candidates by AssetID, preserving each discovering source plugin and raw score.
//  3. Temporal consensus: each unique asset is individually verified across resolvers with jitter.
//  4. Reliability: per-source Bayesian confidence adjustment, merged via Noisy-OR for multi-source assets.
//  5. Export: passing findings are persisted to store and written to JSONL.
func Run(ctx context.Context, cfg RunConfig) error {
	// Step 1: Fan-out — start all plugins concurrently, merge into one channel.
	merged := fanOut(ctx, cfg.Plugins, cfg.Target)

	// Step 2: Aggregate by unique AssetID, tracking every discovering source.
	assets := make(map[string]*aggregatedCandidate)
	var assetOrder []string

	for cand := range merged {
		if cand.Error != nil || cand.AssetID == "" {
			continue
		}
		agg, exists := assets[cand.AssetID]
		if !exists {
			agg = &aggregatedCandidate{
				assetID:      cand.AssetID,
				assetType:    cand.AssetType,
				combinedMeta: make(map[string]any),
			}
			assets[cand.AssetID] = agg
			assetOrder = append(assetOrder, cand.AssetID)
		}

		hasSource := false
		for _, s := range agg.sources {
			if s == cand.SourcePlugin {
				hasSource = true
				break
			}
		}
		if !hasSource && cand.SourcePlugin != "" {
			agg.sources = append(agg.sources, cand.SourcePlugin)
			agg.candidates = append(agg.candidates, cand)
		}
		for k, v := range cand.Evidence {
			agg.combinedMeta[k] = v
		}
	}

	if len(assetOrder) == 0 {
		log.Info().Msg("no candidates discovered across all sources")
		return nil
	}

	log.Info().Int("unique_assets", len(assetOrder)).Msg("running temporal consensus checks")

	// Step 3: Temporal consensus — concurrent per-asset verification.
	concurrency := cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 20
	}

	jobChan := make(chan *aggregatedCandidate, len(assetOrder))
	resultChan := make(chan checkJob, len(assetOrder))

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for agg := range jobChan {
				if ctx.Err() != nil {
					return
				}
				var cr consensus.ConsensusResult
				if cfg.Consensus != nil {
					cr = cfg.Consensus.Check(ctx, agg.assetID)
				} else {
					cr = consensus.ConsensusResult{
						AssetID:           agg.assetID,
						TemporalStability: 1.0,
						Passes:            true,
					}
				}
				if cr.Passes {
					select {
					case resultChan <- checkJob{agg: agg, cr: cr}:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	for _, id := range assetOrder {
		jobChan <- assets[id]
	}
	close(jobChan)

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Step 4 + 5: Build findings with individual source reliability & Noisy-OR, persist and export.
	for job := range resultChan {
		if ctx.Err() != nil {
			break
		}

		f := FuseFindingsForAsset(
			ctx,
			job.agg.assetID,
			job.agg.assetType,
			cfg.Target,
			job.agg.candidates,
			cfg.Reliability,
			job.cr,
			cfg.ScanID,
			job.agg.combinedMeta,
		)

		if cfg.Store != nil {
			if err := cfg.Store.UpsertFinding(ctx, f); err != nil {
				log.Warn().Err(err).Str("asset_id", f.AssetID).Msg("failed to persist finding")
			}

			// Extract and persist infrastructure fingerprint
			correlator := correlate.NewEngine(cfg.Store)
			fp := correlator.ExtractFingerprint(f)
			if err := cfg.Store.SaveFingerprint(ctx, fp); err != nil {
				log.Warn().Err(err).Str("asset_id", f.AssetID).Msg("failed to persist fingerprint")
			}
		}

		if cfg.Writer != nil {
			if err := cfg.Writer.Write(f); err != nil {
				log.Warn().Err(err).Str("asset_id", f.AssetID).Msg("failed to write finding to JSONL")
			}
		}

		log.Info().
			Str("asset", f.AssetID).
			Str("source", f.SourcePlugin).
			Int("consensus", f.ConsensusCount).
			Float64("stability", f.TemporalStability).
			Float64("adj_confidence", f.AdjustedConfidence).
			Float64("effective_conf", f.EffectiveConfidence).
			Msg("finding")
	}

	// Step 6: Automatically run cross-target correlation against stored infrastructure
	if cfg.Store != nil {
		correlator := correlate.NewEngine(cfg.Store)
		corrs, err := correlator.Correlate(ctx, cfg.Target)
		if err != nil {
			log.Warn().Err(err).Msg("cross-target correlation error")
		} else if len(corrs) > 0 {
			log.Info().Int("correlations_found", len(corrs)).Msg("cross-target infrastructure correlations detected")
			for _, c := range corrs {
				log.Info().
					Str("type", c.CorrelationType).
					Str("domain_a", c.RootDomainA).
					Str("domain_b", c.RootDomainB).
					Str("shared", c.SharedElement).
					Float64("confidence", c.Confidence).
					Msg("cross-target correlation")
			}
		}
	}

	return nil
}

// FuseFindingsForAsset performs the canonical Reliability-then-Fuse calculation:
//
// Step 1 (per source i individually):
//
//	adjusted_i = raw_i × ReliabilityScore(source_i, domain_pattern)
//
// Step 2 (fuse adjusted scores via Noisy-OR, NOT the raw scores):
//
//	combined_confidence = 100 × (1 - Π(1 - adjusted_i/100))
//
// Why this order: A source with reliability=0.9 and one with reliability=0.3
// should not have equal weight in the distribution shape. Adjusting before
// fusion guarantees that a historically less reliable source has a genuinely
// lighter influence on the final result, perfectly fulfilling the cumulative
// learnable trust principle of Aperture.
func FuseFindingsForAsset(
	ctx context.Context,
	assetID string,
	assetType model.AssetType,
	parentAsset string,
	candidates []sources.RawCandidate,
	relEngine *reliability.Engine,
	cr consensus.ConsensusResult,
	scanID string,
	combinedMeta map[string]any,
) *model.Finding {
	var adjustedScores []float64
	perSourceRaw := make(map[string]float64)
	sourceNames := make([]string, 0, len(candidates))
	pattern := reliability.DomainPattern(assetID)

	var rawConfidencePtr *float64
	if len(candidates) == 1 {
		raw := candidates[0].RawScore
		if raw <= 0 {
			raw = 70.0
		}
		rawConfidencePtr = &raw
	}

	for _, c := range candidates {
		raw := c.RawScore
		if raw <= 0 {
			raw = 70.0
		}
		perSourceRaw[c.SourcePlugin] = raw
		sourceNames = append(sourceNames, c.SourcePlugin)

		adjusted := raw
		if relEngine != nil {
			_ = relEngine.RecordFinding(ctx, c.SourcePlugin, pattern)
			adj, err := relEngine.AdjustedConfidence(ctx, c.SourcePlugin, pattern, raw)
			if err == nil {
				adjusted = adj
			}
		}
		adjustedScores = append(adjustedScores, adjusted)
	}

	combined := NoisyOR(adjustedScores)
	sort.Strings(sourceNames)

	now := time.Now().UTC()
	effConf, decayFactor := model.CalculateEffectiveConfidence(combined, now, nil, now)

	return &model.Finding{
		ID:                     uuid.NewString(),
		ScanID:                 scanID,
		AssetID:                assetID,
		AssetType:              assetType,
		ParentAsset:            parentAsset,
		SourcePlugin:           strings.Join(sourceNames, ","),
		RawConfidence:          rawConfidencePtr,
		PerSourceRawConfidence: perSourceRaw,
		CombinedConfidence:     combined,
		AdjustedConfidence:     combined,
		EffectiveConfidence:    effConf,
		DecayFactor:            decayFactor,
		ConsensusCount:         len(candidates),
		TemporalStability:      cr.TemporalStability,
		ResolvedIPs:            cr.ResolvedIPs,
		Metadata:               combinedMeta,
		Tags:                   []string{},
		DiscoveredAt:           now,
	}
}

// NoisyOR combines multiple confidence probabilities using standard Noisy-OR.
// Formula: 100 * (1 - product(1 - p_i)), where p_i = score_i / 100.
func NoisyOR(scores []float64) float64 {
	if len(scores) == 0 {
		return 0
	}
	if len(scores) == 1 {
		return scores[0]
	}
	product := 1.0
	for _, s := range scores {
		p := s / 100.0
		if p < 0 {
			p = 0
		} else if p > 0.99 {
			p = 0.99
		}
		product *= (1.0 - p)
	}
	combined := 100.0 * (1.0 - product)
	if combined > 100.0 {
		combined = 100.0
	}
	return combined
}

// fanOut launches all plugins concurrently and merges their candidate channels into one.
func fanOut(ctx context.Context, plugins []sources.SourcePlugin, target string) <-chan sources.RawCandidate {
	merged := make(chan sources.RawCandidate, 512)
	var wg sync.WaitGroup

	for _, plugin := range plugins {
		p := plugin
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch, err := p.Discover(ctx, target)
			if err != nil {
				log.Error().Err(err).Str("plugin", p.Name()).Msg("plugin discover error")
				return
			}
			for cand := range ch {
				if cand.Error != nil {
					log.Warn().Err(cand.Error).Str("plugin", p.Name()).Msg("plugin candidate error")
					continue
				}
				if cand.SourcePlugin == "" {
					cand.SourcePlugin = p.Name()
				}
				select {
				case merged <- cand:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(merged)
	}()

	return merged
}
