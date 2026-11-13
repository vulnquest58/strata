package reliability

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"aperture/internal/model"
	"aperture/internal/store"
)

// Engine manages source reliability scoring using Bayesian Beta-Binomial inference.
// It is the only component in Aperture that has write access to source_reliability records.
type Engine struct {
	store  store.Store
	priors map[string]float64
}

// NewEngine creates a new reliability engine backed by the given store.
func NewEngine(s store.Store) *Engine {
	return &Engine{
		store:  s,
		priors: make(map[string]float64),
	}
}

// RegisterPrior registers the default prior reliability for a plugin.
func (e *Engine) RegisterPrior(pluginName string, prior float64) {
	if prior > 0 && prior <= 1.0 {
		e.priors[pluginName] = prior
		if e.store != nil {
			ctx := context.Background()
			rec, err := e.store.GetReliability(ctx, pluginName, "*")
			if err == nil && rec.SampleSize == 0 {
				rec.ReliabilityScore = prior
				rec.LastUpdated = time.Now().UTC()
				_ = e.store.SaveReliability(ctx, rec)
			}
		}
	}
}

// AdjustedConfidence returns the adjusted confidence for a finding by multiplying
// the raw score by the current reliability of its source plugin.
func (e *Engine) AdjustedConfidence(ctx context.Context, sourcePlugin, domainPattern string, rawConfidence float64) (float64, error) {
	rec, err := e.store.GetReliability(ctx, sourcePlugin, domainPattern)
	if err != nil {
		return rawConfidence, fmt.Errorf("reliability.AdjustedConfidence: %w", err)
	}
	score := rec.ReliabilityScore
	if rec.SampleSize == 0 {
		if p, ok := e.priors[sourcePlugin]; ok && p > 0 {
			score = p
		}
	}
	return rawConfidence * score, nil
}

// RecordFinding increments the total_findings counter for the (source, pattern) pair.
// Called once per finding ingested from a source, before any verification.
func (e *Engine) RecordFinding(ctx context.Context, sourcePlugin, domainPattern string) error {
	rec, err := e.store.GetReliability(ctx, sourcePlugin, domainPattern)
	if err != nil {
		return err
	}
	rec.TotalFindings++
	if rec.SampleSize > 0 {
		rec.ReliabilityScore = model.ComputeReliabilityScore(rec.ConfirmedLive, rec.SampleSize)
	} else if p, ok := e.priors[sourcePlugin]; ok && p > 0 {
		rec.ReliabilityScore = p
	}
	rec.LastUpdated = time.Now().UTC()
	return e.store.SaveReliability(ctx, rec)
}

// RecordOutcome records whether a previously reported finding was verified alive or dead.
// This is the core update step that makes reliability scores improve over time.
func (e *Engine) RecordOutcome(ctx context.Context, sourcePlugin, domainPattern string, live bool) error {
	rec, err := e.store.GetReliability(ctx, sourcePlugin, domainPattern)
	if err != nil {
		return err
	}
	if live {
		rec.ConfirmedLive++
	} else {
		rec.ConfirmedDead++
	}
	rec.SampleSize = rec.ConfirmedLive + rec.ConfirmedDead
	rec.ReliabilityScore = model.ComputeReliabilityScore(rec.ConfirmedLive, rec.SampleSize)
	rec.LastUpdated = time.Now().UTC()
	return e.store.SaveReliability(ctx, rec)
}

// DomainPattern extracts the TLD pattern for reliability bucketing.
// e.g., "api.example.com" → ".com"
//
//	"app.target.io"  → ".io"
//	""               → "*"
func DomainPattern(assetID string) string {
	parts := strings.Split(assetID, ".")
	if len(parts) < 2 {
		return "*"
	}
	return "." + parts[len(parts)-1]
}

// -------------------------------------------------------------------
// Verifier — async background job
// -------------------------------------------------------------------

// Verifier samples unverified findings for a given source and probes their liveness
// via a simple HTTP HEAD request, then updates the reliability record accordingly.
type Verifier struct {
	engine     *Engine
	store      store.Store
	httpClient *http.Client
}

// NewVerifier creates a Verifier.
func NewVerifier(e *Engine, s store.Store, timeoutSecs int) *Verifier {
	return &Verifier{
		engine: e,
		store:  s,
		httpClient: &http.Client{
			Timeout: time.Duration(timeoutSecs) * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
	}
}

// VerificationResult records what happened to a verified finding.
type VerificationResult struct {
	FindingID    string
	AssetID      string
	SourcePlugin string
	Live         bool
}

// Run executes a verification pass for the given source plugin.
// It samples sampleRate fraction of unverified findings older than olderThan, probes each,
// and records the outcome.
func (v *Verifier) Run(ctx context.Context, sourcePlugin string, sampleRate float64, olderThan time.Duration) ([]VerificationResult, error) {
	findings, err := v.store.SampleUnverifiedFindings(ctx, sourcePlugin, sampleRate, olderThan)
	if err != nil {
		return nil, fmt.Errorf("sampling unverified findings: %w", err)
	}

	var results []VerificationResult
	for _, f := range findings {
		if ctx.Err() != nil {
			break
		}

		live := v.probeLiveness(ctx, f.AssetID)
		pattern := DomainPattern(f.AssetID)

		// Update the finding's verification status.
		_ = v.store.MarkFindingVerified(ctx, f.ID, live)

		// Update the source's reliability record.
		_ = v.engine.RecordOutcome(ctx, f.SourcePlugin, pattern, live)

		results = append(results, VerificationResult{
			FindingID:    f.ID,
			AssetID:      f.AssetID,
			SourcePlugin: f.SourcePlugin,
			Live:         live,
		})
	}
	return results, nil
}

// probeLiveness attempts DNS resolution and HTTP/HTTPS probe.
// Returns true if DNS resolves to a valid public IP or any HTTP response is received.
func (v *Verifier) probeLiveness(ctx context.Context, assetID string) bool {
	// 1. DNS check
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", assetID)
	if err == nil && len(ips) > 0 {
		for _, ip := range ips {
			if !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() {
				return true
			}
		}
	}

	// 2. HTTP/HTTPS probe fallback
	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s", scheme, assetID)
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Aperture/1.0 (liveness-check)")

		resp, err := v.httpClient.Do(req)
		if err == nil {
			resp.Body.Close()
			return true // any HTTP response = host is alive
		}
	}
	return false
}
