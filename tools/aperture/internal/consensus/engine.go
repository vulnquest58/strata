package consensus

import (
	"context"
	"math/rand"
	"net"
	"sort"
	"sync"
	"time"

	"aperture/internal/resolver"
	"aperture/internal/sources"
)

// ConsensusResult is the outcome of a 3-attempt temporal consensus check.
type ConsensusResult struct {
	// AssetID is the hostname that was checked.
	AssetID string

	// Attempts contains the individual resolution results (up to 3).
	Attempts []resolver.Result

	// TemporalStability is successes / len(Attempts). Range: 0.0–1.0.
	TemporalStability float64

	// ResolvedIPs is the union of all IPs returned across successful attempts.
	ResolvedIPs []string

	// Passes is true when TemporalStability >= the configured threshold.
	Passes bool
}

// Engine performs temporal consensus resolution: 3 attempts using different resolver
// backends (DoH/Cloudflare, DoH/Google, raw UDP), each separated by a random jitter
// delay. An asset passes only if at least 2 of 3 attempts succeed (stability ≥ 0.66).
//
// The deliberate use of both DoH and raw UDP provides protocol diversity —
// a geo-routing artefact or CDN quirk that affects DoH differently from UDP
// will reveal itself as reduced TemporalStability rather than a silent false-negative.
type Engine struct {
	resolvers []resolver.Resolver // exactly 3: DoH-CF, DoH-Google, raw UDP
	minJitter time.Duration
	maxJitter time.Duration
	threshold float64
}

// NewEngine creates a ConsensusEngine.
// resolvers should contain exactly 3 Resolver instances in the following recommended order:
//
//	[0] DoH (Cloudflare)
//	[1] DoH (Google)
//	[2] Raw UDP (8.8.8.8 or similar)
//
// minJitter and maxJitter define the inter-attempt sleep range.
// threshold is the minimum TemporalStability to pass (e.g., 0.66).
func NewEngine(resolvers []resolver.Resolver, minJitter, maxJitter time.Duration, threshold float64) *Engine {
	if len(resolvers) == 0 {
		panic("consensus.NewEngine: resolvers must not be empty")
	}
	return &Engine{
		resolvers: resolvers,
		minJitter: minJitter,
		maxJitter: maxJitter,
		threshold: threshold,
	}
}

// Check performs the 3-attempt temporal consensus check for a single hostname.
func (e *Engine) Check(ctx context.Context, hostname string) ConsensusResult {
	return e.check(ctx, hostname)
}

// CheckMany runs consensus checks for all candidates in the input channel and returns
// a channel of ConsensusResults, emitting only those that pass the stability threshold.
//
// This function blocks internally (it waits for all attempts with jitter), so it must
// be run inside a goroutine by the caller if non-blocking behaviour is required.
func (e *Engine) CheckMany(ctx context.Context, candidates <-chan sources.RawCandidate, concurrency int) <-chan ConsensusResult {
	out := make(chan ConsensusResult, 64)

	go func() {
		defer close(out)

		sem := make(chan struct{}, concurrency)
		var wg sync.WaitGroup

		for cand := range candidates {
			if cand.Error != nil || cand.AssetID == "" {
				continue
			}

			assetID := cand.AssetID
			wg.Add(1)
			sem <- struct{}{}

			go func(id string) {
				defer wg.Done()
				defer func() { <-sem }()

				cr := e.check(ctx, id)
				if cr.Passes {
					select {
					case out <- cr:
					case <-ctx.Done():
					}
				}
			}(assetID)
		}

		wg.Wait()
	}()

	return out
}

// isLiveIP checks whether an IP is globally routable and live (not 0.0.0.0, loopback, or private).
func isLiveIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	return true
}

// check performs the 3-attempt temporal consensus check for a single hostname.
func (e *Engine) check(ctx context.Context, hostname string) ConsensusResult {
	cr := ConsensusResult{AssetID: hostname}
	ipSet := make(map[string]bool)

	for i, res := range e.resolvers {
		// Apply inter-attempt jitter (skipped for the first attempt).
		if i > 0 && e.maxJitter > e.minJitter {
			jitter := e.minJitter + time.Duration(rand.Int63n(int64(e.maxJitter-e.minJitter)))
			select {
			case <-ctx.Done():
				// Context cancelled mid-check — compute partial stability.
				cr.TemporalStability = float64(successCount(cr.Attempts)) / float64(len(e.resolvers))
				cr.Passes = cr.TemporalStability >= e.threshold
				cr.ResolvedIPs = mapKeys(ipSet)
				return cr
			case <-time.After(jitter):
			}
		}

		result := res.Resolve(ctx, hostname)
		var liveIPs []string
		for _, ipStr := range result.IPs {
			parsed := net.ParseIP(ipStr)
			if isLiveIP(parsed) {
				liveIPs = append(liveIPs, ipStr)
				ipSet[ipStr] = true
			}
		}
		result.IPs = liveIPs
		result.Resolves = len(liveIPs) > 0
		cr.Attempts = append(cr.Attempts, result)
	}

	successes := successCount(cr.Attempts)
	cr.TemporalStability = float64(successes) / float64(len(e.resolvers))
	cr.Passes = cr.TemporalStability >= e.threshold
	cr.ResolvedIPs = mapKeys(ipSet)
	return cr
}

// successCount returns the number of attempts that resolved successfully.
func successCount(attempts []resolver.Result) int {
	n := 0
	for _, a := range attempts {
		if a.Resolves {
			n++
		}
	}
	return n
}

// mapKeys returns the keys of a map[string]bool as a sorted slice.
func mapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
