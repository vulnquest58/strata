package resolver

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/echoforge/echoforge/internal/utils"
)

// ResolutionResult holds the result of resolving a single hostname.
type ResolutionResult struct {
	Hostname    string
	IPAddresses []string
	Resolves    bool
	// AgreementCount: how many independent resolvers confirmed the result
	AgreementCount int
	// Wildcard: true if this result matches a wildcard record
	Wildcard bool
}

// Pool manages a pool of DoH resolvers with rotation, jitter, and rate limiting.
type Pool struct {
	providers   []DoHProvider
	client      *DoHClient
	jitter      *utils.Jitter
	stealth     bool
	mu          sync.Mutex
	roundRobin  uint64
}

// NewPool creates a new resolver pool.
func NewPool(timeoutSecs int, stealth bool) *Pool {
	baseMsec := 200
	if stealth {
		baseMsec = 500
	}
	return &Pool{
		providers: BuiltInProviders,
		client:    NewDoHClient(timeoutSecs),
		jitter:    utils.NewJitter(baseMsec, 0.5, stealth),
		stealth:   stealth,
	}
}

// nextProvider returns the next provider using round-robin selection.
func (p *Pool) nextProvider() DoHProvider {
	idx := atomic.AddUint64(&p.roundRobin, 1)
	return p.providers[int(idx)%len(p.providers)]
}

// randomProvider returns a random provider from the pool.
func (p *Pool) randomProvider() DoHProvider {
	return p.providers[rand.Intn(len(p.providers))]
}

// Resolve resolves a hostname using a randomly selected DoH provider.
// In stealth mode, it sleeps before each request.
func (p *Pool) Resolve(ctx context.Context, hostname string) ResolutionResult {
	if p.stealth {
		p.jitter.Sleep()
	}

	provider := p.randomProvider()
	ips, resolves := p.client.Resolve(ctx, provider, hostname)

	result := ResolutionResult{
		Hostname:       hostname,
		IPAddresses:    ips,
		Resolves:       resolves,
		AgreementCount: 0,
	}

	if resolves {
		result.AgreementCount = 1
		// In non-stealth mode, do a quick cross-check with a second resolver
		if !p.stealth {
			provider2 := p.randomProvider()
			_, resolves2 := p.client.Resolve(ctx, provider2, hostname)
			if resolves2 {
				result.AgreementCount = 2
			}
		}
	}

	return result
}

// DetectWildcard probes 3 random non-existent subdomains to detect wildcard DNS.
// Returns the set of wildcard IPs if a wildcard is found, or nil if not.
func (p *Pool) DetectWildcard(ctx context.Context, domain string) map[string]bool {
	wildcardIPs := make(map[string]bool)
	hits := 0

	for i := 0; i < 3; i++ {
		// Generate a random subdomain guaranteed not to exist
		probe := fmt.Sprintf("echoforge-wc-probe-%d-%d.%s", rand.Int63n(9999999), i, domain)
		result := p.Resolve(ctx, probe)
		if result.Resolves {
			hits++
			for _, ip := range result.IPAddresses {
				wildcardIPs[ip] = true
			}
		}
	}

	// If at least 2 of 3 probes resolved, wildcard is confirmed
	if hits >= 2 && len(wildcardIPs) > 0 {
		return wildcardIPs
	}
	return nil
}

// FilterWildcard marks ResolutionResults that resolve to wildcard IPs.
func FilterWildcard(results []ResolutionResult, wildcardIPs map[string]bool) []ResolutionResult {
	if wildcardIPs == nil {
		return results
	}
	filtered := make([]ResolutionResult, 0, len(results))
	for _, r := range results {
		if r.Resolves {
			isWildcard := false
			for _, ip := range r.IPAddresses {
				if wildcardIPs[ip] {
					isWildcard = true
					break
				}
			}
			if isWildcard {
				r.Resolves = false
				r.Wildcard = true
				r.IPAddresses = nil
			}
		}
		filtered = append(filtered, r)
	}
	return filtered
}

// ResolveMany resolves multiple hostnames concurrently using a worker pool.
func (p *Pool) ResolveMany(ctx context.Context, hostnames []string, concurrency int) []ResolutionResult {
	results := make([]ResolutionResult, 0, len(hostnames))
	mu := &sync.Mutex{}
	sem := make(chan struct{}, concurrency)
	wg := &sync.WaitGroup{}

	for _, h := range hostnames {
		select {
		case <-ctx.Done():
			break
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()

			// Small per-goroutine jitter to spread load
			time.Sleep(time.Duration(rand.Intn(100)) * time.Millisecond)

			r := p.Resolve(ctx, host)
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		}(h)
	}

	wg.Wait()
	return results
}
