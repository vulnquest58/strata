package miner

import (
	"strings"
)

// EchoEvolver implements the Echo Evolution pipeline (Layer 3).
// For each confirmed subdomain, it generates intelligent "echo" candidates
// by combining Markov generation, n-gram analysis, and industry context injection.
type EchoEvolver struct {
	domain   string
	markov   *MarkovChain
	ngram    *NGramExtractor
	industry *IndustryProfile
	maxDepth int
	freqMap  map[string]int // N-gram frequency map for quality gating
}

// NewEchoEvolver creates an evolver ready to generate candidates from confirmed seeds.
func NewEchoEvolver(domain string, markov *MarkovChain, ngram *NGramExtractor,
	industry *IndustryProfile, maxDepth int, freqMap map[string]int) *EchoEvolver {
	return &EchoEvolver{
		domain:   domain,
		markov:   markov,
		ngram:    ngram,
		industry: industry,
		maxDepth: maxDepth,
		freqMap:  freqMap,
	}
}

// isHighFreq returns true if a token appears in the top patterns with frequency ≥ minFreq.
func (e *EchoEvolver) isHighFreq(token string, minFreq int) bool {
	if e.freqMap == nil {
		return true
	}
	return e.freqMap[token] >= minFreq
}

// skipPrefix returns true for tokens that should NOT be used to generate echoes.
// This prevents generating thousands of meaningless www.* candidates.
func skipPrefix(token string) bool {
	skip := map[string]bool{
		"www": true, "m": true, "t": true, "f": true, "e": true,
		"i": true, "r": true, "s": true, "n": true,
	}
	// Skip very short tokens (single chars) or common noise
	if len(token) <= 1 {
		return true
	}
	return skip[token]
}

// GenerateEchoes produces intelligent candidates derived from a confirmed subdomain.
// Key improvements over v1:
//   - Skips www., m., single-char tokens as generation seeds
//   - Only expands tokens with high n-gram frequency (quality gating)
//   - Industry keyword injection uses confirmed patterns only
func (e *EchoEvolver) GenerateEchoes(confirmedSubdomain string, currentDepth int) []string {
	if currentDepth >= e.maxDepth {
		return nil
	}

	tokens := tokenize(confirmedSubdomain)
	if len(tokens) == 0 {
		return nil
	}

	// Filter to meaningful tokens only
	qualityTokens := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		if !skipPrefix(tok) && len(tok) >= 2 {
			qualityTokens = append(qualityTokens, tok)
		}
	}
	if len(qualityTokens) == 0 {
		return nil
	}

	// Compute min frequency threshold: use tokens appearing ≥2 times
	minFreq := 1
	if currentDepth == 0 {
		minFreq = 2 // stricter at root level
	}

	seen := make(map[string]bool)
	var echoes []string

	add := func(candidate string) {
		candidate = strings.ToLower(strings.TrimSpace(candidate))
		if candidate == "" || seen[candidate] {
			return
		}
		// Must be a subdomain of target domain
		if !strings.HasSuffix(candidate, "."+e.domain) {
			return
		}
		// Reject www.* candidates — they're almost always noise
		prefix := strings.TrimSuffix(candidate, "."+e.domain)
		if strings.HasPrefix(prefix, "www.") || strings.HasPrefix(prefix, "m.") {
			return
		}
		seen[candidate] = true
		echoes = append(echoes, candidate)
	}

	// ── Method 1: Markov generation — only from high-freq tokens ──────────
	if e.markov.IsTrained() {
		for _, tok := range qualityTokens {
			if !e.isHighFreq(tok, minFreq) {
				continue
			}
			candidates := e.markov.GenerateFromToken(tok, e.domain, 3, 4)
			for _, c := range candidates {
				add(c)
			}
		}
		// Seed-based Markov from ordered tokens
		if len(tokens) >= e.markov.order {
			seed := tokens[:e.markov.order]
			for i := 0; i < 3; i++ {
				add(e.markov.Generate(seed, e.domain, 4))
			}
		}
	}

	// ── Method 2: Targeted prefix/suffix on quality tokens only ───────────
	// Pruned prefixes — no www, m, single-chars
	prefixes := []string{
		"api", "dev", "staging", "prod", "internal", "admin",
		"secure", "vpn", "cdn", "app", "web", "portal", "mail",
		"gateway", "auth", "backend", "test",
	}
	suffixes := []string{
		"v2", "v3", "eu", "us", "ap", "beta", "new", "prod", "dev", "int",
	}

	for _, tok := range qualityTokens {
		// Only expand high-frequency tokens at depth 0
		if currentDepth == 0 && !e.isHighFreq(tok, minFreq) {
			continue
		}
		for _, pre := range prefixes {
			if pre != tok { // avoid "api-api.domain.com"
				add(pre + "-" + tok + "." + e.domain)
			}
		}
		for _, suf := range suffixes {
			add(tok + "-" + suf + "." + e.domain)
		}
	}

	// ── Method 3: Industry keyword injection (only on quality tokens) ──────
	if e.industry != nil {
		for _, kw := range e.industry.Prefixes {
			for _, tok := range qualityTokens {
				if kw != tok {
					add(kw + "-" + tok + "." + e.domain)
					add(tok + "-" + kw + "." + e.domain)
				}
			}
		}
		for _, kw := range e.industry.Suffixes {
			for _, tok := range qualityTokens {
				add(tok + "-" + kw + "." + e.domain)
			}
		}
	}

	// ── Method 4: Environment + region combos (on quality tokens only) ────
	envs := []string{"prod", "staging", "dev", "qa", "uat", "sandbox"}
	regions := []string{"eu", "us", "ap", "us-east", "eu-west"}

	for _, tok := range qualityTokens {
		if !e.isHighFreq(tok, minFreq) {
			continue
		}
		for _, env := range envs {
			add(tok + "-" + env + "." + e.domain)
		}
		for _, reg := range regions {
			add(tok + "-" + reg + "." + e.domain)
		}
	}

	// Limit echoes per seed to avoid combinatorial explosion
	maxEchoes := 20
	if currentDepth > 0 {
		maxEchoes = 10
	}
	if len(echoes) > maxEchoes {
		return echoes[:maxEchoes]
	}
	return echoes
}

// RunEvolution executes the full echo evolution loop.
// It starts with confirmed seeds and iterates until maxDepth or saturation.
// Returns all generated candidates for resolution.
func RunEvolution(
	domain string,
	seeds []string,
	markov *MarkovChain,
	ngram *NGramExtractor,
	industry *IndustryProfile,
	maxDepth int,
	freqMap map[string]int,
) []string {
	evolver := NewEchoEvolver(domain, markov, ngram, industry, maxDepth, freqMap)
	seen := make(map[string]bool)
	var allCandidates []string

	queue := make([]struct {
		sub   string
		depth int
	}, 0, len(seeds))

	for _, s := range seeds {
		if !seen[s] {
			seen[s] = true
			queue = append(queue, struct {
				sub   string
				depth int
			}{s, 0})
		}
	}

	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		echoes := evolver.GenerateEchoes(item.sub, item.depth)
		for _, echo := range echoes {
			if !seen[echo] {
				seen[echo] = true
				allCandidates = append(allCandidates, echo)
				// New echoes become seeds for next depth level
				if item.depth+1 < maxDepth {
					queue = append(queue, struct {
						sub   string
						depth int
					}{echo, item.depth + 1})
				}
			}
		}
	}

	return allCandidates
}
