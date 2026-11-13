package miner

import (
	"strings"
	"unicode"
)

// NGramExtractor analyses subdomain names to extract meaningful token n-grams.
type NGramExtractor struct {
	MaxN int
}

// NewNGramExtractor creates an extractor with a maximum n-gram order.
func NewNGramExtractor(maxN int) *NGramExtractor {
	if maxN < 1 {
		maxN = 3
	}
	return &NGramExtractor{MaxN: maxN}
}

// tokenize splits a subdomain name into lowercase tokens on common delimiters.
// Example: "api-staging-v2.example.com" → ["api", "staging", "v2"]
func tokenize(name string) []string {
	// Strip the root domain part if present (everything after first dot in FQDN)
	if idx := strings.Index(name, "."); idx != -1 {
		name = name[:idx]
	}

	// Split on hyphens and other separators, keeping meaningful tokens
	parts := strings.FieldsFunc(name, func(r rune) bool {
		return r == '-' || r == '_' || r == '.' || unicode.IsSpace(r)
	})

	var tokens []string
	for _, p := range parts {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" && len(p) >= 2 {
			tokens = append(tokens, p)
		}
	}
	return tokens
}

// ExtractFrequency builds a frequency map of n-grams (1 to MaxN) from a list of subdomains.
// Returns a map from gram string to occurrence count.
func (e *NGramExtractor) ExtractFrequency(subdomains []string) map[string]int {
	freq := make(map[string]int)

	for _, sub := range subdomains {
		tokens := tokenize(sub)
		for n := 1; n <= e.MaxN; n++ {
			for i := 0; i+n <= len(tokens); i++ {
				gram := strings.Join(tokens[i:i+n], "-")
				freq[gram]++
			}
		}
	}
	return freq
}

// TopN returns the top-n most frequent grams from a frequency map.
func TopN(freq map[string]int, n int) []string {
	type kv struct {
		key   string
		count int
	}
	pairs := make([]kv, 0, len(freq))
	for k, v := range freq {
		pairs = append(pairs, kv{k, v})
	}
	// Simple insertion sort (n is usually small, 10-50)
	for i := 1; i < len(pairs); i++ {
		for j := i; j > 0 && pairs[j].count > pairs[j-1].count; j-- {
			pairs[j], pairs[j-1] = pairs[j-1], pairs[j]
		}
	}
	result := make([]string, 0, n)
	for i := 0; i < n && i < len(pairs); i++ {
		result = append(result, pairs[i].key)
	}
	return result
}

// GenerateCombinations produces permutations from top n-grams combined with
// common prefixes and suffixes from the frequency table.
func GenerateCombinations(domain string, topGrams []string, industry []string) []string {
	seen := make(map[string]bool)
	var results []string

	add := func(parts ...string) {
		candidate := strings.Join(parts, "-") + "." + domain
		if !seen[candidate] {
			seen[candidate] = true
			results = append(results, candidate)
		}
	}

	// Single gram candidates
	for _, g := range topGrams {
		add(g)
	}

	// Cross-product: gram × gram
	for i, g1 := range topGrams {
		for j, g2 := range topGrams {
			if i == j {
				continue
			}
			add(g1, g2)
		}
		// gram × industry keyword
		for _, kw := range industry {
			add(g1, kw)
			add(kw, g1)
		}
	}

	// Common suffixes applied to top grams
	suffixes := []string{"v2", "v3", "eu", "us", "ap", "prod", "dev", "test", "beta", "int", "old", "new"}
	for _, g := range topGrams[:minInt(5, len(topGrams))] {
		for _, s := range suffixes {
			add(g, s)
		}
	}

	return results
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
