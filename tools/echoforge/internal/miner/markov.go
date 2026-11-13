package miner

import (
	"math/rand"
	"strings"
)

// MarkovOrder defines how many previous tokens are used for prediction.
const MarkovOrder = 2

// MarkovChain is an Order-N Markov Chain trained on subdomain token sequences.
// It learns transition probabilities between token n-grams and generates
// realistic new subdomain candidates.
type MarkovChain struct {
	// transitions: map[stateKey]map[nextToken]count
	transitions map[string]map[string]int
	// starts: valid start sequences for generation
	starts [][]string
	order  int
}

// NewMarkovChain creates an untrained Markov Chain of the given order.
func NewMarkovChain(order int) *MarkovChain {
	if order < 1 {
		order = 1
	}
	return &MarkovChain{
		transitions: make(map[string]map[string]int),
		order:       order,
	}
}

// stateKey encodes a slice of tokens as a single map key.
func stateKey(tokens []string) string {
	return strings.Join(tokens, "|")
}

// Train ingests a list of subdomain names to build the transition model.
// Each subdomain is tokenized and its token n-grams feed the transition table.
func (m *MarkovChain) Train(subdomains []string) {
	for _, sub := range subdomains {
		tokens := tokenize(sub)
		if len(tokens) < 2 {
			continue
		}

		// Record start sequences
		if len(tokens) >= m.order {
			m.starts = append(m.starts, tokens[:m.order])
		}

		// Build transition table
		for i := 0; i+m.order < len(tokens); i++ {
			state := stateKey(tokens[i : i+m.order])
			next := tokens[i+m.order]
			if m.transitions[state] == nil {
				m.transitions[state] = make(map[string]int)
			}
			m.transitions[state][next]++
		}
	}
}

// Generate produces a new subdomain candidate starting from the given seed tokens.
// maxLen limits the total number of tokens in the generated name.
func (m *MarkovChain) Generate(seed []string, domain string, maxLen int) string {
	if len(seed) == 0 || len(m.starts) == 0 {
		return ""
	}

	current := make([]string, len(seed))
	copy(current, seed)
	result := make([]string, len(seed))
	copy(result, seed)

	for len(result) < maxLen {
		var stateTokens []string
		if len(current) >= m.order {
			stateTokens = current[len(current)-m.order:]
		} else {
			stateTokens = current
		}

		key := stateKey(stateTokens)
		nexts, ok := m.transitions[key]
		if !ok || len(nexts) == 0 {
			break
		}

		// Weighted random selection
		total := 0
		for _, count := range nexts {
			total += count
		}

		r := rand.Intn(total)
		cumulative := 0
		var chosen string
		for token, count := range nexts {
			cumulative += count
			if r < cumulative {
				chosen = token
				break
			}
		}
		if chosen == "" {
			break
		}

		result = append(result, chosen)
		current = append(current, chosen)
	}

	if len(result) < 2 {
		return ""
	}
	return strings.Join(result, "-") + "." + domain
}

// GenerateFromRandom produces N candidates starting from random training seeds.
func (m *MarkovChain) GenerateFromRandom(domain string, count, maxLen int) []string {
	if len(m.starts) == 0 {
		return nil
	}

	seen := make(map[string]bool)
	var results []string

	attempts := 0
	for len(results) < count && attempts < count*10 {
		attempts++
		seed := m.starts[rand.Intn(len(m.starts))]
		candidate := m.Generate(seed, domain, maxLen)
		if candidate != "" && !seen[candidate] {
			seen[candidate] = true
			results = append(results, candidate)
		}
	}
	return results
}

// GenerateFromToken produces N candidates seeded from a specific token.
func (m *MarkovChain) GenerateFromToken(token, domain string, count, maxLen int) []string {
	seed := []string{token}
	seen := make(map[string]bool)
	var results []string

	for attempt := 0; len(results) < count && attempt < count*5; attempt++ {
		candidate := m.Generate(seed, domain, maxLen)
		if candidate != "" && !seen[candidate] {
			seen[candidate] = true
			results = append(results, candidate)
		}
	}
	return results
}

// IsTrained returns true if the model has been trained on at least one sequence.
func (m *MarkovChain) IsTrained() bool {
	return len(m.transitions) > 0
}
