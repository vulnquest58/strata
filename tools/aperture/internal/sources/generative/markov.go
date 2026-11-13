package generative

import (
	"context"
	"math/rand"
	"strings"
	"unicode"

	"aperture/internal/model"
	"aperture/internal/sources"
)

// MarkovGenerator is a generative source plugin that creates candidate subdomains
// by learning character-level bigram patterns from a seed corpus of known subdomain names.
//
// Unlike wordlist bruteforce, it generates novel names that follow the structural
// patterns of real subdomains (e.g., "api-v2-prod", "staging-eu-west", "auth2-beta").
// This catches subdomains that aren't in any wordlist but follow naming conventions.
//
// Design note: this is a *source* like any other — it starts with the same prior
// reliability (0.5) and builds trust through the Bayesian reliability engine.
// It is NOT a privileged or special generator — its findings compete equally with
// passive sources for corroboration and temporal consensus.
type MarkovGenerator struct {
	// order is the n-gram size for the Markov chain (2 = bigram, 3 = trigram).
	order int
	// generateCount is how many candidates to generate per target.
	generateCount int
	// seedCorpus provides training examples for the Markov model.
	seedCorpus []string
}

// NewMarkovGenerator creates a Markov generator with sensible defaults.
func NewMarkovGenerator(generateCount int) *MarkovGenerator {
	return &MarkovGenerator{
		order:         2,
		generateCount: generateCount,
		seedCorpus:    defaultCorpus,
	}
}

func (m *MarkovGenerator) Name() string                    { return "markov" }
func (m *MarkovGenerator) Category() model.SourceCategory  { return model.SourceGenerative }
func (m *MarkovGenerator) DefaultPriorReliability() float64 { return 0.35 } // generative = more speculative

// Discover generates candidate subdomain names for the target using a Markov chain
// trained on common subdomain naming patterns.
func (m *MarkovGenerator) Discover(ctx context.Context, target string) (<-chan sources.RawCandidate, error) {
	out := make(chan sources.RawCandidate, 256)

	go func() {
		defer close(out)

		chain := buildChain(m.seedCorpus, m.order)
		seen := make(map[string]bool)
		attempts := 0
		maxAttempts := m.generateCount * 10 // allow for collisions

		for len(seen) < m.generateCount && attempts < maxAttempts {
			if ctx.Err() != nil {
				return
			}
			attempts++

			candidate := generateName(chain, m.order, 4, 20)
			if candidate == "" || seen[candidate] {
				continue
			}
			seen[candidate] = true

			hostname := candidate + "." + target
			select {
			case <-ctx.Done():
				return
			case out <- sources.RawCandidate{
				AssetID:      hostname,
				SourcePlugin: m.Name(),
				AssetType:    model.AssetSubdomain,
				RawScore:     40.0, // lower raw score to reflect generative uncertainty
				Evidence: map[string]any{
					"method":          "markov_chain",
					"markov_order":    m.order,
					"generated_label": candidate,
				},
			}:
			}
		}
	}()

	return out, nil
}

// -------------------------------------------------------------------
// Markov chain internals
// -------------------------------------------------------------------

// chain maps n-gram prefix → list of characters that follow it in the corpus.
type chain map[string][]rune

// buildChain trains a Markov chain on the given corpus using n-gram order k.
func buildChain(corpus []string, k int) chain {
	c := make(chain)
	for _, word := range corpus {
		runes := []rune(strings.ToLower(word))
		if len(runes) < k+1 {
			continue
		}
		for i := 0; i <= len(runes)-k-1; i++ {
			key := string(runes[i : i+k])
			c[key] = append(c[key], runes[i+k])
		}
	}
	return c
}

// generateName generates a single candidate name using the trained chain.
// minLen and maxLen control the target length.
func generateName(c chain, k, minLen, maxLen int) string {
	keys := make([]string, 0, len(c))
	for key := range c {
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return ""
	}

	// Pick a random starting bigram.
	start := keys[rand.Intn(len(keys))]
	buf := []rune(start)

	for len(buf) < maxLen {
		key := string(buf[len(buf)-k:])
		nexts, ok := c[key]
		if !ok || len(nexts) == 0 {
			break
		}
		next := nexts[rand.Intn(len(nexts))]
		buf = append(buf, next)
	}

	result := string(buf)
	// Validate: only lowercase alnum + hyphen, no leading/trailing hyphen.
	if len([]rune(result)) < minLen {
		return ""
	}
	for _, r := range result {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' {
			return ""
		}
	}
	if strings.HasPrefix(result, "-") || strings.HasSuffix(result, "-") {
		return ""
	}
	return result
}

// defaultCorpus is a curated set of real-world subdomain label patterns
// (just the label part, not the full hostname) used to train the Markov model.
// The corpus deliberately avoids single-word entries to push generation toward
// compound names that are more likely to represent real services.
var defaultCorpus = []string{
	"api-v1", "api-v2", "api-v3", "api-prod", "api-staging", "api-dev",
	"api-internal", "api-gateway", "api-backend", "api-service",
	"app-server", "app-backend", "app-frontend", "app-api",
	"auth-service", "auth-api", "auth-server", "auth-proxy",
	"web-app", "web-api", "web-server", "web-frontend",
	"admin-api", "admin-panel", "admin-portal", "admin-console",
	"beta-api", "beta-app", "beta-web",
	"dev-api", "dev-app", "dev-server", "dev-backend",
	"staging-api", "staging-app", "staging-web", "staging-server",
	"test-api", "test-app", "test-server",
	"prod-api", "prod-app", "prod-server",
	"us-east", "us-west", "eu-west", "eu-central", "ap-southeast",
	"us-api", "eu-api", "ap-api",
	"internal-api", "internal-app", "internal-service",
	"backend-api", "backend-service", "backend-server",
	"frontend-api", "frontend-app", "frontend-server",
	"data-api", "data-service", "data-server", "data-pipeline",
	"cdn-api", "cdn-static", "cdn-assets", "cdn-media",
	"media-api", "media-server", "media-cdn",
	"mail-server", "mail-api", "mail-relay",
	"smtp-server", "imap-server", "pop3-server",
	"vpn-server", "vpn-gateway", "vpn-proxy",
	"ssh-bastion", "jump-server", "bastion-host",
	"monitor-api", "monitor-server", "monitor-agent",
	"metrics-api", "metrics-server", "metrics-collector",
	"log-api", "log-server", "log-collector", "log-aggregator",
	"search-api", "search-server", "search-service",
	"cache-server", "cache-api", "cache-service",
	"queue-api", "queue-server", "queue-service",
	"worker-api", "worker-server", "worker-service",
	"job-server", "job-api", "job-service",
	"scheduler-api", "scheduler-service",
	"notification-api", "notification-service", "notification-server",
	"payment-api", "payment-gateway", "payment-service",
	"billing-api", "billing-service", "billing-server",
	"order-api", "order-service", "order-server",
	"catalog-api", "catalog-service", "catalog-server",
	"inventory-api", "inventory-service",
	"shipping-api", "shipping-service",
	"user-api", "user-service", "user-server",
	"account-api", "account-service",
	"profile-api", "profile-service",
	"session-api", "session-service",
	"token-api", "token-service",
	"oauth-server", "oauth-api", "oauth-service",
	"sso-server", "sso-api", "sso-service",
	"identity-server", "identity-api", "identity-service",
	"analytics-api", "analytics-service", "analytics-server",
	"reporting-api", "reporting-service",
	"dashboard-api", "dashboard-service",
	"config-api", "config-service", "config-server",
	"secret-api", "secret-service",
	"registry-api", "registry-service",
	"discovery-api", "discovery-service",
	"health-api", "health-check", "health-service",
	"status-api", "status-page", "status-service",
}
