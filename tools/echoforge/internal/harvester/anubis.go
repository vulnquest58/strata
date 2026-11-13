package harvester

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/echoforge/echoforge/internal/utils"
)

// AnubisHarvester queries the Anubis FDNS project via jldc.me API.
// No API key required. Returns JSON array of subdomains.
// Endpoint: https://jldc.me/anubis/subdomains/<domain>
// Data source: passive DNS from Anubis Forward DNS project.
type AnubisHarvester struct {
	client *http.Client
	jitter *utils.Jitter
}

func NewAnubisHarvester(stealth bool) *AnubisHarvester {
	return &AnubisHarvester{
		client: &http.Client{Timeout: 20 * time.Second},
		jitter: utils.NewJitter(1000, 0.4, stealth),
	}
}

// Fetch queries Anubis FDNS for subdomains of the given domain.
func (h *AnubisHarvester) Fetch(ctx context.Context, domain string) ([]string, error) {
	h.jitter.Sleep()

	var results []string
	err := utils.RetryWithBackoff(2, 1000, func() error {
		url := fmt.Sprintf("https://jldc.me/anubis/subdomains/%s", domain)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("anubis: build request: %w", err)
		}
		req.Header.Set("User-Agent", utils.RandomUA())
		req.Header.Set("Accept", "application/json")

		resp, err := h.client.Do(req)
		if err != nil {
			return fmt.Errorf("anubis: request: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			return fmt.Errorf("anubis: rate limited (429)")
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("anubis: HTTP %d", resp.StatusCode)
		}

		// Response: JSON array of strings ["sub1.domain.com", "sub2.domain.com", ...]
		var subdomains []string
		if err := json.NewDecoder(resp.Body).Decode(&subdomains); err != nil {
			return fmt.Errorf("anubis: decode: %w", err)
		}

		seen := make(map[string]bool)
		for _, name := range subdomains {
			name = strings.ToLower(strings.TrimSpace(name))
			name = strings.TrimPrefix(name, "*.")
			if name == "" || seen[name] {
				continue
			}
			if strings.HasSuffix(name, "."+domain) || name == domain {
				seen[name] = true
				results = append(results, name)
			}
		}
		return nil
	})
	return results, err
}
