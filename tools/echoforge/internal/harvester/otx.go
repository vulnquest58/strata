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

// OTXHarvester fetches subdomains from AlienVault OTX public endpoint.
// No API key required for passive DNS data.
type OTXHarvester struct {
	client *http.Client
	jitter *utils.Jitter
}

type otxPassiveDNS struct {
	PassiveDNS []struct {
		Hostname string `json:"hostname"`
	} `json:"passive_dns"`
	Count int `json:"count"`
}

func NewOTXHarvester(stealth bool) *OTXHarvester {
	return &OTXHarvester{
		client: &http.Client{Timeout: 25 * time.Second},
		jitter: utils.NewJitter(2000, 0.6, stealth),
	}
}

// Fetch retrieves passive DNS data from AlienVault OTX for the given domain.
// Retries once on transient error (OTX is rate-limited aggressively on popular domains).
func (h *OTXHarvester) Fetch(ctx context.Context, domain string) ([]string, error) {
	h.jitter.Sleep()

	var results []string
	err := utils.RetryWithBackoff(2, 2000, func() error {
		url := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", domain)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("otx: build request: %w", err)
		}
		req.Header.Set("User-Agent", utils.RandomUA())
		req.Header.Set("Accept", "application/json")

		resp, err := h.client.Do(req)
		if err != nil {
			return fmt.Errorf("otx: request: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			// OTX rate limit — don't retry, it won't help quickly
			return fmt.Errorf("otx: rate limited")
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("otx: HTTP %d", resp.StatusCode)
		}

		var data otxPassiveDNS
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			return fmt.Errorf("otx: decode: %w", err)
		}

		seen := make(map[string]bool)
		for _, entry := range data.PassiveDNS {
			name := strings.ToLower(strings.TrimSpace(entry.Hostname))
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
