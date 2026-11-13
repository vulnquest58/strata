package harvester

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/echoforge/echoforge/internal/utils"
)

// WaybackHarvester fetches subdomains from the Wayback Machine CDX API.
type WaybackHarvester struct {
	client *http.Client
	jitter *utils.Jitter
}

func NewWaybackHarvester(stealth bool) *WaybackHarvester {
	return &WaybackHarvester{
		client: &http.Client{Timeout: 30 * time.Second},
		jitter: utils.NewJitter(3000, 0.5, stealth),
	}
}

// Fetch queries the Wayback Machine CDX API for URLs under the target domain.
// Uses a reduced limit to avoid timeout on large/popular domains.
func (h *WaybackHarvester) Fetch(ctx context.Context, domain string) ([]string, error) {
	h.jitter.Sleep()

	var results []string
	err := utils.RetryWithBackoff(2, 2000, func() error {
		params := url.Values{}
		params.Set("url", fmt.Sprintf("*.%s/*", domain))
		params.Set("output", "json")
		params.Set("fl", "original")
		params.Set("collapse", "urlkey")
		params.Set("limit", "5000") // reduced from 10000 to avoid timeouts

		endpoint := "https://web.archive.org/cdx/search/cdx?" + params.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return fmt.Errorf("wayback: build request: %w", err)
		}
		req.Header.Set("User-Agent", utils.RandomUA())

		resp, err := h.client.Do(req)
		if err != nil {
			return fmt.Errorf("wayback: request: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			return fmt.Errorf("wayback: rate limited (429)")
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("wayback: HTTP %d", resp.StatusCode)
		}

		// Response: JSON array of arrays [[header], [url1], [url2], ...]
		var rows [][]string
		if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
			return fmt.Errorf("wayback: decode: %w", err)
		}

		seen := make(map[string]bool)
		for i, row := range rows {
			if i == 0 || len(row) == 0 {
				continue // skip header row
			}
			raw := row[0]
			u, err := url.Parse(raw)
			if err != nil || u.Host == "" {
				continue
			}
			host := strings.ToLower(strings.Split(u.Host, ":")[0])
			if strings.HasSuffix(host, "."+domain) && !seen[host] {
				seen[host] = true
				results = append(results, host)
			}
		}
		return nil
	})
	return results, err
}
